// Transparent capture through a TUN interface backed by sing-box.
//
// Windows' system proxy and the HTTP(S)_PROXY variables cover browsers, curl,
// git, pip, npm and Python.  They do not cover raw sockets: MTProto clients,
// QUIC/HTTP3, games and updaters dial their own packets and never read either
// setting.  sing-box creates a wintun adapter, takes the default route, and
// forwards every TCP/UDP flow to our local routing proxy (an HTTP outbound to
// 127.0.0.1:<port>), so those applications are routed as well.
//
// Creating the adapter needs Administrator rights, while the app itself runs
// unelevated.  The flow is therefore: install the engine (unelevated), then
// relaunch the app elevated through UAC once the user turns the mode on.

import { execFile, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dataDir } from "./local-proxy.mjs";

const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const CURL = "C:\\Windows\\System32\\curl.exe";
const TAR = "C:\\Windows\\System32\\tar.exe";

export const SINGBOX_VERSION = "1.14.4";
export const SINGBOX_ASSET = `sing-box-${SINGBOX_VERSION}-windows-amd64.zip`;
/** The archive's top-level directory, which is also our vendor directory. */
export const SINGBOX_DIR = SINGBOX_ASSET.replace(/\.zip$/, "");
export const SINGBOX_URL = `https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${SINGBOX_ASSET}`;
export const INTERFACE_NAME = "proxyapp";
/** /30 is enough for a point-to-point TUN: one address for us, one for the peer. */
export const TUN_ADDRESS = "172.19.0.1/30";
/** sing-box 1.14 logs at INFO per connection; WARN keeps app.log readable. */
const LOG_LEVEL = process.env.PROXY_APP_SINGBOX_LOG || "warn";
const TAIL_LIMIT = 80;

let child = null;
let startedAt = null;
let lastError = null;
let tail = [];
let elevation = null;

function vendorBase() {
  return path.join(dataDir(), "vendor");
}

export function vendorDir() {
  return path.join(vendorBase(), SINGBOX_DIR);
}

export function singboxExe() {
  return path.join(vendorDir(), "sing-box.exe");
}

export function configPath() {
  return path.join(dataDir(), "sing-box.json");
}

export function isInstalled() {
  try {
    return fs.statSync(singboxExe()).size > 1_000_000;
  } catch {
    return false;
  }
}

function runPowerShell(script, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    execFile(
      PS,
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) reject(new Error(`${error.message}${stderr ? `: ${stderr.trim()}` : ""}`));
        else resolve(stdout.trim());
      },
    );
  });
}

function run(command, args, timeoutMs = 300000) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({ code: error ? (typeof error.code === "number" ? error.code : 1) : 0, stdout: String(stdout || ""), stderr: String(stderr || "") });
    });
  });
}

/** Administrator check, cached: the answer cannot change inside one process. */
export async function isElevated() {
  if (elevation !== null) return elevation;
  try {
    const out = await runPowerShell(
      "$id=[Security.Principal.WindowsIdentity]::GetCurrent(); (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
      10000,
    );
    elevation = /true/i.test(out);
  } catch {
    elevation = false;
  }
  return elevation;
}

/** Default gateway is the DNS resolver the machine already trusts. */
export async function detectDnsServer(fallback = "1.1.1.1") {
  try {
    const out = await runPowerShell(
      "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1; if ($r) { $r.NextHop }",
      10000,
    );
    if (net.isIP(out)) return out;
  } catch {
    /* fall through to the public resolver */
  }
  return fallback;
}

/** Hosts that must never enter the tunnel: our own upstream proxies and the
 *  SSH control-plane servers.  A SOCKS5 provider usually allows only a few
 *  ports, and SSH through it would break the server management. */
export function cidrsFor(hosts) {
  const seen = new Set();
  const result = [];
  for (const raw of hosts || []) {
    const host = String(raw || "").trim();
    const family = net.isIP(host);
    if (!family || seen.has(host)) continue;
    seen.add(host);
    result.push(`${host}/${family === 6 ? 128 : 32}`);
  }
  return result;
}

export function buildConfig({ port = 38080, dnsServer = "1.1.1.1", directCidrs = [], directPorts = [] } = {}) {
  const rules = [
    { action: "sniff" },
    { protocol: "dns", action: "hijack-dns" },
    // The app outbound speaks HTTP CONNECT, which carries TCP only. Rejecting
    // the rest of UDP (QUIC, WebRTC) makes clients fall back to TCP instead of
    // flooding the log with "UDP is not supported by outbound".
    { network: "udp", action: "reject" },
    // The routing proxy, the tray and any other Node helper talk to each other
    // on loopback; protecting node.exe also keeps the proxy's own upstream
    // connection out of the tunnel and prevents a routing loop.
    { process_name: ["node.exe"], action: "route", outbound: "direct" },
    { ip_is_private: true, action: "route", outbound: "direct" },
  ];
  if (directCidrs.length) rules.push({ ip_cidr: directCidrs, action: "route", outbound: "direct" });
  if (directPorts.length) rules.push({ port: directPorts, action: "route", outbound: "direct" });
  return {
    log: { level: LOG_LEVEL, timestamp: true },
    dns: {
      servers: [{ type: "udp", tag: "local", server: dnsServer }],
      final: "local",
    },
    inbounds: [
      {
        type: "tun",
        tag: "tun-in",
        interface_name: INTERFACE_NAME,
        address: [TUN_ADDRESS],
        mtu: 1500,
        auto_route: true,
        strict_route: true,
        stack: "gvisor",
      },
    ],
    outbounds: [
      { type: "http", tag: "app", server: "127.0.0.1", server_port: Number(port) },
      { type: "direct", tag: "direct" },
    ],
    route: {
      rules,
      final: "app",
      auto_detect_interface: true,
    },
  };
}

export function writeConfig(config) {
  const file = configPath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`);
  return file;
}

function rememberLine(line) {
  const text = String(line || "").trim();
  if (!text) return;
  tail.push(text);
  if (tail.length > TAIL_LIMIT) tail = tail.slice(-TAIL_LIMIT);
}

async function downloadZip(destination, { port, log } = {}) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const base = ["-L", "--fail", "--retry", "2", "--connect-timeout", "15", "--max-time", "600", "-o", destination];
  const direct = await run(CURL, [...base, SINGBOX_URL], 620000);
  if (direct.code === 0 && fs.existsSync(destination) && fs.statSync(destination).size > 1_000_000) return;
  log?.(`прозрачный режим: прямое скачивание не удалось (${direct.code}), пробую через прокси`);
  const viaProxy = await run(CURL, [...base, "-x", `http://127.0.0.1:${port || 38080}`, SINGBOX_URL], 620000);
  if (viaProxy.code !== 0 || !fs.existsSync(destination) || fs.statSync(destination).size < 1_000_000) {
    throw new Error(`не удалось скачать sing-box: ${(viaProxy.stderr || direct.stderr || "").slice(-300)}`);
  }
}

/** Download and unpack the pinned engine once. Returns the executable path. */
export async function install({ port = 38080, log } = {}) {
  if (isInstalled()) return { ok: true, installed: true, exe: singboxExe() };
  if (process.platform !== "win32") throw new Error("прозрачный режим поддерживается только в Windows");
  const zip = path.join(vendorBase(), SINGBOX_ASSET);
  await downloadZip(zip, { port, log });
  fs.mkdirSync(vendorBase(), { recursive: true });
  const unpack = await run(TAR, ["-xf", zip, "-C", vendorBase()], 180000);
  if (unpack.code !== 0 || !isInstalled()) {
    throw new Error(`не удалось распаковать sing-box: ${(unpack.stderr || "").slice(-300)}`);
  }
  fs.rmSync(zip, { force: true });
  const version = await run(singboxExe(), ["version"], 30000);
  log?.(`прозрачный режим: sing-box ${SINGBOX_VERSION} установлен (${version.stdout.split("\n")[0] || "?"})`);
  return { ok: true, installed: true, exe: singboxExe(), version: version.stdout.split("\n")[0] || "" };
}

export async function status() {
  const running = Boolean(child && child.exitCode === null);
  return {
    installed: isInstalled(),
    elevated: await isElevated(),
    running,
    pid: running ? child.pid : null,
    startedAt: running ? startedAt : null,
    interface: INTERFACE_NAME,
    address: TUN_ADDRESS,
    version: SINGBOX_VERSION,
    error: lastError,
    logTail: tail.slice(-TAIL_LIMIT),
  };
}

/** Start the engine; the caller must already be elevated. */
export async function start({ port = 38080, directCidrs = [], directPorts = [], dnsServer, log } = {}) {
  if (child && child.exitCode === null) return { ok: true, ...(await status()) };
  if (!isInstalled()) throw new Error("движок sing-box не установлен");
  if (!(await isElevated())) throw new Error("нужны права администратора");
  const dns = dnsServer || (await detectDnsServer());
  const config = buildConfig({ port, dnsServer: dns, directCidrs, directPorts });
  const file = writeConfig(config);
  const check = await run(singboxExe(), ["check", "-c", file], 60000);
  if (check.code !== 0) throw new Error(`конфиг sing-box отклонён: ${(check.stderr || check.stdout).slice(-400)}`);
  lastError = null;
  tail = [];
  startedAt = new Date().toISOString();
  const proc = spawn(singboxExe(), ["run", "-c", file], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  child = proc;
  proc.stdout.on("data", (chunk) => String(chunk).split(/\r?\n/).forEach(rememberLine));
  proc.stderr.on("data", (chunk) => String(chunk).split(/\r?\n/).forEach(rememberLine));
  proc.on("exit", (code) => {
    if (child === proc) {
      child = null;
      startedAt = null;
    }
    if (code !== 0) lastError = `sing-box завершился с кодом ${code}: ${tail.slice(-2).join(" | ") || "нет вывода"}`;
  });
  proc.on("error", (error) => {
    lastError = error.message;
  });
  await new Promise((resolve) => setTimeout(resolve, 1500));
  if (proc.exitCode !== null) {
    throw new Error(lastError || `sing-box завершился сразу после старта: ${tail.slice(-2).join(" | ")}`);
  }
  log?.(`прозрачный режим: TUN ${INTERFACE_NAME} поднят, DNS ${dns}, sing-box pid ${proc.pid}`);
  return { ok: true, ...(await status()) };
}

export async function stop() {
  const proc = child;
  child = null;
  startedAt = null;
  if (!proc || proc.exitCode !== null) return { ok: true };
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      try {
        proc.kill("SIGKILL");
      } catch {
        /* already gone */
      }
      resolve();
    }, 3000);
    proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    try {
      proc.kill();
    } catch {
      clearTimeout(timer);
      resolve();
    }
  });
  return { ok: true };
}

/** Relaunch the same app through UAC. The caller frees the ports first so the
 *  elevated copy can bind them immediately.
 *
 *  UAC starts the child through the AppInfo service, which does not reliably
 *  inherit our environment, so PROXY_APP_DATA/PROXY_APP_PORT are written into a
 *  small launcher script instead of relying on inheritance. */
export async function relaunchElevated({ port = 8077 } = {}) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const appDir = path.resolve(here, "..");
  const serverPath = path.join(appDir, "server.mjs");
  const data = dataDir();
  const launcher = path.join(data, "start-admin.cmd");
  const lines = [
    "@echo off",
    `set "PROXY_APP_DATA=${data}"`,
    `set "PROXY_APP_PORT=${Number(port) || 8077}"`,
    `set "PROXY_APP_RELAUNCH=1"`,
    `cd /d "${appDir}"`,
    `"${process.execPath}" "${serverPath}"`,
  ];
  if (process.env.PROXY_APP_SINGBOX_LOG) {
    lines.splice(4, 0, `set "PROXY_APP_SINGBOX_LOG=${process.env.PROXY_APP_SINGBOX_LOG}"`);
  }
  fs.writeFileSync(launcher, `${lines.join("\r\n")}\r\n`);
  const quote = (value) => `'${String(value).replace(/'/g, "''")}'`;
  await runPowerShell(
    `Start-Process -FilePath ${quote(launcher)} -WindowStyle Hidden -Verb RunAs`,
    60000,
  );
  return { ok: true, appDir, launcher };
}

export function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}
