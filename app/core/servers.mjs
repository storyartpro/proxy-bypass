// Manage the Linux side over SSH: install the daemon, toggle it, push the
// blocked-host list.  Everything is plain ssh + sudo -n so no extra agent is
// needed on the server.
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DAEMON_PATH = "/usr/local/sbin/proxy-bypass";
const CONFIG_PATH = "/etc/proxy-bypass/config.json";
const UNIT_PATH = "/etc/systemd/system/proxy-bypass.service";
const ASSETS = new URL("../assets/", import.meta.url);

const SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15"];

function sshBinary() {
  const override = process.env.PROXY_APP_SSH;
  if (override) return override;
  const windows = "C:\\Windows\\System32\\OpenSSH\\ssh.exe";
  if (process.platform === "win32" && existsSync(windows)) return windows;
  return "ssh";
}

function asset(name) {
  return readFileSync(fileURLToPath(new URL(name, ASSETS)), "utf8");
}

export function runSsh(alias, command, { input, timeoutMs = 60000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(sshBinary(), [...SSH_OPTIONS, alias, command], { windowsHide: true });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ code: 124, stdout, stderr: `${stderr}\ntimeout` });
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ code: 1, stdout, stderr: error.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
    if (input) child.stdin.end(input);
  });
}

function parseJson(text) {
  const trimmed = (text || "").trim();
  if (!trimmed) throw new Error("пустой ответ демона");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end < start) throw new Error("ответ демона не JSON");
  return JSON.parse(trimmed.slice(start, end + 1));
}

async function daemonJson(alias, args, timeoutMs = 120000) {
  const result = await runSsh(alias, `sudo -n ${DAEMON_PATH} ${args}`, { timeoutMs });
  if (result.code !== 0) {
    const detail = (result.stderr || result.stdout || "").trim().slice(0, 400);
    if (/No such file|not found|command not found/i.test(detail)) throw new Error("демон не установлен");
    throw new Error(detail || `exit ${result.code}`);
  }
  return parseJson(result.stdout);
}

export async function testConnection(alias) {
  const result = await runSsh(alias, "echo proxy-app-ok", { timeoutMs: 30000 });
  if (result.code !== 0 || !result.stdout.includes("proxy-app-ok")) {
    throw new Error((result.stderr || "").trim() || "SSH недоступен");
  }
  return { ok: true };
}

export async function serverStatus(alias) {
  const result = await runSsh(alias, `sudo -n ${DAEMON_PATH} status --json`, { timeoutMs: 45000 });
  if (result.code !== 0) {
    const detail = (result.stderr || result.stdout || "").trim().slice(0, 300);
    return { installed: false, running: false, error: detail || `exit ${result.code}` };
  }
  const data = parseJson(result.stdout);
  return {
    installed: true,
    running: data.service?.proxy_bypass === "active",
    chainRules: data.chain_rules ?? 0,
    blocked: Array.isArray(data.entries) ? data.entries.filter((entry) => entry.active).map((entry) => entry.domain) : [],
    raw: data,
  };
}

async function upload(alias, name, content) {
  const base64 = Buffer.from(content, "utf8").toString("base64");
  const result = await runSsh(alias, `sudo -n bash -c "base64 -d > /tmp/${name}"`, { input: base64, timeoutMs: 60000 });
  if (result.code !== 0) throw new Error(`не удалось загрузить ${name}: ${(result.stderr || "").trim()}`);
}

export async function installServer(alias, blockedHosts = [], chain = "PROXY-BYPASS") {
  const config = JSON.parse(asset("default-config.json"));
  config.chain = chain;
  config.watch = [...new Set([...(blockedHosts || []), ...config.watch])].slice(0, 300);
  await upload(alias, "proxy-bypass.py", asset("proxy-bypass.py"));
  await upload(alias, "proxy-bypass.service", asset("proxy-bypass.service"));
  await upload(alias, "proxy-bypass.json", JSON.stringify(config, null, 2));
  const steps = [
    `sudo -n install -m 0755 /tmp/proxy-bypass.py ${DAEMON_PATH}`,
    `sudo -n install -m 0644 /tmp/proxy-bypass.service ${UNIT_PATH}`,
    `sudo -n mkdir -p /etc/proxy-bypass /var/lib/proxy-bypass`,
    `sudo -n install -m 0644 /tmp/proxy-bypass.json ${CONFIG_PATH}`,
    "sudo -n systemctl daemon-reload",
    "sudo -n systemctl enable --now proxy-bypass",
  ];
  for (const step of steps) {
    const result = await runSsh(alias, step, { timeoutMs: 120000 });
    if (result.code !== 0) throw new Error(`${step}: ${(result.stderr || result.stdout || "").trim().slice(0, 300)}`);
  }
  return serverStatus(alias);
}

export async function controlServer(alias, action) {
  if (!["start", "stop", "restart"].includes(action)) throw new Error("недопустимое действие");
  const result = await runSsh(alias, `sudo -n systemctl ${action} proxy-bypass`, { timeoutMs: 60000 });
  if (result.code !== 0) throw new Error((result.stderr || "").trim().slice(0, 300) || `exit ${result.code}`);
  return serverStatus(alias);
}

export async function pushBlockedList(alias, hosts) {
  const results = [];
  for (const host of hosts) {
    const result = await runSsh(alias, `sudo -n ${DAEMON_PATH} add --domain ${host} --pin --json`, { timeoutMs: 45000 });
    results.push({ host, ok: result.code === 0, error: result.code === 0 ? null : (result.stderr || "").trim().slice(0, 200) });
  }
  return { pushed: results.filter((item) => item.ok).length, total: hosts.length, results };
}

/**
 * Push the PC-side proxy credentials to a server by rewriting its redsocks
 * upstream, with a timestamped backup and a clean restart.
 *
 * The credentials are sent over ssh stdin (never in the command line) so they do
 * not show up in process lists or shell history.
 */
export async function pushProxySettings(alias, proxy) {
  if (!proxy || proxy.type === "ssh") throw new Error("для сервера нужен SOCKS5-прокси с логином и паролем");
  if (!proxy.host || !proxy.port) throw new Error("у прокси не заданы хост и порт");
  const payload = JSON.stringify({
    ip: proxy.host,
    port: Number(proxy.port),
    login: proxy.login || "",
    password: proxy.password || "",
  });
  const script = [
    "import json, os, re, shutil, subprocess, time",
    `data = ${JSON.stringify({ ip: proxy.host, port: Number(proxy.port), login: proxy.login || "", password: proxy.password || "" })}`,
    "path = '/etc/redsocks.conf'",
    "text = open(path, 'r', encoding='utf-8', errors='replace').read()",
    "backup = path + '.bak.' + time.strftime('%Y%m%d-%H%M%S')",
    "shutil.copy2(path, backup)",
    "def set_field(text, key, value):",
    "    pattern = r'(?m)^(\\s*' + key + r'\\s*=\\s*)([^;]*)(;)'",
    "    if re.search(pattern, text):",
    "        return re.sub(pattern, lambda m: m.group(1) + json.dumps(value) + m.group(3), text, count=1)",
    "    return text",
    "text = set_field(text, 'ip', data['ip'])",
    "text = set_field(text, 'port', str(data['port']))",
    "text = set_field(text, 'login', data['login'])",
    "text = set_field(text, 'password', data['password'])",
    "open(path, 'w', encoding='utf-8').write(text)",
    "subprocess.run(['systemctl', 'restart', 'redsocks'], check=False)",
    "print(json.dumps({'ok': True, 'backup': backup}))",
  ].join("\n");
  const result = await runSsh(alias, "sudo -n python3 -", { input: `${script}\n`, timeoutMs: 60000 });
  if (result.code !== 0) {
    throw new Error((result.stderr || result.stdout || "").trim().slice(0, 300) || "не удалось обновить redsocks");
  }
  const start = result.stdout.indexOf("{");
  const end = result.stdout.lastIndexOf("}");
  if (start >= 0 && end > start) return JSON.parse(result.stdout.slice(start, end + 1));
  return { ok: true };
}

export async function serverLogs(alias, lines = 40) {
  const result = await runSsh(alias, `sudo -n journalctl -u proxy-bypass -n ${lines} --no-pager`, { timeoutMs: 45000 });
  return result.stdout.split("\n").slice(-lines);
}
