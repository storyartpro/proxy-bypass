// Per-user environment variables that point command-line clients at the local
// routing proxy, with a restorable backup.
//
// Windows' system proxy covers WinINET/WinHTTP applications (browsers,
// installers).  curl, git, pip, npm and Python's requests read HTTP_PROXY /
// HTTPS_PROXY / ALL_PROXY from the environment instead, so this is the second,
// still reversible, coverage layer.  Raw-socket clients (Telegram's MTProto,
// QUIC, most games) ignore both and need a transparent capture.

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { dataDir } from "./local-proxy.mjs";

const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const BACKUP = () => path.join(dataDir(), "env-proxy-backup.json");

/** Canonical names; Windows treats environment names case-insensitively. */
export const MANAGED_VARS = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];
export const LOOPBACK_NO_PROXY = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];

// Explorer caches the user environment; without the broadcast a freshly opened
// terminal keeps the old (empty) values.
const BROADCAST_SNIPPET = `
$sig = '[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
$type = Add-Type -MemberDefinition $sig -Name EnvBroadcast -Namespace LocalProxy -PassThru
$result = [UIntPtr]::Zero
[void]$type::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
`;

function runPowerShell(script, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    execFile(
      PS,
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) reject(new Error(`${error.message}${stderr ? `: ${stderr.trim()}` : ""}`));
        else resolve(stdout);
      },
    );
  });
}

export function proxyUrlFor(port = 38080) {
  return `http://127.0.0.1:${Number(port)}`;
}

/** Parse a NO_PROXY value into entries, dropping empties. */
export function parseNoProxy(value) {
  return String(value || "")
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

/** Keep the user's own NO_PROXY entries and make sure loopback never proxies. */
export function mergeNoProxy(existing) {
  const parts = parseNoProxy(existing);
  const seen = new Set(parts.map((item) => item.toLowerCase()));
  for (const entry of LOOPBACK_NO_PROXY) {
    if (!seen.has(entry)) {
      parts.push(entry);
      seen.add(entry);
    }
  }
  return parts.join(",");
}

/** True when all three proxy variables already point at this app's listener. */
export function isOurs(current, port = 38080) {
  const url = proxyUrlFor(port);
  return ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"].every((name) => String(current?.[name] || "") === url);
}

/** Values that switch the command-line layer on without losing NO_PROXY. */
export function enabledPlan(current, port = 38080) {
  const url = proxyUrlFor(port);
  return {
    HTTP_PROXY: url,
    HTTPS_PROXY: url,
    ALL_PROXY: url,
    NO_PROXY: mergeNoProxy(current?.NO_PROXY),
  };
}

/** Restore plan from the backup file; null means "variable was not set". */
export function restorePlan(backup) {
  if (!backup || typeof backup !== "object") return null;
  const plan = {};
  for (const name of MANAGED_VARS) plan[name] = backup[name] == null ? null : String(backup[name]);
  return plan;
}

/** Read the managed variables from HKCU\Environment via .NET. */
export async function readUserEnv() {
  const names = MANAGED_VARS.map((name) => `'${name}'`).join(",");
  const out = await runPowerShell(`
$names = @(${names})
$result = [ordered]@{}
foreach ($name in $names) { $result[$name] = [Environment]::GetEnvironmentVariable($name, 'User') }
$result | ConvertTo-Json -Compress
`);
  const trimmed = out.trim();
  if (!trimmed) return {};
  return JSON.parse(trimmed);
}

/** Apply a {NAME: value|null} plan; JSON travels base64-encoded, so values are never interpolated into the script. */
async function applyUserEnv(values) {
  const payload = Buffer.from(JSON.stringify(values), "utf8").toString("base64");
  await runPowerShell(`
$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))
$data = $json | ConvertFrom-Json
foreach ($property in $data.PSObject.Properties) {
  if ($null -eq $property.Value) {
    [Environment]::SetEnvironmentVariable($property.Name, $null, 'User')
  } else {
    [Environment]::SetEnvironmentVariable($property.Name, [string]$property.Value, 'User')
  }
}
${BROADCAST_SNIPPET}
`);
}

export async function envProxyStatus(port = 38080) {
  const current = await readUserEnv();
  return {
    installed: isOurs(current, port),
    proxyUrl: proxyUrlFor(port),
    noProxy: current.NO_PROXY || "",
    current,
  };
}

/**
 * Point the user's HTTP_PROXY / HTTPS_PROXY / ALL_PROXY at the local routing
 * proxy.  The previous values are written once, so repeated toggles and app
 * restarts cannot overwrite the real pre-install state with our own values.
 */
export async function enableEnvProxy(port = 38080) {
  const current = await readUserEnv();
  const backupFile = BACKUP();
  fs.mkdirSync(dataDir(), { recursive: true });
  if (!fs.existsSync(backupFile)) {
    fs.writeFileSync(backupFile, JSON.stringify({ savedAt: new Date().toISOString(), ...current }, null, 2));
  }
  await applyUserEnv(enabledPlan(current, port));
  return { proxyUrl: proxyUrlFor(port), previous: current, backupFile };
}

/** Put the user's variables back; without a backup only our own values are removed. */
export async function disableEnvProxy(port = 38080) {
  const current = await readUserEnv();
  const backupFile = BACKUP();
  let backup = null;
  if (fs.existsSync(backupFile)) {
    try {
      backup = JSON.parse(fs.readFileSync(backupFile, "utf8"));
    } catch {
      backup = null;
    }
  }
  const plan = restorePlan(backup);
  if (plan) {
    await applyUserEnv(plan);
  } else if (isOurs(current, port)) {
    // No backup: our plan definitely wrote these three, NO_PROXY is left alone.
    await applyUserEnv({ HTTP_PROXY: null, HTTPS_PROXY: null, ALL_PROXY: null });
  } else {
    return { restored: null, backupRemoved: false, note: "переменные не наши — ничего не меняю" };
  }
  if (backupFile) fs.rmSync(backupFile, { force: true });
  return { restored: plan, backupRemoved: Boolean(backup) };
}
