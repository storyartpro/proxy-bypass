// Windows system-proxy control (HKCU Internet Settings) with a restorable backup.
//
// The local routing proxy only helps apps that talk to 127.0.0.1:38080.  Point
// Windows' per-user proxy at it so browsers and other WinINET users inherit the
// routing, and keep the previous values so `disable` can put them back.

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { dataDir } from "./local-proxy.mjs";

const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const BACKUP = () => path.join(dataDir(), "system-proxy-backup.json");

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

const KEY = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

const REFRESH_SNIPPET = `
$sig = '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);'
$type = Add-Type -MemberDefinition $sig -Name Internet -Namespace LocalProxy -PassThru
[void]$type::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
[void]$type::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
`;

export async function readSystemProxy() {
  const out = await runPowerShell(`
$item = Get-ItemProperty -Path '${KEY}'
[pscustomobject]@{
  ProxyEnable = [int]$item.ProxyEnable
  ProxyServer = [string]$item.ProxyServer
  ProxyOverride = [string]$item.ProxyOverride
  AutoConfigURL = [string]$item.AutoConfigURL
} | ConvertTo-Json -Compress
`);
  const trimmed = out.trim();
  if (!trimmed) return { ProxyEnable: 0, ProxyServer: "", ProxyOverride: "", AutoConfigURL: "" };
  return JSON.parse(trimmed);
}

function shouldWriteBackup(backupFile) {
  if (!fs.existsSync(backupFile)) return true;
  try {
    const saved = JSON.parse(fs.readFileSync(backupFile, "utf8"));
    // A backup that points at loopback is our own previous state, not the
    // user's: keeping it would make `disable` restore the proxy instead of the
    // plain connection.
    return /(^|;|\s)(127\.0\.0\.1|localhost)(:|$)/i.test(String(saved.ProxyServer || ""));
  } catch {
    return true;
  }
}

export async function enableSystemProxy(server = "127.0.0.1:38080") {
  const current = await readSystemProxy();
  const backupFile = BACKUP();
  if (shouldWriteBackup(backupFile)) {
    // If the machine is already on our loopback proxy (for example after a
    // Harness restart), snapshot the plain connection instead: restoring our
    // own proxy on `disable` would look like the bypass never turned off.
    const loopback = /(^|;|\s)(127\.0\.0\.1|localhost)(:|$)/i.test(String(current.ProxyServer || ""));
    const snapshot = loopback
      ? { ProxyEnable: 0, ProxyServer: "", ProxyOverride: "", AutoConfigURL: "" }
      : current;
    fs.writeFileSync(backupFile, JSON.stringify({ savedAt: new Date().toISOString(), ...snapshot }, null, 2));
  }
  await runPowerShell(`
Set-ItemProperty -Path '${KEY}' -Name ProxyEnable -Value 1 -Type DWord
Set-ItemProperty -Path '${KEY}' -Name ProxyServer -Value '${server}' -Type String
Set-ItemProperty -Path '${KEY}' -Name ProxyOverride -Value '<local>;127.0.0.1;localhost' -Type String
Set-ItemProperty -Path '${KEY}' -Name AutoConfigURL -Value '' -Type String
${REFRESH_SNIPPET}
`);
  return { server, previous: current, backupFile };
}

/**
 * Point Windows at a PAC file instead of a blanket proxy.
 *
 * A blanket `ProxyServer` makes every application (Telegram, installed clients,
 * IP-literal connections) use the routing proxy, and anything the classifier
 * cannot place ends up on the wrong path.  A PAC file lets the browser decide
 * per URL: only the listed domains go through the proxy, everything else is
 * DIRECT.
 */
export async function enableSystemPac(pacPath) {
  const current = await readSystemProxy();
  const backupFile = BACKUP();
  if (!fs.existsSync(backupFile)) {
    fs.writeFileSync(backupFile, JSON.stringify({ savedAt: new Date().toISOString(), ...current }, null, 2));
  }
  const pacUrl = `file:///${pacPath.replace(/\\/g, "/")}`;
  await runPowerShell(`
Set-ItemProperty -Path '${KEY}' -Name ProxyEnable -Value 0 -Type DWord
Set-ItemProperty -Path '${KEY}' -Name ProxyServer -Value '' -Type String
Set-ItemProperty -Path '${KEY}' -Name ProxyOverride -Value '<local>' -Type String
Set-ItemProperty -Path '${KEY}' -Name AutoConfigURL -Value '${pacUrl}' -Type String
${REFRESH_SNIPPET}
`);
  return { pacUrl, previous: current, backupFile };
}

export async function disableSystemProxy() {
  const backupFile = BACKUP();
  let previous = null;
  if (fs.existsSync(backupFile)) {
    try {
      previous = JSON.parse(fs.readFileSync(backupFile, "utf8"));
    } catch {
      previous = null;
    }
  }
  const enable = previous && Number(previous.ProxyEnable) === 1 ? 1 : 0;
  const server = previous && previous.ProxyServer ? previous.ProxyServer : "";
  const override = previous && previous.ProxyOverride ? previous.ProxyOverride : "";
  const autoConfig = previous && previous.AutoConfigURL ? previous.AutoConfigURL : "";
  await runPowerShell(`
Set-ItemProperty -Path '${KEY}' -Name ProxyEnable -Value ${enable} -Type DWord
Set-ItemProperty -Path '${KEY}' -Name ProxyServer -Value '${server.replace(/'/g, "''")}' -Type String
Set-ItemProperty -Path '${KEY}' -Name ProxyOverride -Value '${override.replace(/'/g, "''")}' -Type String
Set-ItemProperty -Path '${KEY}' -Name AutoConfigURL -Value '${autoConfig.replace(/'/g, "''")}' -Type String
${REFRESH_SNIPPET}
`);
  fs.rmSync(backupFile, { force: true });
  return { restored: previous, backupRemoved: true };
}

export async function refreshWinInet() {
  await runPowerShell(REFRESH_SNIPPET);
}

