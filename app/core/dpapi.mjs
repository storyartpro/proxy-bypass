// Windows DPAPI helpers: encrypt secrets with the current Windows account so a
// stolen config file is useless on another machine or account.
//
// Implemented through PowerShell's ProtectedData because Node has no DPAPI
// binding. The secret is passed over stdin (never argv) and the ciphertext comes
// back as base64.
import { spawn } from "node:child_process";

const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

function runPowerShell(script, input, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    const child = spawn(PS, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], {
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("DPAPI timeout"));
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(stdout);
      else reject(new Error(stderr.trim() || `powershell exit ${code}`));
    });
    child.stdin.end(input ?? "");
  });
}

export function dpapiAvailable() {
  return process.platform === "win32";
}

const PROTECT_SCRIPT = `
Add-Type -AssemblyName System.Security
$text = [Console]::In.ReadToEnd()
if ($text.Length -eq 0) { exit 2 }
$bytes = [Text.Encoding]::UTF8.GetBytes($text)
$encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($encrypted))
`;

const UNPROTECT_SCRIPT = `
Add-Type -AssemblyName System.Security
$text = [Console]::In.ReadToEnd()
if ($text.Length -eq 0) { exit 2 }
$bytes = [Convert]::FromBase64String($text)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain))
`;

/** Encrypt with DPAPI. Returns null when DPAPI is not available. */
export async function protectSecret(plain) {
  if (!dpapiAvailable() || typeof plain !== "string" || plain === "") return null;
  const output = await runPowerShell(PROTECT_SCRIPT, plain);
  const ciphertext = output.trim();
  return ciphertext || null;
}

/** Decrypt a DPAPI-protected base64 string. Returns null on failure. */
export async function unprotectSecret(ciphertext) {
  if (!dpapiAvailable() || typeof ciphertext !== "string" || ciphertext === "") return null;
  try {
    const output = await runPowerShell(UNPROTECT_SCRIPT, ciphertext);
    return output;
  } catch {
    return null;
  }
}
