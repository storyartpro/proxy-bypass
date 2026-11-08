// Per-application bypass: remember chosen processes/services, discover every
// network channel they open and feed those endpoints into the blocked list.
//
// Windows has no per-process routing without a driver, so the practical approach
// is: observe the endpoints an application talks to and pin those endpoints to the
// routing proxy. Once a channel is in the blocked list, every application that
// connects to it goes through the proxy.
import { spawn } from "node:child_process";
import dns from "node:dns/promises";

const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const MAX_CHANNELS = 500;
const PRIVATE_RE = /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.)/;

export function isWindows() {
  return process.platform === "win32";
}

function runPowerShell(script, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    const child = spawn(PS, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], {
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("PowerShell timeout"));
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
      else reject(new Error(stderr.trim() || `PowerShell exit ${code}`));
    });
  });
}

async function psJson(script) {
  const output = await runPowerShell(script);
  const text = output.trim();
  if (!text) return null;
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end <= start) {
    const arrayStart = text.indexOf("[");
    const arrayEnd = text.lastIndexOf("]");
    if (arrayStart === -1 || arrayEnd <= arrayStart) return null;
    return JSON.parse(text.slice(arrayStart, arrayEnd + 1));
  }
  return JSON.parse(text.slice(start, end + 1));
}

function psString(value) {
  return `'${String(value ?? "").replace(/'/g, "''")}'`;
}

/** One snapshot: processes, services and the established TCP connections. */
export async function snapshot() {
  if (!isWindows()) return { processes: [], services: [], connections: [] };
  const data = await psJson(`
$ErrorActionPreference = 'SilentlyContinue'
$processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, ParentProcessId
$services = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, ProcessId, PathName
$connections = Get-NetTCPConnection -State Established | Select-Object OwningProcess, RemoteAddress, RemotePort
[pscustomobject]@{
  processes = @($processes)
  services = @($services)
  connections = @($connections)
} | ConvertTo-Json -Depth 4 -Compress
`);
  if (!data || typeof data !== "object") return { processes: [], services: [], connections: [] };
  return {
    processes: Array.isArray(data.processes) ? data.processes : data.processes ? [data.processes] : [],
    services: Array.isArray(data.services) ? data.services : data.services ? [data.services] : [],
    connections: Array.isArray(data.connections) ? data.connections : data.connections ? [data.connections] : [],
  };
}

function processName(process_) {
  return String(process_.Name || "").toLowerCase();
}

/** Resolve which process ids belong to a tracked application. */
export function pidsForProfile(profile, snap) {
  const pids = new Set();
  const name = String(profile.name || "").toLowerCase();
  if (profile.kind === "service") {
    for (const service of snap.services || []) {
      if (String(service.Name || "").toLowerCase() !== name
        && String(service.DisplayName || "").toLowerCase() !== name) continue;
      if (service.ProcessId) pids.add(Number(service.ProcessId));
      const exeName = String(service.PathName || "").split("\\").pop()?.replace(/"/g, "").toLowerCase();
      if (exeName) {
        for (const process_ of snap.processes || []) {
          if (processName(process_) === exeName) pids.add(Number(process_.ProcessId));
        }
      }
    }
    return { pids: [...pids].filter(Boolean), running: [...pids].some((pid) => pid > 0) };
  }
  for (const process_ of snap.processes || []) {
    if (processName(process_) === name || processName(process_) === `${name}.exe`) {
      pids.add(Number(process_.ProcessId));
    }
  }
  return { pids: [...pids], running: pids.size > 0 };
}

/** Extract public endpoints used by the given pids and try to name them. */
export async function channelsForPids(pids, snap) {
  const wanted = new Set(pids.map(Number));
  const ips = new Set();
  const hosts = new Set();
  for (const connection of snap.connections || []) {
    if (!wanted.has(Number(connection.OwningProcess))) continue;
    const address = String(connection.RemoteAddress || "");
    if (!address || PRIVATE_RE.test(address) || address === "::1" || address === "::" || address.startsWith("fe80")) continue;
    ips.add(address);
  }
  const newIps = [...ips].slice(0, MAX_CHANNELS);
  await Promise.all(
    newIps.map(async (ip) => {
      try {
        const names = await dns.reverse(ip);
        const name = names.find((item) => item.includes(".") && !/^\d/.test(item));
        if (name) hosts.add(name.toLowerCase().replace(/\.$/, ""));
      } catch {
        /* no PTR record */
      }
    }),
  );
  return { ips: newIps, hosts: [...hosts].slice(0, MAX_CHANNELS) };
}

function sanitiseTarget(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text || PRIVATE_RE.test(text) || text === "::1") return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) return text;
  if (/^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/.test(text)) return text;
  return null;
}

/** Merge new channels into a profile, keeping the list bounded and unique. */
export function mergeChannels(profile, channels) {
  const existing = new Set(profile.discovered || []);
  const added = [];
  for (const value of [...(channels.ips || []), ...(channels.hosts || [])]) {
    const target = sanitiseTarget(value);
    if (!target || existing.has(target)) continue;
    existing.add(target);
    added.push(target);
  }
  profile.discovered = [...existing].slice(0, MAX_CHANNELS);
  profile.lastScanAt = new Date().toISOString();
  return added;
}

/** Blocked list = manual entries + channels of proxy-mode profiles, minus the
 *  channels of profiles explicitly routed directly. */
export function mergeBlocked(manual, profiles) {
  const result = new Set();
  for (const value of manual || []) {
    const target = sanitiseTarget(value) || String(value || "").trim().toLowerCase();
    if (target) result.add(target);
  }
  const direct = new Set();
  for (const profile of profiles || []) {
    if (profile.enabled === false) continue;
    if (profile.mode === "direct") {
      for (const value of profile.discovered || []) {
        const target = sanitiseTarget(value) || String(value || "").trim().toLowerCase();
        if (target) direct.add(target);
      }
      continue;
    }
    for (const value of profile.discovered || []) {
      const target = sanitiseTarget(value) || String(value || "").trim().toLowerCase();
      if (target) result.add(target);
    }
  }
  // "Direct" wins: the user explicitly asked this application's endpoints to
  // leave the bypass even if they are also in the manual list.
  for (const value of direct) result.delete(value);
  return [...result].sort();
}

/** Normalise a "track this application" request. */
export function normaliseProfileInput(input, providedId) {
  const kind = input.kind === "service" ? "service" : "process";
  const name = String(input.name || "").trim().slice(0, 200);
  if (!name) throw new Error("не указано имя процесса или службы");
  const id = String(providedId || input.id || `app-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`);
  return {
    id,
    kind,
    name,
    label: String(input.label || name).slice(0, 120),
    mode: input.mode === "direct" ? "direct" : "proxy",
    enabled: input.enabled !== false,
    discovered: Array.isArray(input.discovered) ? input.discovered.filter((item) => sanitiseTarget(item)) : [],
    createdAt: input.createdAt || new Date().toISOString(),
    lastScanAt: input.lastScanAt || null,
  };
}
