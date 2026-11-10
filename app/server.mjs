// Proxy app backend: one process that owns the local routing proxy, the
// failover list, the blocked-host list, the scanner and the server fleet.
import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createLocalProxy, LocalRouter, classify, readUpstream } from "./core/local-proxy.mjs";
import { Monitor } from "./core/monitor.mjs";
import { UpstreamManager } from "./core/upstreams.mjs";
import { enableSystemProxy, disableSystemProxy, readSystemProxy } from "./core/system-proxy.mjs";
import { enableEnvProxy, disableEnvProxy, envProxyStatus, proxyUrlFor } from "./core/env-proxy.mjs";
import { loadConfig, loadConfigAsync, writeConfig, dataRoot, defaultConfig } from "./core/store.mjs";
import * as servers from "./core/servers.mjs";
import { normalizeTarget, parseTargetList } from "./core/targets.mjs";
import { expandDomain } from "./core/lookup.mjs";
import * as apps from "./core/apps.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const UI = path.join(HERE, "ui");
const LOG_FILE = path.join(dataRoot(), "app.log");
const startedAt = new Date().toISOString();
const logs = [];
const serverCache = new Map();

function log(message) {
  const line = `${new Date().toISOString()} ${message}`;
  logs.push(line);
  if (logs.length > 500) logs.shift();
  try {
    fs.mkdirSync(dataRoot(), { recursive: true });
    fs.appendFileSync(LOG_FILE, `${line}\n`);
  } catch {
    /* logging must never break the app */
  }
  console.log(line);
}

let config = loadConfig();
const manager = new UpstreamManager({ log });
const router = new LocalRouter({ upstream: { host: "127.0.0.1", port: 9, auth: false } });
const stats = { active: 0, total: 0 };
const proxy = createLocalProxy({ router, port: config.port, log, stats });
const monitor = new Monitor({ manager, log, stats });
const state = {
  proxyRunning: false,
  pcProxyEnabled: false,
  pcProxyError: null,
  envProxy: null,
  envProxyAt: 0,
  envProxyError: null,
  scannerTimer: null,
  appsTimer: null,
  lastScan: null,
};

/** Fill/refresh SOCKS5 credentials from the secrets file.
 *
 * Providers rotate passwords, so an empty-or-stale store must be refreshed from
 * the file the user already maintains instead of silently failing with the old
 * password.
 */
async function hydrateProxyCredentials() {
  let changed = false;
  for (const item of config.proxies) {
    if (item.type !== "socks5" || !config.secretsFile) continue;
    try {
      const upstream = readUpstream(config.secretsFile);
      if (upstream.host !== item.host) continue;
      if (upstream.port && Number(upstream.port) !== Number(item.port)) continue;
      const nextLogin = upstream.username || "";
      const nextPassword = upstream.password || "";
      if (item.login !== nextLogin || item.password !== nextPassword) {
        item.login = nextLogin;
        item.password = nextPassword;
        changed = true;
        log("прокси: логин и пароль обновлены из файла секретов");
      }
    } catch (error) {
      log(`прокси: не удалось прочитать файл секретов (${error.message})`);
    }
  }
  if (changed) {
    config = await writeConfig(config);
  }
}

function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  response.end(body);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let raw = "";
    request.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 2_000_000) reject(new Error("too large"));
    });
    request.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("invalid json"));
      }
    });
    request.on("error", reject);
  });
}

function syncForcedHosts() {
  const wanted = new Set((config.blocked || []).map((host) => String(host).toLowerCase()));
  for (const host of [...router.forced]) {
    if (!wanted.has(host)) router.force(host, false);
  }
  for (const host of wanted) router.force(host, true);
}

/** The blocked list is materialised from two sources: manual entries and the
 *  channels of tracked application profiles. */
function ensureConfigSources() {
  let changed = false;
  if (!Array.isArray(config.manualBlocked)) {
    config.manualBlocked = [...(config.blocked || [])];
    changed = true;
  }
  if (!Array.isArray(config.appProfiles)) {
    config.appProfiles = [];
    changed = true;
  }
  return changed;
}

async function rebuildBlocked({ save = true } = {}) {
  const merged = apps.mergeBlocked(config.manualBlocked, config.appProfiles);
  const before = JSON.stringify(config.blocked || []);
  config.blocked = merged;
  syncForcedHosts();
  if (save && JSON.stringify(merged) !== before) config = await writeConfig(config);
  return merged;
}

/** Add validated targets to the manual part of the blocked list. */
async function addTargets(values) {
  const manual = new Set(config.manualBlocked || []);
  const added = [];
  for (const raw of values || []) {
    let target;
    try {
      target = normalizeTarget(raw);
    } catch {
      continue;
    }
    if (!manual.has(target.value)) {
      manual.add(target.value);
      added.push(target.value);
    }
  }
  if (added.length) {
    config.manualBlocked = [...manual];
    await rebuildBlocked();
    log(`список: добавлено ${added.length} (${added.slice(0, 5).join(", ")}${added.length > 5 ? "…" : ""})`);
    if (config.autoPushToServers) {
      for (const server of config.servers) {
        servers.pushBlockedList(server.alias, added).catch((error) => log(`push ${server.alias}: ${error.message}`));
      }
    }
  }
  return added;
}

/** Remove one target from the manual list. */
async function removeManualTarget(value) {
  const host = String(value || "").trim().toLowerCase();
  config.manualBlocked = (config.manualBlocked || []).filter((item) => item !== host);
  await rebuildBlocked();
  return config.blocked;
}

/** Sample the endpoints of tracked applications and rebuild the blocked list. */
async function scanApplicationProfiles(onlyId) {
  if (!apps.isWindows()) return { ok: false, error: "функция доступна только на Windows" };
  const snap = await apps.snapshot();
  const results = [];
  const addedAll = [];
  for (const profile of config.appProfiles || []) {
    if (onlyId && profile.id !== onlyId) continue;
    if (profile.enabled === false) {
      results.push({ id: profile.id, skipped: true });
      continue;
    }
    const { pids, running } = apps.pidsForProfile(profile, snap);
    if (!running) {
      profile.lastScanAt = new Date().toISOString();
      results.push({ id: profile.id, running: false, added: 0, channels: (profile.discovered || []).length });
      continue;
    }
    const channels = await apps.channelsForPids(pids, snap);
    const added = apps.mergeChannels(profile, channels);
    addedAll.push(...added);
    results.push({ id: profile.id, running: true, added: added.length, channels: (profile.discovered || []).length, pids: pids.length });
  }
  if (addedAll.length) {
    config = await writeConfig(config);
    await rebuildBlocked();
    log(`приложения: новые каналы (${addedAll.length}): ${addedAll.slice(0, 6).join(", ")}${addedAll.length > 6 ? "…" : ""}`);
    if (config.autoPushToServers) {
      for (const server of config.servers) {
        servers.pushBlockedList(server.alias, addedAll).catch((error) => log(`push ${server.alias}: ${error.message}`));
      }
    }
  } else {
    config = await writeConfig(config);
  }
  return { ok: true, scannedAt: new Date().toISOString(), added: addedAll.length, profiles: results };
}

function scheduleApplicationScanner() {
  if (state.appsTimer) clearInterval(state.appsTimer);
  state.appsTimer = null;
  const enabled = (config.appProfiles || []).filter((profile) => profile.enabled !== false);
  if (!enabled.length) return;
  state.appsTimer = setInterval(() => {
    scanApplicationProfiles().catch((error) => log(`приложения: ${error.message}`));
  }, 15_000);
  state.appsTimer.unref?.();
}

async function activeUpstream() {
  const proxyItem = manager.activeProxy();
  if (!proxyItem) return null;
  try {
    return await manager.upstreamFor(proxyItem);
  } catch {
    return null;
  }
}

async function scan() {
  const upstream = await activeUpstream();
  if (!upstream) {
    return { ok: false, error: "нет доступного прокси для проверки" };
  }
  const found = [];
  for (const host of config.scanner.seeds) {
    const result = await classify(host, upstream, 6000).catch(() => ({ verdict: "unreachable" }));
    if (result.verdict === "blocked" && !config.blocked.includes(host)) {
      found.push({ host, reason: result.reason });
    }
  }
  if (found.length) {
    await addTargets(found.map((item) => item.host));
    log(`сканер: добавлено ${found.length} адрес(ов): ${found.map((item) => item.host).join(", ")}`);
  }
  state.lastScan = { at: new Date().toISOString(), checked: config.scanner.seeds.length, found };
  return { ok: true, ...state.lastScan };
}

function scheduleScanner() {
  if (state.scannerTimer) clearInterval(state.scannerTimer);
  state.scannerTimer = null;
  if (!config.scanner.enabled) return;
  const interval = Math.max(2, Number(config.scanner.intervalMin || 15)) * 60_000;
  state.scannerTimer = setInterval(() => {
    scan().catch((error) => log(`сканер: ${error.message}`));
  }, interval);
  state.scannerTimer.unref?.();
}

async function pcStatus() {
  let systemProxy = null;
  try {
    systemProxy = await readSystemProxy();
  } catch (error) {
    state.pcProxyError = error.message;
  }
  const ours = systemProxy && Number(systemProxy.ProxyEnable) === 1 && String(systemProxy.ProxyServer || "").includes(String(config.port));
  return {
    proxyRunning: state.proxyRunning,
    pcProxyEnabled: Boolean(ours),
    systemProxy,
    port: config.port,
    error: state.pcProxyError,
  };
}

async function enablePc() {
  if (!state.proxyRunning) throw new Error("локальный прокси не запущен");
  await enableSystemProxy(`127.0.0.1:${config.port}`);
  state.pcProxyError = null;
  if (!config.pcProxyWanted) {
    config.pcProxyWanted = true;
    config = await writeConfig(config);
  }
  log("ПК: системный прокси включён");
}

async function disablePc() {
  await disableSystemProxy();
  if (config.pcProxyWanted !== false) {
    config.pcProxyWanted = false;
    config = await writeConfig(config);
  }
  log("ПК: системный прокси выключен");
}

/**
 * Environment variables are the second coverage layer: they reach command-line
 * tools (curl, git, pip, npm, Python requests) that ignore WinINET settings.
 * Reading them spawns PowerShell, so the status is cached between UI polls.
 */
async function envStatus(force = false) {
  if (!force && state.envProxy && Date.now() - state.envProxyAt < 30_000) return state.envProxy;
  try {
    state.envProxy = await envProxyStatus(config.port);
    state.envProxyAt = Date.now();
    state.envProxyError = null;
  } catch (error) {
    state.envProxyError = error.message;
  }
  return state.envProxy || { installed: false, proxyUrl: proxyUrlFor(config.port), error: state.envProxyError };
}

async function enableEnv() {
  if (!state.proxyRunning) throw new Error("локальный прокси не запущен");
  await enableEnvProxy(config.port);
  state.envProxyAt = 0;
  if (!config.envProxyWanted) {
    config.envProxyWanted = true;
    config = await writeConfig(config);
  }
  log(`ПК: переменные среды направлены на ${proxyUrlFor(config.port)}`);
}

async function disableEnv() {
  await disableEnvProxy(config.port);
  state.envProxyAt = 0;
  if (config.envProxyWanted !== false) {
    config.envProxyWanted = false;
    config = await writeConfig(config);
  }
  log("ПК: переменные среды возвращены");
}

async function serverListStatuses(refresh = false) {
  const now = Date.now();
  const result = [];
  for (const item of config.servers) {
    const cached = serverCache.get(item.alias);
    if (!refresh && cached && now - cached.at < 30_000) {
      result.push(cached.value);
      continue;
    }
    try {
      const status = await servers.serverStatus(item.alias);
      const value = { alias: item.alias, label: item.label || item.alias, ...status };
      serverCache.set(item.alias, { at: now, value });
      result.push(value);
    } catch (error) {
      const value = { alias: item.alias, label: item.label || item.alias, installed: false, running: false, error: error.message };
      serverCache.set(item.alias, { at: now, value });
      result.push(value);
    }
  }
  return result;
}

/** Proxy list for the UI: health/active state merged with the real configuration
 * fields (host, port, login, password), so a save never wipes them. */
function proxiesView() {
  const snapshot = manager.snapshot();
  const configured = new Map((config.proxies || []).map((item) => [item.id, item]));
  return {
    ...snapshot,
    proxies: snapshot.proxies.map((item) => {
      const raw = configured.get(item.id) || {};
      const { passwordEnc, ...rest } = raw;
      return { ...rest, ...item };
    }),
  };
}

async function apiStatus() {
  const pc = await pcStatus();
  const env = await envStatus();
  return {
    ok: true,
    startedAt,
    pc: { proxyRunning: state.proxyRunning, proxyEnabled: pc.pcProxyEnabled, envEnabled: Boolean(env.installed), port: config.port },
    router: { mode: router.defaultRoute, upstreamAvailable: router.upstreamAvailable, forcedCount: router.forced.size },
    upstreams: proxiesView(),
    blockedCount: config.blocked.length,
    blocked: config.blocked,
    scanner: { enabled: config.scanner.enabled, intervalMin: config.scanner.intervalMin, lastScan: state.lastScan },
    monitoring: { enabled: config.monitoring.enabled, intervalSec: config.monitoring.intervalSec, latest: monitor.latest },
    autoPushToServers: config.autoPushToServers,
    localTunnel: tunnelStatus(),
    servers: config.servers,
    lastLogs: logs.slice(-40),
  };
}

const routes = {
  "GET /api/status": async () => apiStatus(),
  "GET /api/pc": async () => ({ ok: true, ...(await pcStatus()) }),
  "POST /api/pc/toggle": async (body) => {
    const want = Boolean(body.enabled);
    if (want) await enablePc();
    else await disablePc();
    return { ok: true, ...(await pcStatus()) };
  },
  "GET /api/env": async () => ({ ok: true, ...(await envStatus(true)) }),
  "POST /api/env/toggle": async (body) => {
    if (Boolean(body.enabled)) await enableEnv();
    else await disableEnv();
    return { ok: true, ...(await envStatus(true)) };
  },
  "GET /api/router": async () => ({
    ok: true,
    mode: router.defaultRoute,
    upstreamAvailable: router.upstreamAvailable,
    forcedCount: router.forced.size,
  }),
  "POST /api/router/mode": async (body) => {
    const result = router.setDefaultRoute(body.mode);
    log(`маршрут по умолчанию: ${result.mode === "proxy" ? "через прокси" : "напрямую"}`);
    return { ok: true, ...result };
  },
  "GET /api/proxies": async () => ({ ok: true, ...proxiesView(), max: 5 }),
  "POST /api/proxies": async (body) => {
    if (!Array.isArray(body.proxies)) throw new Error("proxies must be an array");
    if (body.proxies.length > 5) throw new Error("не более 5 прокси");
    const existing = new Map((config.proxies || []).map((item) => [item.id, item]));
    config.proxies = body.proxies.map((item, index) => {
      const previous = existing.get(item.id) || {};
      const type = item.type === "ssh" ? "ssh" : "socks5";
      const host = String(item.host ?? previous.host ?? "").trim();
      const port = Number(item.port ?? previous.port ?? 0);
      if (type === "socks5" && (!host || !Number.isInteger(port) || port <= 0)) {
        throw new Error(`прокси ${index + 1}: нужны хост и порт SOCKS5`);
      }
      return {
        id: item.id || `proxy-${index + 1}`,
        name: String(item.name || previous.name || `Прокси ${index + 1}`).slice(0, 80),
        type,
        host: type === "ssh" ? undefined : host,
        port: type === "ssh" ? undefined : port,
        login: type === "ssh" ? undefined : String(item.login ?? previous.login ?? ""),
        password: type === "ssh" ? undefined : String(item.password ?? previous.password ?? ""),
        sshAlias: type === "ssh" ? String(item.sshAlias || previous.sshAlias || "").trim() : undefined,
        localPort: type === "ssh" ? Number(item.localPort || previous.localPort || 1081) : undefined,
        enabled: item.enabled !== false,
      };
    });
    config = await writeConfig(config);
    manager.setProxies(config.proxies);
    await manager.refresh();
    return { ok: true, ...proxiesView() };
  },
  "POST /api/proxies/check": async () => ({ ok: true, ...(await manager.refresh(), proxiesView()) }),
  "GET /api/blocked": async () => ({ ok: true, blocked: config.blocked, blockedCount: config.blocked.length }),
  "POST /api/blocked/add": async (body) => {
    const target = normalizeTarget(body.host);
    await addTargets([target.value]);
    return { ok: true, kind: target.kind, blocked: config.blocked };
  },
  "POST /api/blocked/import": async (body) => {
    const text = String(body.text ?? "");
    const parsed = parseTargetList(text);
    const added = await addTargets(parsed.valid.map((item) => item.value));
    let expanded = null;
    if (body.expandDomains && added.length) {
      const upstream = await activeUpstream();
      const expandedEntries = [];
      const domains = added.filter((value) => !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)).slice(0, 10);
      const details = [];
      for (const domain of domains) {
        try {
          const result = await expandDomain(domain, { upstream });
          details.push({ domain, ips: result.ips.length, subdomains: result.subdomains.length, source: result.source });
          expandedEntries.push(...result.entries.map((item) => item.value));
        } catch (error) {
          details.push({ domain, error: error.message });
        }
      }
      const expandedAdded = await addTargets(expandedEntries);
      expanded = { domains: details, added: expandedAdded.length };
    }
    return {
      ok: true,
      added,
      addedCount: added.length,
      duplicates: parsed.duplicates,
      invalid: parsed.invalid.slice(0, 30),
      invalidCount: parsed.invalid.length,
      expanded,
      blocked: config.blocked,
    };
  },
  "POST /api/blocked/expand": async (body) => {
    const host = normalizeTarget(body.host).value;
    const upstream = await activeUpstream();
    const result = await expandDomain(host, { upstream });
    const added = await addTargets(result.entries.map((item) => item.value));
    return {
      ok: true,
      domain: result.domain,
      source: result.source,
      ips: result.ips,
      subdomains: result.subdomains,
      entriesTotal: result.entries.length,
      added: added.length,
      blocked: config.blocked,
    };
  },
  "POST /api/blocked/remove": async (body) => {
    const host = String(body.host || "").trim().toLowerCase();
    await removeManualTarget(host);
    log(`список: удалён ${host}`);
    return { ok: true, blocked: config.blocked };
  },
  "GET /api/apps": async () => {
    if (!apps.isWindows()) return { ok: false, error: "функция доступна только на Windows" };
    const snap = await apps.snapshot();
    const profiles = (config.appProfiles || []).map((profile) => {
      const { pids, running } = apps.pidsForProfile(profile, snap);
      return {
        ...profile,
        running,
        pids: pids.length,
        channels: (profile.discovered || []).length,
        samples: (profile.discovered || []).slice(0, 12),
      };
    });
    const connected = new Set((snap.connections || []).map((item) => Number(item.OwningProcess)));
    const processes = (snap.processes || [])
      .map((item) => ({ pid: Number(item.ProcessId), name: item.Name, path: item.ExecutablePath || "", connected: connected.has(Number(item.ProcessId)) }))
      .filter((item) => item.name && item.name.toLowerCase() !== "system")
      .sort((a, b) => Number(b.connected) - Number(a.connected) || a.name.localeCompare(b.name))
      .slice(0, 400);
    const services = (snap.services || [])
      .map((item) => ({ name: item.Name, label: item.DisplayName, state: item.State, pid: Number(item.ProcessId || 0) }))
      .sort((a, b) => a.name.localeCompare(b.name));
    return { ok: true, profiles, processes, services };
  },
  "POST /api/apps/track": async (body) => {
    ensureConfigSources();
    const profile = apps.normaliseProfileInput(body);
    const exists = (config.appProfiles || []).some(
      (item) => item.kind === profile.kind && item.name.toLowerCase() === profile.name.toLowerCase(),
    );
    if (exists) throw new Error("этот процесс или служба уже отслеживается");
    config.appProfiles = [...(config.appProfiles || []), profile];
    config = await writeConfig(config);
    await rebuildBlocked();
    scheduleApplicationScanner();
    log(`приложения: добавлено наблюдение за ${profile.kind} ${profile.name}`);
    const result = await scanApplicationProfiles(profile.id).catch((error) => ({ ok: false, error: error.message }));
    return { ok: true, profile: { ...profile, added: result.added || 0 }, profiles: config.appProfiles, blocked: config.blocked };
  },
  "POST /api/apps/untrack": async (body) => {
    const id = String(body.id || "");
    const profile = (config.appProfiles || []).find((item) => item.id === id);
    if (!profile) throw new Error("профиль не найден");
    config.appProfiles = (config.appProfiles || []).filter((item) => item.id !== id);
    config = await writeConfig(config);
    await rebuildBlocked();
    scheduleApplicationScanner();
    log(`приложения: наблюдение за ${profile.name} отменено, каналы убраны из списка`);
    return { ok: true, profiles: config.appProfiles, blocked: config.blocked };
  },
  "POST /api/apps/toggle": async (body) => {
    const id = String(body.id || "");
    const profile = (config.appProfiles || []).find((item) => item.id === id);
    if (!profile) throw new Error("профиль не найден");
    profile.enabled = body.enabled !== false;
    config = await writeConfig(config);
    await rebuildBlocked();
    scheduleApplicationScanner();
    return { ok: true, profiles: config.appProfiles, blocked: config.blocked };
  },
  "POST /api/apps/mode": async (body) => {
    const id = String(body.id || "");
    const profile = (config.appProfiles || []).find((item) => item.id === id);
    if (!profile) throw new Error("профиль не найден");
    const mode = body.mode === "direct" ? "direct" : "proxy";
    profile.mode = mode;
    config = await writeConfig(config);
    await rebuildBlocked();
    log(`приложения: ${profile.name} -> ${mode === "proxy" ? "через прокси" : "напрямую"}`);
    return { ok: true, profiles: config.appProfiles, blocked: config.blocked };
  },
  "POST /api/apps/scan": async (body) => {
    ensureConfigSources();
    const result = await scanApplicationProfiles(body.id ? String(body.id) : undefined);
    return { ...result, profiles: config.appProfiles, blocked: config.blocked };
  },
  "POST /api/scan": async () => scan(),
  "POST /api/scanner": async (body) => {
    config.scanner.enabled = body.enabled !== false;
    if (Number.isFinite(body.intervalMin)) config.scanner.intervalMin = Math.max(2, Math.trunc(body.intervalMin));
    config = await writeConfig(config);
    scheduleScanner();
    return { ok: true, scanner: config.scanner };
  },
  "POST /api/settings": async (body) => {
    if (body.autoPushToServers !== undefined) config.autoPushToServers = Boolean(body.autoPushToServers);
    config = await writeConfig(config);
    return { ok: true, autoPushToServers: config.autoPushToServers };
  },
  "GET /api/servers": async () => ({ ok: true, servers: await serverListStatuses(true) }),
  "POST /api/servers/add": async (body) => {
    const alias = String(body.alias || "").trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(alias)) throw new Error("некорректный SSH-алиас");
    await servers.testConnection(alias);
    if (!config.servers.some((item) => item.alias === alias)) {
      config.servers.push({ alias, label: String(body.label || alias).slice(0, 80) });
      config = await writeConfig(config);
    }
    return { ok: true, servers: await serverListStatuses(true) };
  },
  "POST /api/servers/remove": async (body) => {
    const alias = String(body.alias || "");
    config.servers = config.servers.filter((item) => item.alias !== alias);
    config = await writeConfig(config);
    serverCache.delete(alias);
    return { ok: true, servers: config.servers };
  },
  "POST /api/servers/install": async (body) => {
    const alias = String(body.alias || "");
    const result = await servers.installServer(alias, config.blocked);
    log(`сервер ${alias}: установлен`);
    return { ok: true, status: result };
  },
  "POST /api/servers/control": async (body) => {
    const alias = String(body.alias || "");
    const action = String(body.action || "");
    const result = await servers.controlServer(alias, action);
    log(`сервер ${alias}: ${action}`);
    return { ok: true, status: result };
  },
  "POST /api/servers/push": async (body) => {
    const alias = String(body.alias || "");
    const hosts = Array.isArray(body.hosts) && body.hosts.length ? body.hosts : config.blocked;
    const result = await servers.pushBlockedList(alias, hosts);
    log(`сервер ${alias}: передано ${result.pushed}/${result.total} адресов`);
    return { ok: true, ...result };
  },
  "GET /api/monitor": async () => ({
    ok: true,
    enabled: config.monitoring.enabled,
    intervalSec: config.monitoring.intervalSec,
    latest: monitor.latest,
    history: monitor.history.slice(-60),
  }),
  "POST /api/monitor/sample": async () => ({ ok: true, latest: await monitor.sample() }),
  "POST /api/monitor/config": async (body) => {
    if (body.enabled !== undefined) config.monitoring.enabled = Boolean(body.enabled);
    if (Number.isFinite(body.intervalSec)) config.monitoring.intervalSec = Math.max(15, Math.trunc(body.intervalSec));
    config = await writeConfig(config);
    monitor.configure(config.monitoring);
    monitor.start();
    return { ok: true, monitoring: { enabled: config.monitoring.enabled, intervalSec: config.monitoring.intervalSec } };
  },
  "POST /api/servers/push-proxy": async (body) => {
    const alias = String(body.alias || "");
    const proxyItem = config.proxies.find((item) => item.id === body.proxyId) || config.proxies.find((item) => item.enabled);
    if (!proxyItem) throw new Error("нет прокси с логином и паролем");
    const result = await servers.pushProxySettings(alias, proxyItem);
    log(`сервер ${alias}: прокси обновлён (${proxyItem.host}:${proxyItem.port})`);
    return { ok: true, proxy: { host: proxyItem.host, port: proxyItem.port }, result };
  },
  "GET /api/tunnel": async () => ({ ok: true, tunnel: tunnelStatus() }),
  "POST /api/tunnel": async (body) => {
    config.localTunnel = {
      enabled: body.enabled !== false,
      sshAlias: String(body.sshAlias ?? config.localTunnel?.sshAlias ?? "").trim(),
      port: Number.isFinite(body.port) ? Math.max(1, Math.trunc(body.port)) : Number(config.localTunnel?.port || 1081),
    };
    config = await writeConfig(config);
    stopLocalTunnel();
    await startLocalTunnel();
    return { ok: true, tunnel: tunnelStatus() };
  },
  "POST /api/shutdown": async () => {
    log("команда: закрыть полностью");
    setTimeout(async () => {
      try {
        if (state.scannerTimer) clearInterval(state.scannerTimer);
        monitor.stop();
        stopLocalTunnel();
        manager.stop();
        await disableSystemProxy().catch((error) => log(`возврат прокси Windows: ${error.message}`));
        // The env layer must not point at a dead listener after the app exits;
        // `envProxyWanted` keeps the intent so the next start turns it back on.
        await disableEnvProxy(config.port).catch((error) => log(`возврат переменных среды: ${error.message}`));
        await Promise.race([
          new Promise((resolve) => proxy.stop().then(resolve).catch(() => resolve())),
          new Promise((resolve) => setTimeout(resolve, 2000)),
        ]);
        log("приложение остановлено");
        process.exit(0);
      } catch (error) {
        log(`остановка: ${error.message}`);
        process.exit(1);
      }
    }, 300);
    return { ok: true, stopping: true };
  },
  "GET /api/logs": async () => ({ ok: true, logs: logs.slice(-200) }),
};

function serveStatic(request, response) {
  const url = new URL(request.url, "http://localhost");
  let file = url.pathname === "/" ? "/index.html" : url.pathname;
  const full = path.join(UI, path.normalize(file).replace(/^([/\\])+/, ""));
  if (!full.startsWith(UI) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) {
    response.writeHead(404).end("not found");
    return;
  }
  const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml" };
  response.writeHead(200, { "content-type": types[path.extname(full)] || "application/octet-stream", "cache-control": "no-store" });
  fs.createReadStream(full).pipe(response);
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, "http://localhost");
    const key = `${request.method} ${url.pathname}`;
    const handler = routes[key];
    if (handler) {
      const body = request.method === "POST" ? await readBody(request) : {};
      const result = await handler(body);
      json(response, 200, result);
      return;
    }
    if (request.method === "GET" && !url.pathname.startsWith("/api/")) {
      serveStatic(request, response);
      return;
    }
    json(response, 404, { ok: false, error: "not found" });
  } catch (error) {
    json(response, 400, { ok: false, error: error.message });
  }
});

/** Local SOCKS5 tunnel (`ssh -N -D`) for apps that can only set their own proxy. */
const tunnelState = { child: null, status: "off", error: null, startedAt: null, restarts: 0 };

function portAlive(port, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    const done = (value) => {
      socket.destroy();
      resolve(value);
    };
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    setTimeout(() => done(false), timeoutMs).unref?.();
  });
}

async function startLocalTunnel() {
  const tunnelSettings = config.localTunnel || {};
  if (!tunnelSettings.enabled) {
    tunnelState.status = "off";
    return;
  }
  if (!tunnelSettings.sshAlias) {
    tunnelState.status = "error";
    tunnelState.error = "не задан SSH-алиас";
    return;
  }
  if (tunnelState.child && tunnelState.child.exitCode === null) return;
  const port = Number(tunnelSettings.port || 1081);
  const binary = process.env.PROXY_APP_SSH || "ssh";
  const child = spawn(
    binary,
    ["-N", "-D", `127.0.0.1:${port}`, "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15", tunnelSettings.sshAlias],
    { stdio: "ignore", windowsHide: true },
  );
  tunnelState.child = child;
  tunnelState.status = "starting";
  tunnelState.error = null;
  tunnelState.startedAt = new Date().toISOString();
  child.on("error", (error) => {
    tunnelState.status = "error";
    tunnelState.error = error.message;
  });
  child.on("exit", (code) => {
    if (tunnelState.child !== child) return;
    tunnelState.child = null;
    if (!config.localTunnel.enabled) {
      tunnelState.status = "off";
      return;
    }
    tunnelState.status = "restarting";
    tunnelState.restarts += 1;
    log(`туннель для приложений: ssh завершился (${code}), перезапускаю`);
    setTimeout(() => startLocalTunnel().catch((error) => log(`туннель: ${error.message}`)), 5000).unref?.();
  });
  setTimeout(async () => {
    if (await portAlive(port)) {
      tunnelState.status = "running";
      tunnelState.error = null;
      log(`туннель для приложений: SOCKS5 127.0.0.1:${port} -> ${tunnelSettings.sshAlias}`);
    }
  }, 1500).unref?.();
}

function stopLocalTunnel() {
  const child = tunnelState.child;
  tunnelState.child = null;
  tunnelState.status = "off";
  if (child) {
    try {
      child.kill();
    } catch {
      /* already gone */
    }
  }
}

function tunnelStatus() {
  return {
    enabled: Boolean(config.localTunnel?.enabled),
    sshAlias: config.localTunnel?.sshAlias || "",
    port: Number(config.localTunnel?.port || 1081),
    status: tunnelState.status,
    error: tunnelState.error,
    restarts: tunnelState.restarts,
  };
}

const TRAY_SCRIPT = fileURLToPath(new URL("./tray.ps1", import.meta.url));

/** Tray icon: keeps the app reachable after the window is closed. */
function startTray() {
  if (process.platform !== "win32" || !fs.existsSync(TRAY_SCRIPT)) return;
  try {
    const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    const child = spawn(
      powershell,
      ["-Sta", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", TRAY_SCRIPT],
      { stdio: ["ignore", "ignore", "pipe"], windowsHide: true, cwd: path.dirname(TRAY_SCRIPT) },
    );
    child.stderr.on("data", (chunk) => {
      const text = String(chunk).trim();
      if (text) log(`трей: ${text.slice(0, 300)}`);
    });
    child.on("error", (error) => log(`трей: ${error.message}`));
    child.on("exit", (code) => log(`трей: процесс завершился (${code})`));
    log(`иконка в трее запущена (pid ${child.pid})`);
  } catch (error) {
    log(`трей: ${error.message}`);
  }
}

/** True when something already serves the app UI on the loopback port. */
function interfaceAlive(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    const done = (value) => {
      socket.destroy();
      resolve(value);
    };
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    setTimeout(() => done(false), 1200).unref?.();
  });
}

function openWindow() {
  if (process.env.PROXY_APP_NO_WINDOW) return;
  const url = `http://127.0.0.1:${config.appPort || 8077}`;
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  const chrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const binary = fs.existsSync(edge) ? edge : fs.existsSync(chrome) ? chrome : null;
  if (!binary) return;
  try {
    spawn(binary, [`--app=${url}`, "--window-size=1180,820", "--no-first-run", "--disable-features=msEdgeSidebarV2"], { detached: true, stdio: "ignore" }).unref();
  } catch {
    /* the browser window is a nicety, not a requirement */
  }
}

/** Bring the UI, the window and the tray up. Called before the slow network
 *  probes so the user sees the window immediately. */
function startInterface(port) {
  server.on("error", (error) => {
    if (error && error.code === "EADDRINUSE") {
      // Already running: the Start-menu shortcut must still open the window
      // instead of silently doing nothing.
      log(`интерфейс уже запущен на порту ${port} — открываю окно существующего экземпляра`);
      openWindow();
      setTimeout(() => process.exit(0), 1500);
      return;
    }
    log(`сервер интерфейса: ${error.message}`);
  });
  server.listen(port, "127.0.0.1", () => {
    log(`интерфейс: http://127.0.0.1:${port}`);
    openWindow();
    startTray();
  });
}

async function main() {
  fs.mkdirSync(dataRoot(), { recursive: true });
  const interfacePort = Number(process.env.PROXY_APP_PORT || config.appPort || 8077);
  // If the interface already answers, this launch only has to bring the window
  // back — exactly what a Start-menu click expects while the app keeps running
  // in the background. Check this before binding the routing proxy, otherwise
  // the proxy port conflict would kill the process first.
  if (await interfaceAlive(interfacePort)) {
    log(`приложение уже запущено на 127.0.0.1:${interfacePort} — открываю окно`);
    openWindow();
    setTimeout(() => process.exit(0), 1500);
    return;
  }
  config = await loadConfigAsync();
  ensureConfigSources();
  await rebuildBlocked();
  // The workstation must not route its own traffic through the managed servers:
  // any legacy SSH-tunnel entry in the proxy list is dropped.
  const sshEntries = config.proxies.filter((item) => item.type === "ssh");
  if (sshEntries.length) {
    config.proxies = config.proxies.filter((item) => item.type !== "ssh");
    config = await writeConfig(config);
    log(`прокси: убраны SSH-туннели из локального списка (${sshEntries.length})`);
  }
  await hydrateProxyCredentials();
  manager.setProxies(config.proxies);
  syncForcedHosts();
  monitor.configure(config.monitoring);
  manager.onChange(async () => {
    const upstream = await activeUpstream();
    if (upstream) router.upstream = upstream;
    router.upstreamAvailable = Boolean(upstream);
    log(`активный прокси: ${manager.activeProxy() ? manager.activeProxy().name : "нет"}`);
  });
  const upstream = await activeUpstream();
  if (upstream) router.upstream = upstream;
  router.upstreamAvailable = Boolean(upstream);

  try {
    await proxy.start();
  } catch (error) {
    if (error && error.code === "EADDRINUSE") {
      log(`порт ${config.port} занят другим экземпляром — открываю его окно`);
      openWindow();
      setTimeout(() => process.exit(0), 1500);
      return;
    }
    throw error;
  }
  state.proxyRunning = true;
  log(`локальный прокси слушает 127.0.0.1:${config.port}`);
  // "Закрыть полностью" restores Windows settings; the next start brings the
  // bypass back only if it was on when the app was closed.
  if (config.pcProxyWanted) {
    enablePc().catch((error) => log(`автовключение прокси на ПК: ${error.message}`));
  }
  if (config.envProxyWanted) {
    enableEnv().catch((error) => log(`автовключение переменных среды: ${error.message}`));
  }

  startInterface(interfacePort);
  await manager.start(20000);
  // Passwords rotate outside the app: re-read the secrets file periodically so a
  // stale credential cannot keep the only proxy marked as failing.
  setInterval(() => {
    hydrateProxyCredentials()
      .then(() => {
        manager.setProxies(config.proxies);
        return manager.refresh();
      })
      .catch((error) => log(`обновление реквизитов: ${error.message}`));
  }, 5 * 60_000).unref?.();
  monitor.start();
  startLocalTunnel().catch((error) => log(`туннель для приложений: ${error.message}`));
  scheduleScanner();
  scheduleApplicationScanner();
  setTimeout(() => scan().catch((error) => log(`первый скан: ${error.message}`)), 3000);
}

process.on("uncaughtException", (error) => log(`fatal: ${error.stack || error.message}`));
process.on("unhandledRejection", (error) => log(`unhandled: ${error && error.message ? error.message : error}`));
process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));

main().catch((error) => {
  log(`startup failed: ${error.message}`);
  process.exit(1);
});
