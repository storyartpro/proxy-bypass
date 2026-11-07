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
import { loadConfig, loadConfigAsync, writeConfig, dataRoot, defaultConfig } from "./core/store.mjs";
import * as servers from "./core/servers.mjs";
import { normalizeTarget } from "./core/targets.mjs";

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
const state = { proxyRunning: false, pcProxyEnabled: false, pcProxyError: null, scannerTimer: null, lastScan: null };

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
      config.blocked.push(host);
      found.push({ host, reason: result.reason });
    }
  }
  if (found.length) {
    config = await writeConfig(config);
    syncForcedHosts();
    log(`сканер: добавлено ${found.length} адрес(ов): ${found.map((item) => item.host).join(", ")}`);
    if (config.autoPushToServers) {
      for (const server of config.servers) {
        servers.pushBlockedList(server.alias, found.map((item) => item.host)).catch((error) => log(`push ${server.alias}: ${error.message}`));
      }
    }
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
  log("ПК: системный прокси включён");
}

async function disablePc() {
  await disableSystemProxy();
  log("ПК: системный прокси выключен");
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

async function apiStatus() {
  const pc = await pcStatus();
  return {
    ok: true,
    startedAt,
    pc: { proxyRunning: state.proxyRunning, proxyEnabled: pc.pcProxyEnabled, port: config.port },
    upstreams: manager.snapshot(),
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
  "GET /api/proxies": async () => ({ ok: true, ...manager.snapshot(), max: 5 }),
  "POST /api/proxies": async (body) => {
    if (!Array.isArray(body.proxies)) throw new Error("proxies must be an array");
    if (body.proxies.length > 5) throw new Error("не более 5 прокси");
    config.proxies = body.proxies.map((item, index) => ({
      id: item.id || `proxy-${index + 1}`,
      name: String(item.name || `Прокси ${index + 1}`).slice(0, 80),
      type: item.type === "ssh" ? "ssh" : "socks5",
      host: item.type === "ssh" ? undefined : String(item.host || "").trim(),
      port: item.type === "ssh" ? undefined : Number(item.port || 0),
      login: item.type === "ssh" ? undefined : String(item.login || ""),
      password: item.type === "ssh" ? undefined : String(item.password || ""),
      sshAlias: item.type === "ssh" ? String(item.sshAlias || "").trim() : undefined,
      localPort: item.type === "ssh" ? Number(item.localPort || 1081) : undefined,
      enabled: item.enabled !== false,
    }));
    config = await writeConfig(config);
    manager.setProxies(config.proxies);
    await manager.refresh();
    return { ok: true, ...manager.snapshot() };
  },
  "POST /api/proxies/check": async () => ({ ok: true, ...(await manager.refresh()) }),
  "GET /api/blocked": async () => ({ ok: true, blocked: config.blocked, blockedCount: config.blocked.length }),
  "POST /api/blocked/add": async (body) => {
    const target = normalizeTarget(body.host);
    const host = target.value;
    if (!config.blocked.includes(host)) {
      config.blocked.push(host);
      config = await writeConfig(config);
      syncForcedHosts();
      log(`список: добавлен ${host} (${target.kind})`);
    }
    return { ok: true, kind: target.kind, blocked: config.blocked };
  },
  "POST /api/blocked/remove": async (body) => {
    const host = String(body.host || "").trim().toLowerCase();
    config.blocked = config.blocked.filter((item) => item !== host);
    config = await writeConfig(config);
    syncForcedHosts();
    log(`список: удалён ${host}`);
    return { ok: true, blocked: config.blocked };
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
  setTimeout(() => scan().catch((error) => log(`первый скан: ${error.message}`)), 3000);

  const port = Number(process.env.PROXY_APP_PORT || config.appPort || 8077);
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
  });
}

process.on("uncaughtException", (error) => log(`fatal: ${error.stack || error.message}`));
process.on("unhandledRejection", (error) => log(`unhandled: ${error && error.message ? error.message : error}`));
process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));

main().catch((error) => {
  log(`startup failed: ${error.message}`);
  process.exit(1);
});
