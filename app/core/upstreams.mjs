// Ordered failover across up to five upstream proxies.
//
// Each entry is either a direct SOCKS5 endpoint or an SSH dynamic forward to one
// of the user's servers.  The first healthy entry in priority order is "active";
// when it stops answering, the next one takes over and the local proxy keeps
// serving, so applications never see a dead route.
import net from "node:net";
import { spawn } from "node:child_process";
import { socksConnect, connectTcp } from "./local-proxy.mjs";

const MAX_PROXIES = 5;
const HEALTH_TARGET = "www.google.com";
// Providers can be slow under load: a 8 s probe used to mark a working proxy
// dead and drop the whole route. 20 s tolerates slow-but-alive handshakes.
const HEALTH_TIMEOUT_MS = 20000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function waitPort(host, port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const attempt = () => {
      if (Date.now() > deadline) {
        resolve(false);
        return;
      }
      const socket = net.connect({ host, port });
      socket.once("connect", () => {
        socket.destroy();
        resolve(true);
      });
      socket.once("error", () => {
        socket.destroy();
        setTimeout(attempt, 250);
      });
    };
    attempt();
  });
}

export class UpstreamManager {
  constructor({ log = () => {} } = {}) {
    this.log = log;
    this.proxies = [];
    this.health = new Map();
    this.tunnels = new Map();
    this.pendingTunnels = new Map();
    this.activeId = null;
    this.downStreak = 0;
    this.timer = null;
    this.refreshing = false;
    this.listeners = new Set();
  }

  onChange(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit() {
    for (const listener of this.listeners) {
      try {
        listener(this);
      } catch {
        /* listeners must not break routing */
      }
    }
  }

  setProxies(proxies) {
    this.proxies = (proxies || []).slice(0, MAX_PROXIES).map((item, index) => ({
      ...item,
      priority: index + 1,
      enabled: item.enabled !== false,
    }));
    this.emit();
  }

  activeProxy() {
    return this.proxies.find((item) => item.id === this.activeId) || null;
  }

  async upstreamFor(proxy) {
    if (!proxy) return null;
    if (proxy.type === "ssh") {
      const ready = await this.ensureTunnel(proxy);
      if (!ready) throw new Error(`SSH-туннель ${proxy.sshAlias} не поднялся`);
      return { host: "127.0.0.1", port: Number(proxy.localPort || 1081), auth: false };
    }
    return {
      host: proxy.host,
      port: Number(proxy.port),
      auth: Boolean(proxy.login && proxy.password),
      username: proxy.login || null,
      password: proxy.password || null,
    };
  }

  async ensureTunnel(proxy) {
    const key = proxy.id;
    // Serialise concurrent callers: health checks, the router and the scanner may
    // all ask for the same tunnel at once, and two ssh processes on one port
    // kill each other.
    const pending = this.pendingTunnels.get(key);
    if (pending) return pending;
    const task = this.openTunnel(proxy).finally(() => this.pendingTunnels.delete(key));
    this.pendingTunnels.set(key, task);
    return task;
  }

  async openTunnel(proxy) {
    const key = proxy.id;
    const port = Number(proxy.localPort || 1081);
    // A previous app instance (or a manual `ssh -D`) may still own the port:
    // adopt that listener instead of fighting it.
    if (await waitPort("127.0.0.1", port, 300)) return true;
    const existing = this.tunnels.get(key);
    if (existing && !existing.killed && existing.child.exitCode === null) {
      const alive = await waitPort("127.0.0.1", port, 500);
      if (alive) return true;
    }
    try {
      existing?.child?.kill?.();
    } catch {
      /* already gone */
    }
    this.tunnels.delete(key);
    const binary = process.env.PROXY_APP_SSH || "ssh";
    const child = spawn(
      binary,
      ["-N", "-D", `127.0.0.1:${port}`, "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15", proxy.sshAlias],
      { stdio: "ignore", windowsHide: true },
    );
    child.on("exit", (code) => {
      this.log(`proxy ${proxy.id}: ssh exited with ${code}`);
      if (this.tunnels.get(key)?.child === child) this.tunnels.delete(key);
    });
    this.tunnels.set(key, { child });
    const ready = await waitPort("127.0.0.1", port, 20000);
    if (!ready) {
      child.kill();
      this.tunnels.delete(key);
      return false;
    }
    this.log(`proxy ${proxy.id}: tunnel 127.0.0.1:${port} -> ${proxy.sshAlias}`);
    return true;
  }

  async checkProxy(proxy) {
    const started = Date.now();
    try {
      const upstream = await this.upstreamFor(proxy);
      const socket = await socksConnect(upstream, HEALTH_TARGET, 443, HEALTH_TIMEOUT_MS);
      socket.destroy();
      this.health.set(proxy.id, { healthy: true, latencyMs: Date.now() - started, checkedAt: new Date().toISOString(), error: null });
      return true;
    } catch (error) {
      this.health.set(proxy.id, { healthy: false, latencyMs: null, checkedAt: new Date().toISOString(), error: error.message });
      return false;
    }
  }

  /** Probe every enabled proxy in parallel and activate the first healthy one in priority order. */
  async refresh() {
    if (this.refreshing) return this.snapshot();
    this.refreshing = true;
    try {
      for (const proxy of this.proxies) {
        if (!proxy.enabled) {
          this.health.set(proxy.id, { healthy: false, latencyMs: null, checkedAt: new Date().toISOString(), error: "выключен" });
        }
      }
      const enabled = this.proxies.filter((proxy) => proxy.enabled);
      // Parallel probes: a sequential sweep with a slow proxy could keep the UI
      // waiting for tens of seconds before the first window appears.
      const results = await Promise.all(
        enabled.map(async (proxy) => ({ proxy, healthy: await this.checkProxy(proxy) })),
      );
      const chosen = results.find((item) => item.healthy)?.proxy || null;
      const nextId = chosen ? chosen.id : null;
      if (nextId === null && this.activeId && this.downStreak < 1) {
        // One failed sweep is not enough evidence to drop a route that was
        // working: a provider may be slow or briefly throttling. Keep it until
        // the next sweep also fails.
        this.downStreak += 1;
        this.log("failover: проверка не прошла — сохраняю прежний маршрут до следующего цикла");
        this.emit();
        return this.snapshot();
      }
      if (nextId === this.activeId) {
        this.downStreak = 0;
        return this.snapshot();
      }
      if (nextId === null) this.downStreak += 1;
      else this.downStreak = 0;
      if (nextId !== this.activeId) {
        const previous = this.activeId;
        this.activeId = nextId;
        if (nextId) this.log(`failover: активный прокси -> ${chosen.name}${previous ? ` (был ${previous})` : ""}`);
        else this.log("failover: нет доступных прокси");
        this.emit();
      }
      return this.snapshot();
    } finally {
      this.refreshing = false;
    }
  }

  async start(intervalMs = 20000) {
    await this.refresh();
    if (this.timer) clearInterval(this.timer);
    this.timer = setInterval(() => {
      this.refresh().catch((error) => this.log(`failover refresh: ${error.message}`));
    }, Math.max(5000, intervalMs));
    this.timer.unref?.();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    for (const { child } of this.tunnels.values()) {
      try {
        child.kill();
      } catch {
        /* already gone */
      }
    }
    this.tunnels.clear();
  }

  snapshot() {
    return {
      activeId: this.activeId,
      active: this.activeProxy()
        ? {
            id: this.activeProxy().id,
            name: this.activeProxy().name,
            type: this.activeProxy().type,
            endpoint: this.activeProxy().type === "ssh" ? `ssh://${this.activeProxy().sshAlias}` : `${this.activeProxy().host}:${this.activeProxy().port}`,
          }
        : null,
      proxies: this.proxies.map((proxy) => ({
        id: proxy.id,
        name: proxy.name,
        type: proxy.type,
        priority: proxy.priority,
        enabled: proxy.enabled,
        endpoint: proxy.type === "ssh" ? `ssh://${proxy.sshAlias}:${proxy.localPort}` : `${proxy.host}:${proxy.port}`,
        active: proxy.id === this.activeId,
        health: this.health.get(proxy.id) || null,
      })),
    };
  }
}

export { MAX_PROXIES, sleep, waitPort };
