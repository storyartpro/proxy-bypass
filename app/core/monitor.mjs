// Continuous monitoring: the PC's own external IP, and for every proxy its
// latency, download speed, stability and current connection load.
import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import { fileURLToPath } from "node:url";
import { dataRoot } from "./store.mjs";
import { socksConnect, connectTcp } from "./local-proxy.mjs";

const MONITOR_FILE = () => path.join(dataRoot(), "monitor.json");

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function httpsJson(url, { timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { timeout: timeoutMs, headers: { "user-agent": "proxy-app-monitor/1.0" } }, (response) => {
      let raw = "";
      response.on("data", (chunk) => {
        raw += chunk;
      });
      response.on("end", () => {
        try {
          resolve({ status: response.statusCode, body: JSON.parse(raw) });
        } catch {
          resolve({ status: response.statusCode, body: null, raw: raw.slice(0, 200) });
        }
      });
    });
    request.on("timeout", () => {
      request.destroy(new Error("timeout"));
    });
    request.on("error", reject);
  });
}

/** Download a resource through a SOCKS5 proxy to measure throughput. */
function downloadViaProxy(upstream, host, pathname, expectedBytes, timeoutMs) {
  return new Promise(async (resolve) => {
    const started = Date.now();
    let socket = null;
    let secure = null;
    let bytes = 0;
    const done = (error) => {
      try {
        secure?.destroy();
        socket?.destroy();
      } catch {
        /* ignore */
      }
      resolve({ ok: !error, error: error ? error.message : null, bytes, ms: Date.now() - started });
    };
    const timer = setTimeout(() => done(new Error("timeout")), timeoutMs);
    try {
      socket = await socksConnect(upstream, host, 443, timeoutMs);
      const tls = await import("node:tls");
      secure = tls.connect({ socket, servername: host });
      secure.once("error", (error) => {
        clearTimeout(timer);
        done(error);
      });
      secure.once("secureConnect", () => {
        secure.write(`GET ${pathname} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: proxy-app-monitor/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
      });
      secure.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes >= expectedBytes) {
          clearTimeout(timer);
          done(null);
        }
      });
      secure.on("end", () => {
        clearTimeout(timer);
        done(null);
      });
      secure.on("close", () => {
        clearTimeout(timer);
        done(null);
      });
    } catch (error) {
      clearTimeout(timer);
      done(error);
    }
  });
}

export class Monitor {
  constructor({ manager, log = () => {}, stats = null }) {
    this.manager = manager;
    this.log = log;
    this.stats = stats;
    this.config = { enabled: true, intervalSec: 60, historyLimit: 180, speedBytes: 200000, mainIpCheck: true };
    this.history = [];
    this.latest = null;
    this.timer = null;
    this.running = false;
    this.load();
  }

  load() {
    const saved = readJson(MONITOR_FILE(), null);
    if (saved) {
      this.history = Array.isArray(saved.history) ? saved.history.slice(-this.config.historyLimit) : [];
      this.latest = saved.latest || null;
    }
  }

  save() {
    try {
      const file = MONITOR_FILE();
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, JSON.stringify({ latest: this.latest, history: this.history.slice(-this.config.historyLimit) }, null, 2), "utf8");
    } catch {
      /* monitoring must never break routing */
    }
  }

  configure(config) {
    this.config = { ...this.config, ...(config || {}) };
    this.history = this.history.slice(-this.config.historyLimit);
  }

  async sampleMainIp() {
    const started = Date.now();
    try {
      const { body } = await httpsJson("https://ipinfo.io/json", { timeoutMs: 12000 });
      return {
        ok: Boolean(body && body.ip),
        ip: body?.ip || null,
        country: body?.country || null,
        city: body?.city || null,
        org: body?.org || null,
        latencyMs: Date.now() - started,
        checkedAt: new Date().toISOString(),
      };
    } catch (error) {
      return { ok: false, error: error.message, latencyMs: Date.now() - started, checkedAt: new Date().toISOString() };
    }
  }

  async sampleProxy(proxy) {
    const upstream = await this.manager.upstreamFor(proxy).catch((error) => {
      throw error;
    });
    const start = Date.now();
    let latencyMs = null;
    let ok = false;
    let error = null;
    try {
      const socket = await socksConnect(upstream, "www.google.com", 443, 12000);
      latencyMs = Date.now() - start;
      socket.destroy();
      ok = true;
    } catch (failure) {
      error = failure.message;
    }
    let speedMbps = null;
    let downloaded = 0;
    if (ok) {
      const bytes = Number(this.config.speedBytes || 200000);
      const result = await downloadViaProxy(
        upstream,
        "speed.cloudflare.com",
        `/__down?bytes=${bytes}`,
        bytes,
        25000,
      );
      downloaded = result.bytes;
      if (result.ok && result.ms > 0) {
        speedMbps = Number((((result.bytes * 8) / 1_000_000) / (result.ms / 1000)).toFixed(2));
      }
      if (!result.ok && !error) error = result.error;
    }
    const previous = this.latest?.proxies?.[proxy.id];
    const samples = Math.min(20, (previous?.samples || 0) + 1);
    const successes = Math.min(20, (previous?.successes || 0) + (ok ? 1 : 0));
    return {
      id: proxy.id,
      name: proxy.name,
      endpoint: proxy.type === "ssh" ? `ssh://${proxy.sshAlias}` : `${proxy.host}:${proxy.port}`,
      ok,
      error,
      latencyMs,
      speedMbps,
      downloadedBytes: downloaded,
      samples,
      successes,
      stability: samples ? Number(((successes / samples) * 100).toFixed(0)) : null,
      load: this.stats ? this.stats.active || 0 : null,
      checkedAt: new Date().toISOString(),
    };
  }

  async sample() {
    if (this.running) return this.latest;
    this.running = true;
    try {
      const proxies = [];
      const list = this.manager.proxies.filter((item) => item.enabled);
      for (const proxy of list) {
        proxies.push(await this.sampleProxy(proxy));
      }
      const mainIp = this.config.mainIpCheck ? await this.sampleMainIp() : this.latest?.mainIp || null;
      const sample = {
        at: new Date().toISOString(),
        mainIp,
        proxies: Object.fromEntries(proxies.map((item) => [item.id, item])),
        activeProxyId: this.manager.activeId,
        connections: this.stats ? this.stats.active || 0 : 0,
        totalConnections: this.stats ? this.stats.total || 0 : 0,
      };
      this.latest = sample;
      this.history.push({
        at: sample.at,
        mainIp: mainIp?.ip || null,
        latencyMs: mainIp?.latencyMs || null,
        activeProxyId: sample.activeProxyId,
        connections: sample.connections,
        proxies: Object.fromEntries(proxies.map((item) => [item.id, { latencyMs: item.latencyMs, speedMbps: item.speedMbps, stability: item.stability }])),
      });
      if (this.history.length > this.config.historyLimit) this.history = this.history.slice(-this.config.historyLimit);
      this.save();
      return sample;
    } finally {
      this.running = false;
    }
  }

  start() {
    if (this.timer) clearInterval(this.timer);
    if (!this.config.enabled) return;
    const interval = Math.max(15, Number(this.config.intervalSec || 60)) * 1000;
    this.timer = setInterval(() => {
      this.sample().catch((error) => this.log(`мониторинг: ${error.message}`));
    }, interval);
    this.timer.unref?.();
    setTimeout(() => this.sample().catch((error) => this.log(`мониторинг: ${error.message}`)), 2500).unref?.();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}
