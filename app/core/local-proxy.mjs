// Local selective proxy for the Windows workstation.
//
// The PC sits behind the same kind of restrictions as the servers, but Windows
// has no iptables.  Instead a tiny HTTP proxy listens on loopback and decides
// per destination host: a blocked host is tunnelled through the SOCKS5
// upstream, everything else goes out directly.  Windows' system proxy points at
// this listener, so browsers and other proxy-aware apps inherit the routing.
//
// Verdicts are learned the same way as on the servers: probe directly, probe
// through SOCKS5, and treat a geo-block body on a direct 403 as a block.

import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { ipInCidr, isIpv4 } from "./targets.mjs";

export const DEFAULT_PORT = 38080;
export const USER_AGENT = "proxy-orchestrator-local/1.0";

export const GEO_MARKERS = [
  "unsupported_country_region_territory",
  "country, region, or territory not supported",
  "country or region not supported",
  "not available in your country",
  "not available in your region",
  "isn't available in your country",
  "unsupported_country",
  "unavailable_for_legal_reasons",
  "geo-restricted",
  "blocked in your region",
];

export const SEED_HOSTS = [
  "openrouter.ai",
  "api.openai.com",
  "chatgpt.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "huggingface.co",
  "api.github.com",
  "raw.githubusercontent.com",
  "registry.npmjs.org",
  "pypi.org",
  "registry-1.docker.io",
  "discord.com",
  "api.notion.com",
  "api.groq.com",
  "api.mistral.ai",
  "www.figma.com",
  "api.deepseek.com",
  // Google AI surfaces: the page opens from Russia but the service itself
  // shows "unsupported country", so they are pinned to the proxy.
  "gemini.google.com",
  "flow.google.com",
  "aistudio.google.com",
  "notebooklm.google.com",
  "labs.google",
  "gemini.app.google",
  "geminiweb-pa.clients6.google.com",
  "aisandbox-pa.googleapis.com",
  "aisandbox-pa-webchannel.clients6.google.com",
];

// Hosts that must never go through a foreign exit.  The Harness itself talks to
// DeepSeek for sign-in and model listings; routing those requests through the
// SOCKS5 made the account endpoint answer 403 and destabilised the host, so they
// are always connected directly, as are loopback and mDNS names.
export const ALWAYS_DIRECT = ["deepseek.com", "localhost", "127.0.0.1", "::1", "local", "msftconnecttest.com", "msftncsi.com"];

/** Loopback / RFC1918 / link-local: never proxied, never probed. */
export function isPrivateAddress(name) {
  const value = String(name || "").trim().toLowerCase();
  if (value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local")) return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }
  if (value.includes(":")) {
    return value === "::1" || value.startsWith("fe80:") || value.startsWith("fc") || value.startsWith("fd");
  }
  return false;
}

export function isIpLiteral(name) {
  const value = String(name || "").trim();
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":");
}

export function isAlwaysDirect(host) {
  const name = String(host || "").trim().toLowerCase();
  if (name === "") return true;
  if (isPrivateAddress(name)) return true;
  return ALWAYS_DIRECT.some((suffix) => name === suffix || name.endsWith(`.${suffix}`) || name.endsWith(suffix));
}

export function dataDir() {
  if (process.env.PROXY_APP_DATA) {
    const override = process.env.PROXY_APP_DATA;
    fs.mkdirSync(override, { recursive: true });
    return override;
  }
  const base = process.env.LOCALAPPDATA || path.join(os.homedir(), ".local", "share");
  const dir = path.join(base, "proxy-app");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Parse the upstream credentials file.  Never log or return the password. */
export function readUpstream(file) {
  const lines = fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) throw new Error("secrets file is empty");
  let index = 0;
  if (/^(socks5h?|socks|http|https)$/i.test(lines[0])) index = 1; // optional scheme line
  const host = lines[index];
  const portText = lines[index + 1];
  const username = lines[index + 2];
  const password = lines[index + 3];
  if (!host || !portText) throw new Error("secrets file: expected host and port");
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("secrets file: bad port");
  return {
    host,
    port,
    username: username || null,
    password: password || null,
    auth: Boolean(username && password),
  };
}

function once(socket, event, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => finish(new Error("timeout")), timeoutMs);
    function finish(error, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener(event, onOk);
      socket.removeListener("error", onError);
      if (error) reject(error);
      else resolve(value);
    }
    function onOk(value) {
      finish(null, value);
    }
    function onError(error) {
      finish(error);
    }
    socket.once(event, onOk);
    socket.once("error", onError);
  });
}

export function connectTcp(host, port, timeoutMs) {
  const socket = net.connect({ host, port });
  socket.setNoDelay(true);
  // Permanent catch-all: an ECONNRESET arriving after the promise settled must
  // never become an uncaught 'error' event, because this code runs inside the
  // Harness Host process where that is fatal.
  socket.on("error", () => {});
  return once(socket, "connect", timeoutMs).then(() => socket);
}

function recvExactly(socket, size, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => cleanup(new Error("timeout")), timeoutMs);
    function cleanup(error) {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      if (error) reject(error);
    }
    function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= size) {
        cleanup(null);
        resolve(buffer.subarray(0, size));
      }
    }
    function onError(error) {
      cleanup(error);
    }
    function onClose() {
      cleanup(new Error("socket closed"));
    }
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

/**
 * SOCKS5 client implemented as a single incremental parser.  All replies are
 * collected in one buffer by one listener: attaching and detaching listeners per
 * step races with the socket and used to stall the handshake for seconds.
 */
export function socksConnect(upstream, host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: upstream.host, port: upstream.port });
    socket.setNoDelay(true);
    let stage = "greeting";
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => finish(new Error("socks: timeout")), timeoutMs);

    function finish(error, value) {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      if (error) {
        socket.destroy();
        reject(error);
      } else {
        resolve(value);
      }
    }

    function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        step();
      } catch (error) {
        finish(error);
      }
    }
    function onError(error) {
      finish(error);
    }
    function onClose() {
      finish(new Error("socks: closed"));
    }

    function buildAddress() {
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
        return Buffer.concat([Buffer.from([0x01]), Buffer.from(host.split(".").map((part) => Number(part)))]);
      }
      if (host.includes(":")) {
        const [headPart, tailPart] = host.split(":");
        const head = headPart === "" ? [] : headPart.split(":");
        const tail = tailPart ? tailPart.split(":") : [];
        const groups = [];
        for (const item of head) groups.push(parseInt(item || "0", 16));
        for (let index = 0; index < 8 - head.length - tail.length; index += 1) groups.push(0);
        for (const item of tail) groups.push(parseInt(item || "0", 16));
        const bytes = [];
        for (const group of groups.slice(0, 8)) bytes.push((group >> 8) & 0xff, group & 0xff);
        return Buffer.concat([Buffer.from([0x04]), Buffer.from(bytes)]);
      }
      const name = Buffer.from(host, "utf8");
      return Buffer.concat([Buffer.from([0x03, name.length]), name]);
    }

    function sendConnect() {
      stage = "reply";
      const address = buildAddress();
      socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), address, Buffer.from([(port >> 8) & 0xff, port & 0xff])]));
    }

    function step() {
      if (stage === "greeting") {
        if (buffer.length < 2) return;
        const greeting = buffer.subarray(0, 2);
        buffer = buffer.subarray(2);
        if (greeting[0] !== 0x05) throw new Error("socks: bad version");
        if (greeting[1] === 0x02) {
          if (!upstream.auth) throw new Error("socks: upstream wants auth");
          const user = Buffer.from(upstream.username, "utf8");
          const pass = Buffer.from(upstream.password, "utf8");
          socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]));
          stage = "auth";
          return;
        }
        if (greeting[1] !== 0x00) throw new Error("socks: no acceptable auth method");
        sendConnect();
        return;
      }
      if (stage === "auth") {
        if (buffer.length < 2) return;
        const reply = buffer.subarray(0, 2);
        buffer = buffer.subarray(2);
        if (reply[1] !== 0x00) throw new Error("socks: auth rejected");
        sendConnect();
        return;
      }
      if (stage === "reply") {
        if (buffer.length < 4) return;
        const rep = buffer[1];
        const atyp = buffer[3];
        const need = atyp === 0x01 ? 4 + 6 : atyp === 0x04 ? 4 + 18 : 4 + 1 + buffer[4] + 2;
        if (buffer.length < need) return;
        buffer = buffer.subarray(need);
        if (rep !== 0x00) throw new Error(`socks: connect failed (${rep})`);
        finish(null, socket);
      }
    }

    socket.on("error", onError);
    socket.on("close", onClose);
    socket.on("connect", () => {
      socket.write(upstream.auth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]));
    });
    socket.on("data", onData);
  });
}
async function readHttpStatus(socket, timeoutMs) {
  return new Promise((resolve) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => finish({ status: 0, body: "" }), timeoutMs);
    function finish(value) {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      resolve(value);
    }
    function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= 4096) finish(parse(buffer));
      const headEnd = buffer.indexOf("\r\n\r\n");
      if (headEnd !== -1 && buffer.length >= headEnd + 4 + 512) finish(parse(buffer));
    }
    function onError() {
      finish({ status: 0, body: "" });
    }
    function onClose() {
      finish(parse(buffer));
    }
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

function parse(buffer) {
  const text = buffer.toString("utf8");
  const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(text);
  const bodyStart = text.indexOf("\r\n\r\n");
  return {
    status: match ? Number(match[1]) : 0,
    body: bodyStart === -1 ? text.slice(0, 2048) : text.slice(bodyStart + 4, bodyStart + 4 + 2048),
  };
}

async function probeThrough(socket, host, timeoutMs) {
  try {
    let conn = socket;
    conn.on("error", () => {});
    conn = tls.connect({ socket, servername: host });
    conn.setNoDelay(true);
    conn.on("error", () => {});
    await once(conn, "secureConnect", timeoutMs);
    conn.write(
      `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
    );
    const result = await readHttpStatus(conn, timeoutMs);
    conn.destroy();
    return result;
  } catch {
    return { status: 0, body: "" };
  }
}

function geoBlocked(result) {
  if (result.status !== 403 && result.status !== 451) return false;
  const body = (result.body || "").toLowerCase();
  return GEO_MARKERS.some((marker) => body.includes(marker));
}

/** Classify one host as direct / blocked / unreachable. */
export async function classify(host, upstream, timeoutMs = 5000) {
  const directSocket = await connectTcp(host, 443, timeoutMs).catch(() => null);
  const direct = directSocket ? await probeThrough(directSocket, host, timeoutMs) : { status: 0, body: "" };
  if (direct.status && direct.status !== 403 && direct.status !== 451) {
    return { verdict: "direct", reason: "direct-ok", status: direct.status };
  }
  if (geoBlocked(direct)) return { verdict: "blocked", reason: "geo-block", status: direct.status };

  const proxied = await socksConnect(upstream, host, 443, timeoutMs)
    .then((socket) => probeThrough(socket, host, timeoutMs))
    .catch(() => ({ status: 0, body: "" }));

  if (direct.status) {
    // A refusal on the direct path is ambiguous.  A *different* answer through
    // the proxy (and not another Cloudflare misdirection) is the evidence that
    // the direct path is filtered rather than the service refusing us.
    const refusal = direct.status;
    if (!proxied.status || proxied.status === 421) {
      return { verdict: "direct", reason: "service-refusal", status: refusal };
    }
    if (proxied.status !== refusal) {
      return { verdict: "blocked", reason: "proxy-answers-differently", status: proxied.status };
    }
    return { verdict: "direct", reason: "same-refusal", status: refusal };
  }

  if (proxied.status && proxied.status < 500) {
    return { verdict: "blocked", reason: "network", status: proxied.status };
  }
  return { verdict: "unreachable", reason: "both-failed", status: 0 };
}

/** IP-literal destinations (Telegram data centres, API hosts) are decided by reachability. */
export async function classifyIp(host, port, upstream, timeoutMs = 5000) {
  const direct = await connectTcp(host, port, Math.min(timeoutMs, 3000)).then((socket) => {
    socket.destroy();
    return true;
  }).catch(() => false);
  if (direct) return { verdict: "direct", reason: "tcp-ok", status: 0 };
  const viaProxy = await socksConnect(upstream, host, port, timeoutMs).then((socket) => {
    socket.destroy();
    return true;
  }).catch(() => false);
  if (viaProxy) return { verdict: "blocked", reason: "tcp-via-proxy", status: 0 };
  return { verdict: "unreachable", reason: "both-failed", status: 0 };
}

/** Background learner plus lazy per-host routing decisions. */
export class LocalRouter {
  constructor(options) {
    this.upstream = options.upstream;
    this.timeoutMs = options.timeoutMs || 5000;
    this.verdicts = new Map();
    this.forced = new Set();
    // "direct" keeps the historical behaviour (unknown hosts go direct and are
    // classified in the background); "proxy" inverts it: everything except the
    // always-direct whitelist starts on the proxy and is learned from there.
    this.defaultRoute = "direct";
    // Set by the app: when no upstream proxy is healthy, forced hosts fall back
    // to a direct connection instead of failing with a 502.
    this.upstreamAvailable = true;
    this.stateFile = path.join(dataDir(), "local-state.json");
    this.load();
  }

  load() {
    try {
      const data = JSON.parse(fs.readFileSync(this.stateFile, "utf8"));
      for (const [host, entry] of Object.entries(data.hosts || {})) {
        // Drop stale "always-direct" markers: they were written before IP-literal
        // destinations became probeable, and would keep Telegram pinned to a
        // blocked direct path forever.
        if (entry && entry.reason === "always-direct") continue;
        this.verdicts.set(host, entry);
      }
      for (const host of data.forced || []) this.forced.add(String(host).toLowerCase());
      if (data.defaultRoute === "proxy") this.defaultRoute = "proxy";
    } catch {
      /* first run */
    }
  }

  save() {
    const hosts = Object.fromEntries(this.verdicts);
    fs.writeFileSync(
      this.stateFile,
      JSON.stringify({ version: 2, updatedAt: new Date().toISOString(), hosts, forced: [...this.forced], defaultRoute: this.defaultRoute }, null, 2),
    );
  }

  /** True when the host (or a parent domain of it) is pinned to the proxy. */
  isForced(host) {
    const name = String(host || "").toLowerCase();
    if (this.forced.has(name)) return true;
    for (const entry of this.forced) {
      if (name.endsWith(`.${entry}`)) return true;
      // A subnet in the list pins every address inside it.
      if (entry.includes("/") && isIpv4(name) && ipInCidr(name, entry)) return true;
    }
    return false;
  }

  /** Pin a host to the proxy (or unpin it) and persist the decision. */
  force(host, enabled = true) {
    const name = String(host || "").trim().toLowerCase();
    if (enabled) {
      this.forced.add(name);
      this.verdicts.set(name, { verdict: "blocked", reason: "forced", status: 0, at: new Date().toISOString() });
    } else {
      this.forced.delete(name);
      this.verdicts.delete(name);
    }
    this.save();
    return { host: name, forced: enabled, forcedHosts: [...this.forced] };
  }

  /** Switch the default route for hosts that have no verdict yet. */
  setDefaultRoute(mode) {
    const next = mode === "proxy" ? "proxy" : "direct";
    this.defaultRoute = next;
    this.save();
    return {
      mode: next,
      description:
        next === "proxy"
          ? "через прокси; напрямую идут только локальные адреса и белый список"
          : "напрямую; через прокси идут только известные блокировки",
    };
  }

  get blockedCount() {
    let count = 0;
    for (const entry of this.verdicts.values()) if (entry.verdict === "blocked") count += 1;
    return count;
  }

  snapshot(limit = 60) {
    return [...this.verdicts.entries()]
      .map(([host, entry]) => ({ host, ...entry }))
      .sort((a, b) => (a.host < b.host ? -1 : 1))
      .slice(0, limit);
  }

  async learn(hosts = SEED_HOSTS) {
    const queue = [...new Set(hosts)];
    const results = [];
    const workers = 4;
    async function run() {
      while (queue.length) {
        const host = queue.shift();
        if (isAlwaysDirect(host)) {
          results.push({ host, verdict: "direct", reason: "always-direct", status: 0 });
          continue;
        }
        if (this.isForced(host)) {
          results.push({ host, verdict: "blocked", reason: "forced", status: 0 });
          continue;
        }
        const result = await classify(host, this.upstream, this.timeoutMs).catch(() => ({ verdict: "unreachable", reason: "error", status: 0 }));
        this.verdicts.set(host, { ...result, at: new Date().toISOString() });
        results.push({ host, ...result });
      }
    }
    await Promise.all(Array.from({ length: Math.min(workers, queue.length) }, () => run.call(this)));
    this.save();
    return results;
  }

  async routeFor(host, port = 443) {
    if (isAlwaysDirect(host)) return "direct";
    if (this.isForced(host)) return this.upstreamAvailable === false ? "direct" : "blocked";
    const known = this.verdicts.get(host);
    if (known && isIpLiteral(host)) {
      // IP reachability can change as the provider rotates, so re-probe stale
      // entries instead of trusting them forever.
      const ageMs = Date.now() - Date.parse(known.at || 0);
      if (Number.isFinite(ageMs) && ageMs < 15 * 60 * 1000) {
        return known.verdict === "blocked" ? "blocked" : "direct";
      }
    } else if (known) {
      return known.verdict === "blocked" ? "blocked" : "direct";
    }
    if (isIpLiteral(host)) {
      const ipResult = await classifyIp(host, port, this.upstream, this.timeoutMs).catch(() => ({ verdict: "unreachable", reason: "error", status: 0 }));
      this.verdicts.set(host, { ...ipResult, at: new Date().toISOString() });
      this.save();
      return ipResult.verdict === "blocked" ? "blocked" : "direct";
    }
    // Never make a page wait seconds for a first-time decision: pick the default
    // route now and classify in the background, so the next request already knows.
    this.learnOne(host).catch(() => {});
    if (this.defaultRoute === "proxy" && this.upstreamAvailable !== false) return "blocked";
    return "direct";
  }

  async learnOne(host) {
    const result = await classify(host, this.upstream, this.timeoutMs).catch(() => ({ verdict: "unreachable", reason: "error", status: 0 }));
    this.verdicts.set(host, { ...result, at: new Date().toISOString() });
    this.save();
    return result;
  }
}

async function pipeTunnel(client, remote) {
  remote.setNoDelay(true);
  client.pipe(remote);
  remote.pipe(client);
  const close = () => {
    client.destroy();
    remote.destroy();
  };
  client.on("error", close);
  remote.on("error", close);
  client.on("close", close);
  remote.on("close", close);
}

/** HTTP proxy (CONNECT + absolute-form) with per-host routing. */
export function createLocalProxy({ router, port = DEFAULT_PORT, host = "127.0.0.1", log = () => {}, maxSocks = 6, tunnelTimeoutMs = 25000, stats = null }) {
  // The upstream provider throttles bursts: many parallel SOCKS5 handshakes turn
  // into multi-second queues.  Apps such as Telegram and Gemini open dozens of
  // sockets at once, so the handshakes are capped and queued.
  let activeSocks = 0;
  const socksWaiters = [];
  async function withSocksSlot(task) {
    if (activeSocks >= maxSocks) await new Promise((resolve) => socksWaiters.push(resolve));
    activeSocks += 1;
    try {
      return await task();
    } finally {
      activeSocks = Math.max(0, activeSocks - 1);
      const next = socksWaiters.shift();
      if (next) next();
    }
  }

  const server = net.createServer((client) => {
    client.on("error", () => {});
    if (stats) {
      stats.active = (stats.active || 0) + 1;
      stats.total = (stats.total || 0) + 1;
      client.once("close", () => {
        stats.active = Math.max(0, (stats.active || 1) - 1);
      });
    }
    let buffer = "";
    const onData = async (chunk) => {
      buffer += chunk.toString("latin1");
      const headEnd = buffer.indexOf("\r\n\r\n");
      if (headEnd === -1) {
        if (buffer.length > 16384) client.destroy();
        return;
      }
      client.removeListener("data", onData);
      const head = buffer.slice(0, headEnd);
      const rest = buffer.slice(headEnd + 4);
      const [requestLine] = head.split("\r\n");
      const [method, target] = requestLine.split(" ");
      try {
        if (method === "CONNECT") {
          const [name, portText] = target.split(":");
          const targetPort = Number(portText || 443);
          const verdict = await router.routeFor(name, targetPort);
          const remote =
            verdict === "blocked"
              ? await withSocksSlot(() => socksConnect(router.upstream, name, targetPort, tunnelTimeoutMs))
              : await connectTcp(name, targetPort, router.timeoutMs);
          client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          if (rest) remote.write(Buffer.from(rest, "latin1"));
          await pipeTunnel(client, remote);
          return;
        }
        if (method === "GET" || method === "POST" || method === "HEAD" || method === "PUT" || method === "DELETE") {
          const url = new URL(target);
          const targetPort = Number(url.port || (url.protocol === "https:" ? 443 : 80));
          const verdict = await router.routeFor(url.hostname, targetPort);
          const remote =
            verdict === "blocked"
              ? await withSocksSlot(() => socksConnect(router.upstream, url.hostname, targetPort, tunnelTimeoutMs))
              : await connectTcp(url.hostname, targetPort, router.timeoutMs);
          const pathPart = `${url.pathname}${url.search || ""}`;
          const headers = head
            .split("\r\n")
            .slice(1)
            .filter((line) => !/^proxy-connection:/i.test(line));
          remote.write(`${method} ${pathPart} HTTP/1.1\r\n${headers.join("\r\n")}\r\n\r\n`);
          if (rest) remote.write(Buffer.from(rest, "latin1"));
          await pipeTunnel(client, remote);
          return;
        }
        client.write("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
        client.destroy();
      } catch (error) {
        log(`local proxy: ${method} ${target} failed: ${error.message}`);
        if (!client.destroyed) client.end("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
      }
    };
    client.on("data", onData);
  });
  return {
    server,
    port,
    start: () =>
      new Promise((resolve, reject) => {
        // A listener error after startup must never become an uncaught
        // exception in the Host process: log it and keep serving.
        server.on("error", (error) => log(`local proxy server error: ${error.message}`));
        const onStartupError = (error) => reject(error);
        server.once("error", onStartupError);
        server.listen(port, host, () => {
          server.removeListener("error", onStartupError);
          resolve({ port, host });
        });
      }),
    stop: () =>
      new Promise((resolve) => {
        const finish = () => resolve();
        // Open keep-alive connections would otherwise keep `close()` pending
        // forever and the daemon process would never exit.
        server.close(finish);
        if (typeof server.closeAllConnections === "function") {
          server.closeAllConnections();
        } else {
          server.closeIdleConnections?.();
        }
        setTimeout(finish, 1500).unref?.();
      }),
  };
}


