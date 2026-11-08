// Domain reconnaissance for the blocked list: every address a domain resolves to
// and all subdomains that can be discovered (certificate transparency, with a
// common-prefix fallback). Everything can go through the active proxy, because
// on a filtered network DNS and CT endpoints are often blocked too.
import dns from "node:dns/promises";
import https from "node:https";
import tls from "node:tls";
import { normalizeTarget } from "./targets.mjs";
import { socksConnect } from "./local-proxy.mjs";

const USER_AGENT = "proxy-bypass-lookup/1.0";
const MAX_RESPONSE = 4 * 1024 * 1024;

const COMMON_PREFIXES = [
  "www", "api", "app", "cdn", "static", "assets", "img", "media", "files", "download",
  "mail", "smtp", "auth", "sso", "login", "account", "accounts", "admin", "panel", "dashboard",
  "dev", "test", "stage", "staging", "beta", "m", "mobile", "shop", "blog", "docs", "help",
  "support", "status", "edge", "origin", "ws", "socket", "stream", "video", "upload",
];

function fetchDirect(url, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { timeout: timeoutMs, headers: { "user-agent": USER_AGENT, "accept-encoding": "identity", accept: "application/json,text/plain,*/*" } }, (response) => {
      if (response.statusCode && response.statusCode >= 400) {
        response.resume();
        reject(new Error(`HTTP ${response.statusCode}`));
        return;
      }
      let size = 0;
      let body = "";
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE) {
          request.destroy(new Error("response too large"));
          return;
        }
        body += chunk;
      });
      response.on("end", () => resolve(body));
    });
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", reject);
  });
}

/** Same request through a SOCKS5 upstream (CONNECT + TLS). */
async function fetchViaProxy(upstream, url, timeoutMs = 20000) {
  const parsed = new URL(url);
  const port = Number(parsed.port || 443);
  const socket = await socksConnect(upstream, parsed.hostname, port, timeoutMs);
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername: parsed.hostname });
    let body = "";
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      secure.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => finish(new Error("timeout")), timeoutMs);
    secure.once("error", (error) => finish(error));
    secure.once("secureConnect", () => {
      secure.write(
        `GET ${parsed.pathname}${parsed.search} HTTP/1.1\r\nHost: ${parsed.hostname}\r\n`
        + `User-Agent: ${USER_AGENT}\r\nAccept: application/json,text/plain,*/*\r\n`
        + "Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
      );
    });
    secure.on("data", (chunk) => {
      body += chunk;
      if (body.length > MAX_RESPONSE) finish(new Error("response too large"));
    });
    secure.on("end", () => finish(null, body));
  });
}

async function fetchText(url, upstream) {
  try {
    return await fetchDirect(url);
  } catch (directError) {
    if (!upstream) throw directError;
    return fetchViaProxy(upstream, url);
  }
}

function stripHttpHead(raw) {
  const index = raw.indexOf("\r\n\r\n");
  let body = index === -1 ? raw : raw.slice(index + 4);
  // de-chunk if the endpoint answered with chunked encoding
  if (/^[0-9a-f]+\r\n/i.test(body)) {
    let out = "";
    let rest = body;
    while (rest.length) {
      const match = /^([0-9a-f]+)\r\n/i.exec(rest);
      if (!match) break;
      const size = parseInt(match[1], 16);
      if (!size) break;
      out += rest.slice(match[0].length, match[0].length + size);
      rest = rest.slice(match[0].length + size + 2);
    }
    body = out;
  }
  return body.trim();
}

async function lookupIps(host) {
  const result = { ipv4: [], ipv6: [] };
  try {
    result.ipv4 = await dns.resolve4(host);
  } catch {
    /* NXDOMAIN / blocked DNS */
  }
  try {
    result.ipv6 = await dns.resolve6(host);
  } catch {
    /* nothing */
  }
  if (!result.ipv4.length) {
    try {
      result.ipv4 = (await dns.lookup(host, { all: true })).filter((item) => item.family === 4).map((item) => item.address);
    } catch {
      /* still nothing */
    }
  }
  return result;
}

function cleanName(value, base) {
  const name = String(value || "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!name || name === base) return null;
  if (!name.endsWith(`.${base}`)) return null;
  const label = name.slice(0, -(base.length + 1));
  if (!label || label.includes("/") || label.includes(" ")) return null;
  return name;
}

/** Discover subdomains through crt.sh, then probe common prefixes as a fallback. */
async function discoverSubdomains(base, upstream) {
  const found = new Set();
  let source = "certificate-transparency";
  try {
    const raw = await fetchText(`https://crt.sh/?q=${encodeURIComponent(`%.${base}`)}&output=json`, upstream);
    const body = stripHttpHead(raw);
    let rows = [];
    try {
      rows = JSON.parse(body);
    } catch {
      rows = [];
    }
    for (const row of Array.isArray(rows) ? rows : []) {
      for (const value of String(row.name_value || "").split("\n")) {
        const name = cleanName(value, base);
        if (name) found.add(name);
      }
    }
  } catch {
    source = "common-prefixes";
  }

  // Probe the usual prefixes for whatever CT did not reveal (and as the only
  // source when crt.sh is unreachable).
  const missing = COMMON_PREFIXES.filter((prefix) => !found.has(`${prefix}.${base}`));
  const probe = await Promise.all(
    missing.map(async (prefix) => {
      const name = `${prefix}.${base}`;
      try {
        const ips = await dns.resolve4(name);
        return ips.length ? name : null;
      } catch {
        return null;
      }
    }),
  );
  for (const name of probe) if (name) found.add(name);
  if (found.size && source === "certificate-transparency") source = "certificate-transparency + prefixes";
  return { subdomains: [...found].sort().slice(0, 300), source };
}

/**
 * Expand one domain into everything worth routing: the domain itself, its
 * subdomains and the IPv4 addresses it resolves to.
 * @param {string} input
 * @param {{upstream?: object}} options
 */
export async function expandDomain(input, { upstream } = {}) {
  const baseTarget = normalizeTarget(input);
  if (baseTarget.kind !== "domain") throw new Error("для разворота нужен домен, а не IP");
  const base = baseTarget.value;
  const ips = await lookupIps(base);
  const { subdomains, source } = await discoverSubdomains(base, upstream);

  const entries = [];
  const seen = new Set();
  const push = (kind, value) => {
    const key = `${kind}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    entries.push({ kind, value });
  };
  push("domain", base);
  for (const name of subdomains) push("domain", name);
  for (const ip of ips.ipv4) push("ip", ip);

  return {
    domain: base,
    source,
    ips: ips.ipv4,
    ipsV6: ips.ipv6,
    subdomains,
    entries,
  };
}
