// Persistent configuration and state for the proxy app.
import fs from "node:fs";
import path from "node:path";
import { dpapiAvailable, protectSecret, unprotectSecret } from "./dpapi.mjs";

export function dataRoot() {
  if (process.env.PROXY_APP_DATA) return process.env.PROXY_APP_DATA;
  const base = process.env.LOCALAPPDATA || path.join(process.env.USERPROFILE || ".", "AppData", "Local");
  return path.join(base, "proxy-app");
}

const CONFIG_PATH = () => path.join(dataRoot(), "config.json");

const DEFAULTS = {
  port: 38080,
  activeProxyId: null,
  // The PC is the control centre: it reaches the internet through its own
  // proxies, never through the managed servers.  Credentials can be entered in
  // the UI or pulled from a local secrets file (see `secretsFile`).
  proxies: [
    {
      id: "proxy-1",
      name: "SOCKS5 proxy",
      type: "socks5",
      host: "127.0.0.1",
      port: 1080,
      login: "",
      password: "",
      enabled: true,
    },
  ],
  // Optional local file with proxy credentials (host / port / login / password).
  secretsFile: "",
  monitoring: {
    enabled: true,
    intervalSec: 60,
    historyLimit: 180,
    speedBytes: 200000,
    mainIpCheck: true,
  },
  // Local SOCKS5 tunnel for applications that can only use their own proxy
  // setting (Telegram, for instance): the app keeps `ssh -N -D` alive.
  localTunnel: {
    enabled: false,
    sshAlias: "",
    port: 1081,
  },
  servers: [{ alias: "my-server", label: "My Linux server" }],
  blocked: [
    "gemini.google.com",
    "flow.google.com",
    "aistudio.google.com",
    "notebooklm.google.com",
    "labs.google",
    "gemini.app.google",
    "geminiweb-pa.clients6.google.com",
    "aisandbox-pa.googleapis.com",
    "aisandbox-pa-webchannel.clients6.google.com",
    "content.googleapis.com",
    "api.openai.com",
    "chatgpt.com",
    "openrouter.ai",
    "api.anthropic.com",
    "api.groq.com",
    "discord.com",
    "api.notion.com",
  ],
  scanner: {
    enabled: true,
    intervalMin: 15,
    seeds: [
      "openrouter.ai",
      "api.openai.com",
      "chatgpt.com",
      "api.anthropic.com",
      "generativelanguage.googleapis.com",
      "huggingface.co",
      "api.github.com",
      "registry.npmjs.org",
      "pypi.org",
      "registry-1.docker.io",
      "discord.com",
      "api.notion.com",
      "api.groq.com",
      "api.mistral.ai",
      "www.figma.com",
      "api.deepseek.com",
    ],
  },
  autoPushToServers: false,
  updatedAt: null,
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function loadConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH(), "utf8");
    const parsed = JSON.parse(raw);
    return {
      ...clone(DEFAULTS),
      ...parsed,
      scanner: { ...DEFAULTS.scanner, ...(parsed.scanner || {}) },
      monitoring: { ...DEFAULTS.monitoring, ...(parsed.monitoring || {}) },
      localTunnel: { ...DEFAULTS.localTunnel, ...(parsed.localTunnel || {}) },
    };
  } catch {
    return clone(DEFAULTS);
  }
}

/**
 * Persist the configuration. Passwords are encrypted with Windows DPAPI
 * (`passwordEnc`) and never written in plain text when DPAPI is available.
 */
export async function writeConfig(config) {
  fs.mkdirSync(dataRoot(), { recursive: true });
  const next = { ...config, updatedAt: new Date().toISOString() };
  const copy = JSON.parse(JSON.stringify(next));
  for (const proxy of copy.proxies || []) {
    if (proxy.password) {
      const ciphertext = await protectSecret(proxy.password);
      if (ciphertext) {
        proxy.passwordEnc = ciphertext;
        delete proxy.password;
      }
    }
  }
  fs.writeFileSync(CONFIG_PATH(), JSON.stringify(copy, null, 2), "utf8");
  return next;
}

/** Load the configuration and decrypt stored proxy passwords. */
export async function loadConfigAsync() {
  const config = loadConfig();
  let changed = false;
  for (const proxy of config.proxies || []) {
    if (proxy.passwordEnc && !proxy.password) {
      const plain = await unprotectSecret(proxy.passwordEnc);
      if (plain) {
        proxy.password = plain;
        changed = true;
      }
    }
  }
  if (changed) return config;
  return config;
}

export { dpapiAvailable };

export function defaultConfig() {
  return clone(DEFAULTS);
}
