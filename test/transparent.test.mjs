import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// The engine keeps its state under dataDir(), which honours this variable.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-transparent-test-"));
process.env.PROXY_APP_DATA = dir;

const transparent = await import("../app/core/transparent.mjs");

test("cidrsFor keeps IP literals and skips host names", () => {
  assert.deepEqual(transparent.cidrsFor(["185.9.25.56", "example.com", "2001:db8::1", "185.9.25.56", ""]), [
    "185.9.25.56/32",
    "2001:db8::1/128",
  ]);
  assert.deepEqual(transparent.cidrsFor(), []);
});

test("buildConfig captures all traffic into the local proxy", () => {
  const config = transparent.buildConfig({ port: 38080, dnsServer: "192.168.15.1" });
  assert.equal(config.inbounds[0].type, "tun");
  assert.equal(config.inbounds[0].stack, "gvisor");
  assert.equal(config.inbounds[0].interface_name, "proxyapp");
  assert.equal(config.inbounds[0].auto_route, true);
  assert.equal(config.outbounds[0].type, "http");
  assert.equal(config.outbounds[0].server_port, 38080);
  assert.equal(config.route.final, "app");
  assert.equal(config.dns.final, "local");
  assert.equal(config.dns.servers[0].server, "192.168.15.1");

  const rules = config.route.rules;
  assert.equal(rules[0].action, "sniff");
  assert.equal(rules[1].action, "hijack-dns");
  const processRule = rules.find((rule) => rule.process_name);
  assert.deepEqual(processRule.process_name, ["node.exe"]);
  assert.equal(processRule.outbound, "direct");
  assert.equal(rules.some((rule) => rule.network === "udp" && rule.action === "reject"), true);
  assert.equal(rules.find((rule) => rule.ip_is_private).outbound, "direct");
  assert.equal(rules.some((rule) => "ip_cidr" in rule), false);
  assert.equal(rules.some((rule) => "port" in rule), false);
});

test("buildConfig keeps upstreams, SSH and local networks outside the tunnel", () => {
  const config = transparent.buildConfig({ directCidrs: ["185.9.25.56/32"], directPorts: [22] });
  const rules = config.route.rules;
  const cidr = rules.find((rule) => "ip_cidr" in rule);
  const port = rules.find((rule) => "port" in rule);
  assert.deepEqual(cidr.ip_cidr, ["185.9.25.56/32"]);
  assert.equal(cidr.outbound, "direct");
  assert.deepEqual(port.port, [22]);
  assert.equal(port.outbound, "direct");
});

test("writeConfig persists the JSON under the data directory", () => {
  const file = transparent.writeConfig(transparent.buildConfig({ port: 12345 }));
  assert.equal(file, path.join(dir, "sing-box.json"));
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.outbounds[0].server_port, 12345);
});

test("an absent vendor directory reports the engine as not installed", () => {
  assert.equal(transparent.isInstalled(), false);
  assert.equal(transparent.singboxExe(), path.join(dir, "vendor", transparent.SINGBOX_DIR, "sing-box.exe"));
});

test("status exposes the fields the UI renders", async () => {
  const status = await transparent.status();
  for (const key of ["installed", "elevated", "running", "pid", "interface", "address", "version", "error", "logTail"]) {
    assert.ok(key in status, `missing ${key}`);
  }
  assert.equal(status.running, false);
  assert.equal(status.pid, null);
});
