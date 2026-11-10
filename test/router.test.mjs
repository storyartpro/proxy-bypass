import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// LocalRouter persists its state under dataDir(), which honours this variable.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-router-test-"));
process.env.PROXY_APP_DATA = dir;

const { LocalRouter } = await import("../app/core/local-proxy.mjs");

function makeRouter() {
  return new LocalRouter({ upstream: { host: "127.0.0.1", port: 9, auth: false }, timeoutMs: 60 });
}

test("default route is direct and survives a restart", () => {
  const router = makeRouter();
  assert.equal(router.defaultRoute, "direct");
  router.setDefaultRoute("proxy");
  assert.equal(router.defaultRoute, "proxy");
  assert.equal(makeRouter().defaultRoute, "proxy");
});

test("invalid mode falls back to direct", () => {
  const router = makeRouter();
  const result = router.setDefaultRoute("nonsense");
  assert.equal(result.mode, "direct");
});

test("loopback and the always-direct whitelist never use the proxy", async () => {
  const router = makeRouter();
  router.setDefaultRoute("proxy");
  assert.equal(await router.routeFor("localhost"), "direct");
  assert.equal(await router.routeFor("127.0.0.1"), "direct");
  assert.equal(await router.routeFor("deepseek.com"), "direct");
});

test("unknown hosts start on the proxy in proxy mode", async () => {
  const router = makeRouter();
  router.setDefaultRoute("proxy");
  assert.equal(await router.routeFor("unclassified.invalid"), "blocked");
});

test("unknown hosts stay direct in direct mode", async () => {
  const router = makeRouter();
  router.setDefaultRoute("direct");
  assert.equal(await router.routeFor("unclassified2.invalid"), "direct");
});

test("forced hosts follow the proxy and fall back when it is unavailable", async () => {
  const router = makeRouter();
  router.force("forced.example", true);
  router.upstreamAvailable = true;
  assert.equal(await router.routeFor("sub.forced.example"), "blocked");
  router.upstreamAvailable = false;
  assert.equal(await router.routeFor("sub.forced.example"), "direct");
});

test.after(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});
