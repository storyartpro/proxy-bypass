import test from "node:test";
import assert from "node:assert/strict";
import {
  MANAGED_VARS,
  enabledPlan,
  isOurs,
  mergeNoProxy,
  parseNoProxy,
  proxyUrlFor,
  restorePlan,
} from "../app/core/env-proxy.mjs";

test("proxy URL points at the local routing listener", () => {
  assert.equal(proxyUrlFor(38080), "http://127.0.0.1:38080");
  assert.equal(proxyUrlFor(9000), "http://127.0.0.1:9000");
});

test("NO_PROXY parsing keeps entries and drops empties", () => {
  assert.deepEqual(parseNoProxy("a.com, b.com  c.com"), ["a.com", "b.com", "c.com"]);
  assert.deepEqual(parseNoProxy(""), []);
});

test("loopback is always added to NO_PROXY, user entries survive", () => {
  const merged = parseNoProxy(mergeNoProxy("corp.example, 127.0.0.1"));
  assert.ok(merged.includes("corp.example"));
  assert.equal(merged.filter((entry) => entry === "127.0.0.1").length, 1);
  for (const entry of ["localhost", "127.0.0.1", "::1", "0.0.0.0"]) assert.ok(merged.includes(entry));
});

test("ours is true only when all three proxy variables match", () => {
  const url = proxyUrlFor(38080);
  assert.equal(isOurs({ HTTP_PROXY: url, HTTPS_PROXY: url, ALL_PROXY: url }, 38080), true);
  assert.equal(isOurs({ HTTP_PROXY: url, HTTPS_PROXY: url }, 38080), false);
  assert.equal(isOurs({ HTTP_PROXY: "http://127.0.0.1:38080", HTTPS_PROXY: url, ALL_PROXY: "socks5://127.0.0.1:1080" }, 38080), false);
});

test("enabled plan sets the three variables and preserves NO_PROXY", () => {
  const plan = enabledPlan({ NO_PROXY: "intranet.local" }, 38080);
  assert.deepEqual(MANAGED_VARS.sort(), Object.keys(plan).sort());
  assert.equal(plan.HTTP_PROXY, "http://127.0.0.1:38080");
  assert.equal(plan.HTTPS_PROXY, plan.HTTP_PROXY);
  assert.equal(plan.ALL_PROXY, plan.HTTP_PROXY);
  assert.match(plan.NO_PROXY, /intranet\.local/);
  assert.match(plan.NO_PROXY, /localhost/);
});

test("restore plan turns missing variables into null", () => {
  assert.deepEqual(restorePlan({ HTTP_PROXY: "http://10.0.0.1:3128", NO_PROXY: "x" }), {
    HTTP_PROXY: "http://10.0.0.1:3128",
    HTTPS_PROXY: null,
    ALL_PROXY: null,
    NO_PROXY: "x",
  });
  assert.equal(restorePlan(null), null);
});
