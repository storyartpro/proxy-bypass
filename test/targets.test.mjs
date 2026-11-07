// Target validation and CIDR matching for the blocked list.
import { test } from "node:test";
import assert from "node:assert/strict";

import { ipInCidr, normalizeTarget, splitTargets } from "../app/core/targets.mjs";

test("accepts domains and normalises case and trailing dot", () => {
  assert.deepEqual(normalizeTarget("Example.COM."), { kind: "domain", value: "example.com" });
  assert.deepEqual(normalizeTarget("xn--80aswg.xn--p1ai"), { kind: "domain", value: "xn--80aswg.xn--p1ai" });
});

test("accepts IPv4 addresses", () => {
  assert.deepEqual(normalizeTarget("203.0.113.7"), { kind: "ip", value: "203.0.113.7" });
});

test("accepts IPv4 subnets and normalises the network address", () => {
  assert.deepEqual(normalizeTarget("203.0.113.55/24"), { kind: "cidr", value: "203.0.113.55/24" });
  assert.deepEqual(normalizeTarget("10.0.0.0/8"), { kind: "cidr", value: "10.0.0.0/8" });
});

test("rejects garbage", () => {
  for (const value of ["", "http://a.com", "1.2.3.4/33", "999.1.1.1", "*.example.com", "a b.com"]) {
    assert.throws(() => normalizeTarget(value), undefined, value);
  }
});

test("matches addresses inside a subnet and ignores the rest", () => {
  assert.equal(ipInCidr("203.0.113.5", "203.0.113.0/24"), true);
  assert.equal(ipInCidr("203.0.113.255", "203.0.113.0/24"), true);
  assert.equal(ipInCidr("203.0.114.1", "203.0.113.0/24"), false);
  assert.equal(ipInCidr("8.8.8.8", "0.0.0.0/0"), true);
  assert.equal(ipInCidr("not-an-ip", "10.0.0.0/8"), false);
});

test("splits a mixed list into domains and subnets", () => {
  const { domains, subnets } = splitTargets(["api.openai.com", "203.0.113.7", "198.51.100.0/24", "bad entry"]);
  assert.deepEqual(domains, ["api.openai.com"]);
  assert.deepEqual(subnets, ["203.0.113.7/32", "198.51.100.0/24"]);
});
