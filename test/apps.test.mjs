// Pure helpers for the application-tracking module (no Windows calls).
import { test } from "node:test";
import assert from "node:assert/strict";

import { mergeBlocked, mergeChannels, normaliseProfileInput, pidsForProfile } from "../app/core/apps.mjs";

test("mergeBlocked unions manual entries with enabled profiles only", () => {
  const manual = ["api.openai.com", "203.0.113.7"];
  const profiles = [
    { id: "a", enabled: true, discovered: ["104.253.1.146", "telegram.org", "api.openai.com"] },
    { id: "b", enabled: false, discovered: ["disabled.example.com"] },
  ];
  const merged = mergeBlocked(manual, profiles);
  assert.deepEqual(merged, ["104.253.1.146", "203.0.113.7", "api.openai.com", "telegram.org"]);
});

test("mergeChannels deduplicates, ignores private addresses and reports additions", () => {
  const profile = { discovered: ["104.253.1.146"] };
  const added = mergeChannels(profile, {
    ips: ["104.253.1.146", "192.168.1.5", "1.1.1.1", "not-an-ip"],
    hosts: ["cdn.example.com", "localhost", "104.253.1.146"],
  });
  assert.deepEqual(added, ["1.1.1.1", "cdn.example.com"]);
  assert.deepEqual(profile.discovered, ["104.253.1.146", "1.1.1.1", "cdn.example.com"]);
});

test("normaliseProfileInput defaults to proxy mode and keeps a stable id", () => {
  const profile = normaliseProfileInput({ kind: "service", name: "DNSCache", label: "DNS Client" }, "fixed-id");
  assert.equal(profile.id, "fixed-id");
  assert.equal(profile.kind, "service");
  assert.equal(profile.name, "DNSCache");
  assert.equal(profile.enabled, true);
  assert.equal(profile.mode, "proxy");
  assert.equal(normaliseProfileInput({ name: "x", mode: "direct" }).mode, "direct");
  assert.equal(normaliseProfileInput({ name: "x", mode: "garbage" }).mode, "proxy");
  assert.throws(() => normaliseProfileInput({ kind: "process", name: "" }));
});

test("a direct profile removes its channels from the bypass list", () => {
  const manual = ["api.openai.com", "104.253.1.146", "chatgpt.com"];
  const profiles = [
    { id: "p", enabled: true, mode: "direct", discovered: ["api.openai.com", "104.253.1.146"] },
    { id: "q", enabled: true, mode: "proxy", discovered: ["cdn.example.com"] },
  ];
  assert.deepEqual(mergeBlocked(manual, profiles), ["cdn.example.com", "chatgpt.com"]);
  // a disabled direct profile must not remove anything
  profiles[0].enabled = false;
  assert.deepEqual(mergeBlocked(manual, profiles), ["104.253.1.146", "api.openai.com", "cdn.example.com", "chatgpt.com"]);
});

test("pidsForProfile matches processes by executable name", () => {
  const snap = {
    processes: [
      { ProcessId: 10, Name: "Telegram.exe" },
      { ProcessId: 11, Name: "telegram.exe" },
      { ProcessId: 12, Name: "chrome.exe" },
    ],
    services: [],
  };
  const result = pidsForProfile({ kind: "process", name: "telegram" }, snap);
  assert.deepEqual(result.pids.sort(), [10, 11]);
  assert.equal(result.running, true);
});

test("pidsForProfile resolves a service through its process", () => {
  const snap = {
    processes: [{ ProcessId: 42, Name: "svchost.exe" }],
    services: [{ Name: "Dnscache", DisplayName: "DNS Client", ProcessId: 42, PathName: '"C:\\Windows\\System32\\svchost.exe" -k NetworkService' }],
  };
  const result = pidsForProfile({ kind: "service", name: "Dnscache" }, snap);
  assert.ok(result.pids.includes(42));
  assert.equal(result.running, true);
});
