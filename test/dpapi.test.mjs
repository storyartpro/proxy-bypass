// Windows DPAPI round-trip. Skipped on non-Windows platforms.
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.PROXY_APP_DATA = process.env.PROXY_APP_DATA || "test/.tmp-data";

const { dpapiAvailable, protectSecret, unprotectSecret } = await import("../app/core/dpapi.mjs");

test("protects and unprotects a secret with the current Windows account", { skip: !dpapiAvailable() }, async () => {
  const secret = "socks5-password-й-€-42";
  const ciphertext = await protectSecret(secret);
  assert.ok(ciphertext, "ciphertext must be produced");
  assert.ok(!ciphertext.includes(secret), "ciphertext must not contain the plaintext");
  const plain = await unprotectSecret(ciphertext);
  assert.equal(plain, secret);
});

test("returns null for empty input", { skip: !dpapiAvailable() }, async () => {
  assert.equal(await protectSecret(""), null);
  assert.equal(await unprotectSecret(null), null);
});
