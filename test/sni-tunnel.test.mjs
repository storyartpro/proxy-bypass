import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-sni-"));
process.env.PROXY_APP_DATA = dataDir;

const { LocalRouter, createLocalProxy, parseClientHelloSni } = await import("../app/core/local-proxy.mjs");

function clientHello(host) {
  const name = Buffer.from(host, "latin1");
  const entry = Buffer.alloc(3 + name.length);
  entry[0] = 0; // host_name
  entry.writeUInt16BE(name.length, 1);
  name.copy(entry, 3);
  const list = Buffer.alloc(2 + entry.length);
  list.writeUInt16BE(entry.length, 0);
  entry.copy(list, 2);
  const extension = Buffer.alloc(4 + list.length);
  extension.writeUInt16BE(0, 0); // server_name
  extension.writeUInt16BE(list.length, 2);
  list.copy(extension, 4);
  const extensions = Buffer.alloc(2 + extension.length);
  extensions.writeUInt16BE(extension.length, 0);
  extension.copy(extensions, 2);
  const body = Buffer.alloc(41 + extensions.length);
  body.writeUInt16BE(0x0303, 0); // legacy version
  body[34] = 0; // empty session id
  body.writeUInt16BE(2, 35); // one cipher suite
  body.writeUInt16BE(0x1301, 37);
  body[39] = 1; // one compression method
  body[40] = 0; // null compression
  extensions.copy(body, 41);
  const handshake = Buffer.alloc(4 + body.length);
  handshake[0] = 1; // ClientHello
  handshake.writeUIntBE(body.length, 1, 3);
  body.copy(handshake, 4);
  const record = Buffer.alloc(5 + handshake.length);
  record[0] = 0x16; // handshake
  record[1] = 0x03;
  record[2] = 0x01;
  record.writeUInt16BE(handshake.length, 3);
  handshake.copy(record, 5);
  return record;
}

test("parseClientHelloSni reads the server name", () => {
  assert.equal(parseClientHelloSni(clientHello("api.telegram.org")), "api.telegram.org");
});

test("parseClientHelloSni rejects non-TLS and truncated data", () => {
  assert.equal(parseClientHelloSni(Buffer.from("GET / HTTP/1.1\r\n\r\n")), null);
  assert.equal(parseClientHelloSni(clientHello("example.com").subarray(0, 20)), null);
  assert.equal(parseClientHelloSni(Buffer.alloc(0)), null);
});

test("CONNECT to a raw IP tunnels under the SNI domain", async () => {
  const seen = [];
  const socks = net.createServer((socket) => {
    socket.once("data", () => {
      socket.write(Buffer.from([0x05, 0x00]));
      socket.once("data", (request) => {
        assert.equal(request[0], 0x05);
        assert.equal(request[1], 0x01);
        assert.equal(request[3], 0x03, "upstream must receive a domain, not an IP");
        const length = request[4];
        const host = request.subarray(5, 5 + length).toString("latin1");
        seen.push(host);
        socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      });
    });
  });
  await new Promise((resolve) => socks.listen(0, "127.0.0.1", resolve));
  const socksPort = socks.address().port;

  const router = new LocalRouter({ upstream: { host: "127.0.0.1", port: socksPort, auth: false }, timeoutMs: 500 });
  router.defaultRoute = "proxy";
  router.verdicts.set("api.telegram.org", { verdict: "blocked", at: new Date().toISOString() });

  const proxy = createLocalProxy({ router, port: 0, host: "127.0.0.1", log: () => {} });
  await proxy.start();
  const listenPort = proxy.server.address().port;

  const client = net.connect({ host: "127.0.0.1", port: listenPort });
  let reply = "";
  await new Promise((resolve, reject) => {
    client.once("error", reject);
    client.once("data", (chunk) => {
      reply += chunk.toString("latin1");
      resolve();
    });
    client.write("CONNECT 149.154.166.110:443 HTTP/1.1\r\nHost: 149.154.166.110:443\r\n\r\n");
    client.write(clientHello("api.telegram.org"));
  });
  assert.match(reply, /200 Connection Established/);
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.deepEqual(seen, ["api.telegram.org"]);

  client.destroy();
  await proxy.stop();
  await new Promise((resolve) => socks.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});
