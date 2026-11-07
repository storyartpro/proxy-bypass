// Protocol tests for the SOCKS5 client. No network: a fake SOCKS5 server runs
// in-process and records what the client asked for.
import net from "node:net";
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.PROXY_APP_DATA = process.env.PROXY_APP_DATA || "test/.tmp-data";

const { socksConnect } = await import("../app/core/local-proxy.mjs");

/** Incremental reader that never discards bytes received ahead of the read size. */
function makeReader(socket) {
  let buffer = Buffer.alloc(0);
  let waiter = null;
  const pump = () => {
    if (!waiter || buffer.length < waiter.size) return;
    const current = waiter;
    waiter = null;
    const out = buffer.subarray(0, current.size);
    buffer = buffer.subarray(current.size);
    current.resolve(out);
  };
  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    pump();
  });
  socket.on("error", () => {});
  return {
    read(size) {
      return new Promise((resolve) => {
        waiter = { size, resolve };
        pump();
      });
    },
  };
}

function startFakeSocks({ requireAuth = false, replyCode = 0 } = {}) {
  const records = {};
  const server = net.createServer(async (socket) => {
    const reader = makeReader(socket);
    try {
      const greeting = await reader.read(2);
      records.methods = [...(await reader.read(greeting[1]))];
      if (requireAuth) {
        if (!records.methods.includes(2)) {
          socket.end(Buffer.from([5, 0xff]));
          return;
        }
        socket.write(Buffer.from([5, 2]));
        const authHead = await reader.read(2);
        records.username = (await reader.read(authHead[1])).toString("utf8");
        const passLength = (await reader.read(1))[0];
        records.password = (await reader.read(passLength)).toString("utf8");
        socket.write(Buffer.from([1, 0]));
      } else {
        socket.write(Buffer.from([5, 0]));
      }
      const head = await reader.read(4);
      records.cmd = head[1];
      records.atyp = head[3];
      if (head[3] === 1) {
        records.host = [...(await reader.read(4))].join(".");
      } else if (head[3] === 4) {
        records.host = "ipv6";
        await reader.read(16);
      } else {
        const length = (await reader.read(1))[0];
        records.host = (await reader.read(length)).toString("utf8");
      }
      records.port = (await reader.read(2)).readUInt16BE(0);
      socket.write(Buffer.from([5, replyCode, 0, 1, 0, 0, 0, 0, 0, 0]));
      if (replyCode !== 0) socket.end();
    } catch {
      /* client disconnected early */
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: server.address().port,
        records,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

test("connects to a domain destination without auth", async () => {
  const fake = await startFakeSocks();
  try {
    const socket = await socksConnect({ host: "127.0.0.1", port: fake.port, auth: false }, "example.com", 443, 3000);
    socket.destroy();
    assert.equal(fake.records.cmd, 1);
    assert.equal(fake.records.atyp, 3);
    assert.equal(fake.records.host, "example.com");
    assert.equal(fake.records.port, 443);
  } finally {
    await fake.close();
  }
});

test("sends IPv4 destinations as ATYP 1", async () => {
  const fake = await startFakeSocks();
  try {
    const socket = await socksConnect({ host: "127.0.0.1", port: fake.port, auth: false }, "1.2.3.4", 80, 3000);
    socket.destroy();
    assert.equal(fake.records.atyp, 1);
    assert.equal(fake.records.host, "1.2.3.4");
    assert.equal(fake.records.port, 80);
  } finally {
    await fake.close();
  }
});

test("performs username/password auth when credentials are present", async () => {
  const fake = await startFakeSocks({ requireAuth: true });
  try {
    const socket = await socksConnect(
      { host: "127.0.0.1", port: fake.port, auth: true, username: "alice", password: "top-secret" },
      "api.example.org",
      8443,
      3000,
    );
    socket.destroy();
    assert.equal(fake.records.username, "alice");
    assert.equal(fake.records.password, "top-secret");
    assert.equal(fake.records.host, "api.example.org");
    assert.equal(fake.records.port, 8443);
  } finally {
    await fake.close();
  }
});

test("rejects when the upstream refuses the destination", async () => {
  const fake = await startFakeSocks({ replyCode: 2 });
  try {
    await assert.rejects(
      () => socksConnect({ host: "127.0.0.1", port: fake.port, auth: false }, "blocked.example.com", 443, 3000),
      /connect failed \(2\)/,
    );
  } finally {
    await fake.close();
  }
});
