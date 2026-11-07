// Demo SOCKS5 servers used only to render documentation screenshots.
// They accept the handshake and reply "success" without forwarding anything.
import net from "node:net";

const ports = process.argv.slice(2).map(Number).filter(Boolean);

function serve(port) {
  net.createServer((socket) => {
    socket.on("error", () => {});
    let buffer = Buffer.alloc(0);
    let stage = "greeting";
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const pump = () => {
        if (stage === "greeting" && buffer.length >= 2 && buffer.length >= 2 + buffer[1]) {
          const methods = buffer.subarray(2, 2 + buffer[1]);
          buffer = buffer.subarray(2 + buffer[1]);
          socket.write(Buffer.from([5, methods.includes(0) ? 0 : 2]));
          stage = "request";
          pump();
          return;
        }
        if (stage === "request" && buffer.length >= 4) {
          const atyp = buffer[3];
          let need = 4;
          if (atyp === 1) need += 4;
          else if (atyp === 4) need += 16;
          else if (buffer.length >= 5) need += 1 + buffer[4];
          need += 2;
          if (buffer.length >= need) {
            buffer = buffer.subarray(need);
            socket.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
            stage = "done";
          }
        }
      };
      pump();
    });
  }).listen(port, "127.0.0.1");
}

for (const port of ports) serve(port);
console.log(JSON.stringify({ listening: ports }));
