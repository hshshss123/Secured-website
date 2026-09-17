const http = require("http");
const crypto = require("crypto");
const pty = require("node-pty");
const { WebSocketServer } = require("ws");

const HOST = process.env.TERMINAL_HOST || "127.0.0.1";
const PORT = Number(process.env.TERMINAL_PORT || 7681);
const SECRET = process.env.TERMINAL_SECRET;
const IMAGE = process.env.TERMINAL_IMAGE || "securedlab-terminal:latest";
const NETWORK = process.env.LAB_NETWORK || "securedlab_labnet";
const ORIGINS = new Set(["http://127.0.0.1:5000", "http://localhost:5000"]);

if (!SECRET) throw new Error("TERMINAL_SECRET is required");

function validToken(token) {
  try {
    const [ts, sig] = String(token || "").split(".");
    if (!/^\d+$/.test(ts) || !sig) return false;
    const age = Date.now() - Number(ts);
    if (age < -30000 || age > 300000) return false;
    const expected = crypto.createHmac("sha256", SECRET).update(ts).digest("hex");
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

const server = http.createServer((_req, res) => {
  res.writeHead(200, {"content-type": "text/plain; charset=utf-8"});
  res.end("Secured Lab terminal service");
});

const wss = new WebSocketServer({server, maxPayload: 65536});

wss.on("connection", (ws, req) => {
  const origin = req.headers.origin;
  const url = new URL(req.url, "http://127.0.0.1");
  if (!ORIGINS.has(origin) || !validToken(url.searchParams.get("token"))) {
    ws.close(1008, "Unauthorized");
    return;
  }

  const name = "sl-" + crypto.randomBytes(8).toString("hex");
  const args = [
    "run", "--rm", "-it", "--name", name,
    "--network", NETWORK,
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--memory", "512m",
    "--cpus", "1",
    "--pids-limit", "128",
    "--read-only",
    "--tmpfs", "/tmp:rw,nosuid,size=64m",
    "--tmpfs", "/home/lab:rw,nosuid,size=128m",
    "--security-opt", "seccomp=default",
    IMAGE, "/bin/bash", "--login"
  ];

  let child;
  try {
    child = pty.spawn("docker", args, {
      name: "xterm-256color",
      cols: 100,
      rows: 30,
      env: {
        PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        TERM: "xterm-256color",
        HOME: "/home/lab",
        LANG: "C.UTF-8"
      }
    });
  } catch (err) {
    ws.send(JSON.stringify({type:"error", message:"Unable to start isolated lab container."}));
    ws.close();
    return;
  }

  ws.send(JSON.stringify({
    type:"status",
    message:"Connected to an isolated lab container. Target: http://target:8080"
  }));

  child.onData(data => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({type:"output", data}));
  });

  child.onExit(({exitCode}) => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({type:"status", message:"Lab session ended (" + exitCode + ")."}));
      ws.close();
    }
  });

  ws.on("message", raw => {
    if (raw.length > 65536) return;
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === "input" && typeof msg.data === "string") {
        child.write(msg.data.slice(0, 8192));
      } else if (msg.type === "resize") {
        const cols = Math.max(40, Math.min(200, Number(msg.cols) || 100));
        const rows = Math.max(10, Math.min(80, Number(msg.rows) || 30));
        child.resize(cols, rows);
      }
    } catch {}
  });

  ws.on("close", () => {
    try { child.kill(); } catch {}
  });
});

server.listen(PORT, HOST, () => {
  console.log("Terminal service listening on ws://" + HOST + ":" + PORT);
});
