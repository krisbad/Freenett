// Vercel serverless function: POST /api/scan
// Body: { target, port, domains: [..], ws }
const tls = require("tls");
const dns = require("dns").promises;
const net = require("net");

const MAX_DOMAINS = 40;
const TIMEOUT_MS = 4000;
const CONCURRENCY = 20;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i;

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 10 || a === 127 || a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === "::1" || l === "::" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80");
  }
  return true;
}

function testSni(ip, port, sni, ws) {
  return new Promise((resolve) => {
    const start = Date.now();
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch (_) {}
      resolve({ sni, ...r });
    };
    const socket = tls.connect(
      { host: ip, port, servername: sni, rejectUnauthorized: false, timeout: TIMEOUT_MS },
      () => {
        const ms = Date.now() - start;
        if (!ws) return finish({ ok: true, ms, status: "TLS OK" });
        socket.write(
          `GET ${ws} HTTP/1.1\r\nHost: ${sni}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
          `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`
        );
      }
    );
    socket.on("data", (d) => {
      const line = d.toString().split("\r\n")[0];
      finish({ ok: true, ms: Date.now() - start, status: line || "TLS OK" });
    });
    socket.on("timeout", () => finish({ ok: false, status: "timeout" }));
    socket.on("error", (e) => finish({ ok: false, status: e.code || "error" }));
  });
}

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });

  try {
    const { target, port = 443, domains = [], ws = "" } = req.body || {};
    if (typeof target !== "string" || !target) return res.status(400).json({ error: "target required" });
    const p = Number(port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) return res.status(400).json({ error: "bad port" });
    if (ws && !/^\/[\x21-\x7e]*$/.test(ws)) return res.status(400).json({ error: "bad ws path" });

    const list = [...new Set(domains.map((d) => String(d).trim().toLowerCase()))]
      .filter((d) => HOST_RE.test(d))
      .slice(0, MAX_DOMAINS);
    if (!list.length) return res.status(400).json({ error: "no valid domains" });

    // Resolve once, and refuse private/internal addresses (SSRF protection)
    const ip = net.isIP(target) ? target : (await dns.lookup(target)).address;
    if (isPrivate(ip)) return res.status(400).json({ error: "target resolves to a private address" });

    const results = [];
    let i = 0;
    const worker = async () => {
      while (i < list.length) {
        const d = list[i++];
        results.push(await testSni(ip, p, d, ws));
      }
    };
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, list.length) }, worker));

    res.status(200).json({ ip, results });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
};
