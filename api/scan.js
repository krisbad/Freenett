const tls = require('tls');
const crypto = require('crypto');

const MAX_PROBES = 300;   // per request
const CONCURRENCY = 50;
const TIMEOUT_MS = 4000;

function probe(ip, port, sni, path) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    let sock;
    const finish = (r) => {
      if (done) return;
      done = true;
      try { sock && sock.destroy(); } catch (e) {}
      resolve({ ip, sni, ms: Date.now() - t0, ...r });
    };
    try {
      sock = tls.connect({
        host: ip,
        port,
        servername: sni,
        rejectUnauthorized: false,
        timeout: TIMEOUT_MS,
      });
    } catch (e) {
      return finish({ ok: false, detail: e.code || e.message });
    }
    sock.once('secureConnect', () => {
      if (!path) return finish({ ok: true, detail: 'TLS ' + sock.getProtocol() });
      const key = crypto.randomBytes(16).toString('base64');
      sock.write(
        `GET ${path} HTTP/1.1\r\nHost: ${sni}\r\nUpgrade: websocket\r\n` +
        `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\n` +
        `Sec-WebSocket-Version: 13\r\n\r\n`
      );
      let buf = '';
      sock.on('data', (d) => {
        buf += d.toString('latin1');
        if (buf.includes('\r\n')) {
          const line = buf.split('\r\n')[0];
          finish({ ok: /^HTTP\/1\.[01] 101/.test(line), detail: line });
        }
      });
    });
    sock.once('timeout', () => finish({ ok: false, detail: 'timeout' }));
    sock.once('error', (e) => finish({ ok: false, detail: e.code || e.message }));
    sock.once('close', () => finish({ ok: false, detail: 'closed' }));
  });
}

async function pool(tasks, limit) {
  const results = [];
  let i = 0;
  async function worker() {
    while (i < tasks.length) {
      const idx = i++;
      results[idx] = await tasks[idx]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'POST only' });
    return;
  }
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
    const ips = Array.isArray(body.ips) ? body.ips.map(String) : [];
    const hosts = Array.isArray(body.hosts) ? body.hosts.map(String) : [];
    const port = parseInt(body.port, 10) || 443;
    const path = body.path ? String(body.path) : '';

    if (!ips.length || !hosts.length) {
      res.status(400).json({ error: 'ips and hosts are required' });
      return;
    }
    if (ips.length * hosts.length > MAX_PROBES) {
      res.status(400).json({ error: `Too many probes (max ${MAX_PROBES} per request)` });
      return;
    }
    if (!/^[\w.\-:]+$/.test(path.replace(/\//g, '')) && path) {
      res.status(400).json({ error: 'Bad path' });
      return;
    }

    const tasks = [];
    for (const ip of ips) {
      for (const h of hosts) tasks.push(() => probe(ip, port, h, path));
    }
    const results = await pool(tasks, CONCURRENCY);
    res.status(200).json({ results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
