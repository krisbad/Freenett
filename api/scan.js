const tls = require('tls');
const net = require('net');
const crypto = require('crypto');

const MAX_PROBES = 300;   // per request
const CONCURRENCY = 50;
const TIMEOUT_MS = 4000;

function probe(ip, port, sni, path, hostHeader, codes) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    let sock;
    const hard = setTimeout(() => finish({ ok: false, detail: 'timeout' }), TIMEOUT_MS + 1500);
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(hard);
      try { sock && sock.destroy(); } catch (e) {}
      resolve({ ip, sni, ms: Date.now() - t0, ...r });
    };

    const onConnect = () => {
      const ws = !!path;
      const host = hostHeader || sni;
      let req = `GET ${path || '/'} HTTP/1.1\r\nHost: ${host}\r\n` +
                `User-Agent: Mozilla/5.0\r\nAccept: */*\r\n`;
      if (ws) {
        req += `Upgrade: websocket\r\nConnection: Upgrade\r\n` +
               `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}\r\n` +
               `Sec-WebSocket-Version: 13\r\n\r\n`;
      } else {
        req += `Connection: close\r\n\r\n`;
      }
      sock.write(req);
      let buf = '';
      sock.on('data', (d) => {
        buf += d.toString('latin1');
        if (!buf.includes('\r\n')) return;
        const line = buf.split('\r\n')[0];
        const m = line.match(/^HTTP\/1\.[01] (\d{3})/);
        if (!m) return finish({ ok: false, detail: 'not HTTP' });
        const status = parseInt(m[1], 10);
        finish({
          ok: codes.includes(status) || (ws && status === 101),
          status,
          detail: line.slice(0, 60),
        });
      });
    };

    try {
      if (port === 80) {
        sock = net.connect({ host: ip, port, timeout: TIMEOUT_MS });
        sock.once('connect', onConnect);
      } else {
        sock = tls.connect({
          host: ip, port, servername: sni,
          rejectUnauthorized: false, timeout: TIMEOUT_MS,
        });
        sock.once('secureConnect', onConnect);
      }
    } catch (e) {
      return finish({ ok: false, detail: e.code || e.message });
    }
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
    const hostHeader = body.host ? String(body.host).trim() : '';
    let codes = Array.isArray(body.codes)
      ? body.codes.map((n) => parseInt(n, 10)).filter((n) => n >= 100 && n <= 599)
      : [];
    if (!codes.length) codes = [200, 301];

    if (!ips.length || !hosts.length) {
      res.status(400).json({ error: 'ips and hosts are required' });
      return;
    }
    if (ips.length * hosts.length > MAX_PROBES) {
      res.status(400).json({ error: `Too many probes (max ${MAX_PROBES} per request)` });
      return;
    }
    if (hostHeader && !/^[\w.\-:]+$/.test(hostHeader)) {
      res.status(400).json({ error: 'Bad host header' });
      return;
    }
    if (path && !/^\/[\w\-./%?=&]*$/.test(path)) {
      res.status(400).json({ error: 'Bad path' });
      return;
    }

    const tasks = [];
    for (const ip of ips) {
      for (const h of hosts) tasks.push(() => probe(ip, port, h, path, hostHeader, codes));
    }
    const results = await pool(tasks, CONCURRENCY);
    res.status(200).json({ results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
