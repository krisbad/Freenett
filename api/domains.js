// Vercel serverless function: GET /api/domains?q=example.co.ke
// Returns hostnames seen in public certificate transparency logs (via crt.sh).
const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i;
const MAX = 400;

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  const q = String(req.query.q || "").trim().toLowerCase().replace(/^\*\./, "");
  if (!HOST_RE.test(q)) return res.status(400).json({ error: "enter a valid domain, e.g. example.co.ke" });

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8500);
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(q)}&output=json`, {
      signal: ctrl.signal,
      headers: { "User-Agent": "sni-scanner" },
    });
    if (!r.ok) return res.status(502).json({ error: "crt.sh returned " + r.status });
    const rows = await r.json();
    const set = new Set();
    for (const row of rows) {
      for (const n of String(row.name_value || "").split("\n")) {
        const h = n.trim().toLowerCase().replace(/^\*\./, "");
        if (HOST_RE.test(h) && h.endsWith(q)) set.add(h);
      }
    }
    res.status(200).json({ domains: [...set].slice(0, MAX) });
  } catch (e) {
    const msg = e.name === "AbortError"
      ? "crt.sh timed out. Try a more specific domain, e.g. safaricom.co.ke instead of co.ke"
      : String(e.message || e);
    res.status(504).json({ error: msg });
  } finally {
    clearTimeout(timer);
  }
};
