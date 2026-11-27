# SNI Scanner

Web page plus a small serverless API that tests which hostnames complete a TLS handshake (and optionally a WebSocket upgrade) against a target host.

## Files
- `index.html` — the page (form, progress bar, searchable/sortable results, copy and CSV export)
- `api/scan.js` — Vercel serverless function that does the actual TLS tests

## Deploy
1. Create a GitHub repo and upload both files, keeping the `api/` folder.
2. Go to vercel.com, choose Add New > Project, and import the repo.
3. Leave all settings as default and deploy. Your page will be live at `https://<project>.vercel.app`.

## Limits
- 40 hostnames per request (the page sends them in batches automatically).
- Private and internal IP addresses are blocked as targets.
- Vercel's free plan limits each function call to about 10 seconds, which is why scans are batched.

## Why not GitHub Pages alone?
GitHub Pages only serves static files. Browsers can't open raw TLS connections with a custom SNI, so the scan has to run on a server. GitHub holds the code; Vercel hosts and runs it.
