# ChargeGuard TAP Capture Worker

Capture **AI-agent purchase evidence** (Visa TAP / RFC 9421-signed requests) on any site behind Cloudflare and forward it to [ChargeGuard](https://trychargeguard.com), so agent-authorized transactions become winnable evidence when a chargeback lands. The worker is a transparent pass-through: the origin response is always returned untouched, no header is ever added or removed, and the capture runs after the response via `waitUntil`. If the ingestion key is missing or the ingestion API is down, customer traffic flows exactly as if the worker were not installed.

Detection matches the [`@chargeguard/tap-capture`](../../packages/tap-capture) npm package: requests carrying TAP signature headers (`Signature-Agent`, `Signature-Input`, `Signature`) are captured, and so are requests whose User-Agent looks like a shopping agent (OpenAI Operator, ChatGPT, Claude, Perplexity, Amazon Nova, generic bots). Everything else passes through with near-zero overhead. No npm install on your origin, no code changes, one worker.

## Install

### Option A: Cloudflare dashboard paste (no tooling on your side)

1. Build the bundle once (any machine with Node 18+):
   ```bash
   cd workers/tap-capture-worker
   npm install
   npm run build
   ```
2. Copy the full contents of `dist/index.js`.
3. Cloudflare dashboard: **Workers & Pages → Create → Worker**, name it (for example `tap-capture`), **Deploy**, then **Edit code**, paste the bundle, **Deploy** again.
4. Worker **Settings → Variables and Secrets → Add secret**: name `CG_INGESTION_KEY`, value = your ingestion key from the ChargeGuard dashboard (**Settings → Agentic evidence**).
5. Worker **Settings → Domains & Routes → Add route**: your checkout paths, for example `shop.example.com/checkout*`.

### Option B: wrangler deploy

```bash
cd workers/tap-capture-worker
npm install
npx wrangler secret put CG_INGESTION_KEY   # paste your ChargeGuard ingestion key
npx wrangler deploy
```

Then add the route either in the dashboard (as in Option A, step 5) or via a `route` entry in `wrangler.toml`.

## Environment

| Name | Kind | Required | Default | Purpose |
|---|---|---|---|---|
| `CG_INGESTION_KEY` | secret | yes, for capture | none | Per-merchant ingestion key from the ChargeGuard dashboard. Without it the worker is a pure pass-through. |
| `CG_ENDPOINT` | var | no | `https://api.trychargeguard.com/api/agentic/evidence` | Ingestion endpoint override. |
| `CG_KV_NAMESPACE` | KV binding | no | none | Best-effort nonce dedupe across worker isolates. Purely optional; the in-memory dedupe works without it. |

## What gets forwarded

Only this, nothing else:

- The three TAP headers, when present: `Signature-Agent`, `Signature-Input`, `Signature`
- The request `authority` (host) and `path` (no query string)
- Exactly four headers, lower-cased: `content-type`, `accept`, `accept-language`, `user-agent`
- The raw User-Agent string
- Consented query params, when present: `cg_email` (or `cgEmail`), `cg_par` (or `cgPar`), `checkout_session_id` (or `session_id`)
- A salted SHA-256 hash of the client IP (from `cf-connecting-ip`); the raw IP is never sent or stored

Cookies, `authorization`, `set-cookie`, request bodies and every other header are dropped unconditionally. Signature nonces are hashed (SHA-256) and deduplicated in-memory (FIFO cache of 5000, plus the optional KV binding) so agent retries don't double-send. Forwards time out after 3 seconds and failures are silently dropped; they never affect the customer request.

Get your ingestion key from the ChargeGuard dashboard under **Settings → Agentic evidence**.
