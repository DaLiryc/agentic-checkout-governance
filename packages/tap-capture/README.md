# @chargeguard/tap-capture

Capture **AI-agent purchase evidence** (Visa TAP / RFC 9421-signed requests) on
your own stack and forward it to [ChargeGuard](https://trychargeguard.com) — so
agent-authorized transactions become winnable evidence when a chargeback lands.

- **Fire-and-forget** — never blocks or mutates your requests
- **Zero runtime dependencies** — `fetch` only
- **Privacy-safe** — forwards a safe header allowlist only (no cookies, no
  auth headers), never stores raw IPs (salted SHA-256 hash)

## Install

```bash
npm install @chargeguard/tap-capture
```

## Config

```ts
const config = {
  ingestionKey: process.env.CHARGEGUARD_INGESTION_KEY!, // from the ChargeGuard dashboard
  endpoint: 'https://api.trychargeguard.com/api/agentic/evidence', // optional
  sampleRate: 1, // optional, 0..1 — fraction of eligible requests forwarded
  debug: false,  // optional — console.warn on failed forwards
}
```

Requests are captured when they carry TAP signature headers
(`Signature-Agent` / `Signature-Input` / `Signature`) **or** the User-Agent
looks like an agent (OpenAI Operator, ChatGPT, Claude, Perplexity, Amazon Nova,
generic bots). Everything else is skipped with zero work.

### Consented identifiers (optional)

If your checkout URLs carry consented identifiers, they are passed through
verbatim and used to match evidence to disputes:

| Query param | Also accepts | Field |
|---|---|---|
| `cg_email` | `cgEmail` | `userEmail` |
| `cg_par` | `cgPar` | `userPar` (Payment Account Reference) |
| `checkout_session_id` | `session_id` | `checkoutSessionId` |

## Next.js (middleware)

```ts
// middleware.ts
import { NextRequest, NextResponse } from 'next/server'
import { maybeCapture } from '@chargeguard/tap-capture/next'

export async function middleware(req: NextRequest) {
  await maybeCapture(req, { ingestionKey: process.env.CHARGEGUARD_INGESTION_KEY! })
  return NextResponse.next()
}

export const config = { matcher: ['/checkout/:path*'] }
```

No existing middleware? `captureNext(config)` gives you the whole wrapper:

```ts
import { captureNext } from '@chargeguard/tap-capture/next'
export const middleware = captureNext({ ingestionKey: process.env.CHARGEGUARD_INGESTION_KEY! })
```

## Express

```ts
import express from 'express'
import { captureExpress } from '@chargeguard/tap-capture/express'

const app = express()
app.use(captureExpress({ ingestionKey: process.env.CHARGEGUARD_INGESTION_KEY! }))

app.get('/checkout', (_req, res) => res.send('ok'))
app.listen(3000)
```

## Fastify

```ts
import Fastify from 'fastify'
import { captureFastify } from '@chargeguard/tap-capture/fastify'

const app = Fastify({ logger: true })
await app.register(captureFastify({ ingestionKey: process.env.CHARGEGUARD_INGESTION_KEY! }))

app.get('/checkout', async () => 'ok')
await app.listen({ port: 3000 })
```

## Behavior notes

- **Never blocks**: evidence is forwarded via a background `fetch` (3s abort
  timeout) that is never awaited in your response path, and never throws.
- **Dedupe**: signature nonces are hashed (SHA-256) and deduplicated
  in-process (FIFO cache of 5000), so retries don't double-send.
- **Safe headers only**: `content-type`, `accept`, `accept-language`,
  `user-agent`. Cookies, `authorization`, `set-cookie` and everything else
  are dropped unconditionally.
- **IP handling**: when your framework exposes a client IP (Express/Fastify
  `req.ip`, Next `x-forwarded-for`), only `sha256(ip + salt)` is sent.
- **UA classifier**: `classifyAgentUA(ua)` is exported from the main entry —
  `'openai-operator' | 'chatgpt' | 'claude' | 'perplexity' | 'amazon-nova' |
  'unknown-bot' | 'human'` — for your own telemetry.
