/**
 * ChargeGuard TAP capture — Cloudflare Worker variant.
 *
 * Captures Visa TAP (RFC 9421-signed) and AI-agent request evidence at the
 * edge and forwards it to the ChargeGuard ingestion API. Runs on the
 * merchant's own domain as a transparent pass-through: the origin response
 * is always returned untouched and the capture never blocks or fails a
 * customer request.
 *
 * Logic mirrors packages/tap-capture/src/core.ts (header allowlist, agent
 * UA list, consented query params, nonce dedupe). Zero runtime deps.
 */

// ── Worker environment (structural types, no @cloudflare/workers-types) ──

/** Minimal KV shape satisfied by a standard `KVNamespace` binding. */
export interface KVLike {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

export interface Env {
  /** Per-merchant ingestion key (ChargeGuard dashboard). Missing → pure pass-through. */
  CG_INGESTION_KEY?: string
  /** Ingestion endpoint override. Defaults to the ChargeGuard production API. */
  CG_ENDPOINT?: string
  /** Optional KV binding for best-effort cross-isolate nonce dedupe. */
  CG_KV_NAMESPACE?: KVLike
}

/** Minimal execution-context shape satisfied by the Workers runtime. */
export interface ExecutionContextLike {
  waitUntil(promise: Promise<unknown>): void
}

export const DEFAULT_ENDPOINT = 'https://api.trychargeguard.com/api/agentic/evidence'

const FORWARD_TIMEOUT_MS = 3_000
const NONCE_KV_TTL_SECONDS = 86_400

// ── Safe-header allowlist (parity with core.ts) ──────────────────────────

/**
 * The ONLY headers ever forwarded. Cookies, authorization, set-cookie and
 * everything else are dropped unconditionally.
 */
const SAFE_HEADERS = ['content-type', 'accept', 'accept-language', 'user-agent'] as const

/** Minimal structural type satisfied by the fetch `Headers` class. */
export interface HeaderBag {
  get(name: string): string | null
}

/** Project any header source down to the safe allowlist, lower-cased. */
export function pickSafeHeaders(bag: HeaderBag): Record<string, string> {
  const out: Record<string, string> = {}
  for (const name of SAFE_HEADERS) {
    const value = bag.get(name)
    if (value !== null) out[name] = value
  }
  return out
}

// ── Detection (parity with core.ts / classify.ts) ────────────────────────

function isHeaderPresent(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.trim().length > 0
}

/** Optional TAP header values as read from the request. */
export interface TapHeaderProbe {
  signatureAgent?: string | null
  signatureInput?: string | null
  signature?: string | null
}

/** True when the request carries any TAP signature header. */
export function hasTapHeaders(req: TapHeaderProbe): boolean {
  return (
    isHeaderPresent(req.signatureAgent) ||
    isHeaderPresent(req.signatureInput) ||
    isHeaderPresent(req.signature)
  )
}

export type AgentKind =
  | 'openai-operator'
  | 'chatgpt'
  | 'claude'
  | 'perplexity'
  | 'amazon-nova'
  | 'unknown-bot'
  | 'human'

/**
 * Classify a User-Agent string. Copied from the npm package's classify list:
 * known agents matched case-insensitively on stable substrings in priority
 * order; null/undefined/empty UAs classify as `human`.
 */
export function classifyAgentUA(ua: string | null | undefined): AgentKind {
  if (typeof ua !== 'string' || ua.length === 0) return 'human'
  const s = ua.toLowerCase()

  if (s.includes('openai operator')) return 'openai-operator'
  if (s.includes('chatgpt')) return 'chatgpt'
  if (s.includes('claude')) return 'claude'
  if (s.includes('perplexity')) return 'perplexity'
  if (/amazon[ -]?nova|nova[ -]?act/.test(s)) return 'amazon-nova'
  if (/bot|spider|headless/.test(s)) return 'unknown-bot'

  return 'human'
}

/** True when the User-Agent looks like an agent/bot rather than a human. */
export function looksLikeAgentUa(ua: string | null | undefined): boolean {
  return classifyAgentUA(ua) !== 'human'
}

// ── Hashing (parity with core.ts) ────────────────────────────────────────

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Salted SHA-256 of a client IP (hex). The raw IP is never retained. */
export async function hashIp(ip: string): Promise<string> {
  return sha256Hex(ip + 'cg-salt-v1')
}

// ── Consented query identifiers (parity with core.ts) ───────────────────

export interface ConsentedIds {
  userEmail: string | null
  userPar: string | null
  checkoutSessionId: string | null
}

/**
 * Pull consented identifiers from the query string:
 * `cg_email` (or `cgEmail`) → userEmail, `cg_par` (or `cgPar`) → userPar,
 * `checkout_session_id` (or `session_id`) → checkoutSessionId.
 */
export function parseConsentParams(searchParams: URLSearchParams): ConsentedIds {
  return {
    userEmail: searchParams.get('cg_email') ?? searchParams.get('cgEmail'),
    userPar: searchParams.get('cg_par') ?? searchParams.get('cgPar'),
    checkoutSessionId:
      searchParams.get('checkout_session_id') ?? searchParams.get('session_id'),
  }
}

// ── Nonce dedupe: module-scope Map, FIFO cap 5000, optional KV ──────────

/** sha256(nonce) → first-seen timestamp. FIFO-capped. */
const seenNonces = new Map<string, number>()
const MAX_NONCE_CACHE = 5000

function extractNonce(signatureInput: string | null | undefined): string | null {
  if (typeof signatureInput !== 'string') return null
  const match = signatureInput.match(/nonce="([^"]+)"/)
  return match !== null ? match[1] : null
}

/** Returns true when the nonce is fresh (and records it); false on replay. */
export function markNonceSeen(nonceHash: string): boolean {
  if (seenNonces.has(nonceHash)) return false
  // Map preserves insertion order → deleting the first key is FIFO eviction.
  if (seenNonces.size >= MAX_NONCE_CACHE) {
    const oldest = seenNonces.keys().next().value
    if (oldest !== undefined) seenNonces.delete(oldest)
  }
  seenNonces.set(nonceHash, Date.now())
  return true
}

/** Test hooks: inspect/reset the per-isolate nonce cache. */
export function nonceCacheSize(): number {
  return seenNonces.size
}

export function resetNonceCacheForTests(): void {
  seenNonces.clear()
}

/**
 * Claim a nonce: false when already seen (in-memory or KV), true (and
 * recorded) when fresh. KV is consulted/persisted best-effort only —
 * a KV failure never blocks or duplicates a forward.
 */
async function claimNonce(nonceHash: string, kv: KVLike | undefined): Promise<boolean> {
  if (seenNonces.has(nonceHash)) return false
  if (kv !== undefined) {
    try {
      if ((await kv.get(`cg:nonce:${nonceHash}`)) !== null) return false
    } catch {
      // Best-effort only: treat KV errors as "unknown".
    }
  }
  if (!markNonceSeen(nonceHash)) return false
  if (kv !== undefined) {
    try {
      await kv.put(`cg:nonce:${nonceHash}`, String(Date.now()), {
        expirationTtl: NONCE_KV_TTL_SECONDS,
      })
    } catch {
      // Best-effort only.
    }
  }
  return true
}

// ── Evidence payload (same shape as the npm package) ────────────────────

export interface EvidencePayload {
  signatureAgent: string | null
  signatureInput: string | null
  signature: string | null
  authority: string
  path: string
  rawHeaders: Record<string, string>
  ua: string | null
  userEmail: string | null
  userPar: string | null
  checkoutSessionId: string | null
  ipHash: string | null
}

/** Client IP as seen at the Cloudflare edge, else the first proxy hop. */
function clientIp(headers: HeaderBag): string | null {
  const cf = headers.get('cf-connecting-ip')
  if (cf !== null && cf.length > 0) return cf
  const first = headers.get('x-forwarded-for')?.split(',')[0]?.trim()
  return first !== undefined && first.length > 0 ? first : null
}

/**
 * Detect + dedupe + build payload + POST to the ingestion API.
 * Fire-and-forget: NEVER throws — every failure is swallowed so the
 * customer request is never affected.
 */
async function captureAndForward(request: Request, env: Env): Promise<void> {
  try {
    const key = env.CG_INGESTION_KEY
    if (!isHeaderPresent(key)) return

    const url = new URL(request.url)
    const signatureAgent = request.headers.get('signature-agent')
    const signatureInput = request.headers.get('signature-input')
    const signature = request.headers.get('signature')
    const ua = request.headers.get('user-agent')

    const nonce = extractNonce(signatureInput)
    if (nonce !== null) {
      const nonceHash = await sha256Hex(nonce)
      if (!(await claimNonce(nonceHash, env.CG_KV_NAMESPACE))) return
    }

    const consent = parseConsentParams(url.searchParams)
    const ip = clientIp(request.headers)
    const payload: EvidencePayload = {
      signatureAgent: signatureAgent ?? null,
      signatureInput: signatureInput ?? null,
      signature: signature ?? null,
      authority: url.host,
      path: url.pathname,
      rawHeaders: pickSafeHeaders(request.headers),
      ua: ua ?? null,
      userEmail: consent.userEmail,
      userPar: consent.userPar,
      checkoutSessionId: consent.checkoutSessionId,
      ipHash: ip !== null ? await hashIp(ip) : null,
    }

    await fetch(env.CG_ENDPOINT ?? DEFAULT_ENDPOINT, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${key}`,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(FORWARD_TIMEOUT_MS),
    })
  } catch {
    // Fire-and-forget: capture failures never surface to the customer.
  }
}

// ── Pass-through origin fetch ────────────────────────────────────────────

/**
 * Proxy the request to the origin, response untouched. On origin failure
 * return a plain-text 502 with no third-party branding (this worker runs
 * on the merchant's domain).
 */
async function passthrough(request: Request): Promise<Response> {
  try {
    return await fetch(request)
  } catch {
    return new Response('Bad gateway', {
      status: 502,
      headers: { 'content-type': 'text/plain' },
    })
  }
}

// ── Worker entry ─────────────────────────────────────────────────────────

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContextLike): Promise<Response> {
    // No ingestion key → capture disabled, pure pass-through.
    if (!isHeaderPresent(env.CG_INGESTION_KEY)) return passthrough(request)

    const signatureAgent = request.headers.get('signature-agent')
    const signatureInput = request.headers.get('signature-input')
    const signature = request.headers.get('signature')
    const ua = request.headers.get('user-agent')

    // TAP headers → capture; else agent UA → capture as agent_ua_only;
    // else pass-through immediately.
    if (
      hasTapHeaders({ signatureAgent, signatureInput, signature }) ||
      looksLikeAgentUa(ua)
    ) {
      // Workers may cancel in-flight fetches once the response returns;
      // waitUntil guarantees the capture promise runs to completion.
      ctx.waitUntil(captureAndForward(request, env).catch(() => undefined))
    }
    return passthrough(request)
  },
}
