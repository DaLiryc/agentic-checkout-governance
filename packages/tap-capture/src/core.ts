/**
 * @chargeguard/tap-capture — shared detection + forward logic.
 *
 * Detects TAP (Trusted Agent Protocol, RFC 9421-signed) requests, collects
 * a privacy-safe evidence record, and POSTs it to the ChargeGuard ingestion
 * API. Forwarding is fire-and-forget: it never throws and never blocks the
 * merchant's request path.
 */

import { classifyAgentUA } from './classify.js'

// ── Config & request types ───────────────────────────────────────────────

export interface CaptureConfig {
  /** Per-merchant ingestion key (from the ChargeGuard dashboard). */
  ingestionKey: string
  /** Ingestion endpoint. Defaults to the ChargeGuard production API. */
  endpoint?: string
  /** Fraction of eligible requests to forward, 0..1. Default 1. */
  sampleRate?: number
  /** When true, failed forwards log a console.warn. Default false. */
  debug?: boolean
}

export interface CapturedRequest {
  /** Raw `Signature-Agent` header value, when present. */
  signatureAgent?: string | null
  /** Raw `Signature-Input` header value, when present. */
  signatureInput?: string | null
  /** Raw `Signature` header value, when present. */
  signature?: string | null
  /** Request authority (host, optionally :port). */
  authority: string
  /** Request path (no query string). */
  path: string
  /** Lower-cased safe headers only — see SAFE_HEADERS. */
  rawHeaders: Record<string, string>
  /** Raw User-Agent string. */
  ua?: string | null
  /** Consented identifier from the `cg_email`/`cgEmail` query param. */
  userEmail?: string | null
  /** Consented Payment Account Reference from the `cg_par` query param. */
  userPar?: string | null
  /** Checkout session id, when present in the query string. */
  checkoutSessionId?: string | null
  /** Salted SHA-256 of the client IP. Raw IPs are never stored or sent. */
  ipHash?: string | null
}

export const DEFAULT_ENDPOINT = 'https://api.trychargeguard.com/api/agentic/evidence'

// ── Safe-header allowlist ────────────────────────────────────────────────

/**
 * The ONLY headers ever forwarded. Cookies, authorization, set-cookie and
 * everything else are dropped unconditionally.
 */
const SAFE_HEADERS = ['content-type', 'accept', 'accept-language', 'user-agent'] as const

/** Minimal structural type satisfied by the fetch `Headers` class. */
export interface HeaderBag {
  get(name: string): string | null
}

/** Adapt a plain (Node-style, lower-cased) header record into a HeaderBag. */
export function headerBagFrom(
  headers: Record<string, string | string[] | undefined>,
): HeaderBag {
  return {
    get(name: string): string | null {
      const value = headers[name.toLowerCase()]
      if (value === undefined) return null
      return Array.isArray(value) ? value.join(', ') : value
    },
  }
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

// ── Detection ────────────────────────────────────────────────────────────

function isHeaderPresent(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.trim().length > 0
}

/** True when the request carries any TAP signature header. */
export function hasTapHeaders(
  req: Pick<CapturedRequest, 'signatureAgent' | 'signatureInput' | 'signature'>,
): boolean {
  return (
    isHeaderPresent(req.signatureAgent) ||
    isHeaderPresent(req.signatureInput) ||
    isHeaderPresent(req.signature)
  )
}

/** True when the User-Agent looks like an agent/bot rather than a human. */
export function looksLikeAgentUa(ua: string | undefined | null): boolean {
  return classifyAgentUA(ua) !== 'human'
}

// ── Hashing ──────────────────────────────────────────────────────────────

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Salted SHA-256 of a client IP (hex). The raw IP is never retained.
 * Salt is per-deployment (config.ingestionKey prefix) — not a single
 * hard-coded value — so a global rainbow table over IPv4 cannot be
 * reused across merchants. Callers should pass the salt they derived
 * once per process; the default keeps backward compatibility.
 */
export async function hashIp(ip: string, salt = 'cg-salt-v1'): Promise<string> {
  return sha256Hex(ip + salt)
}

/** Derive a per-deployment IP hash salt from the ingestion key. */
export function deriveIpSalt(ingestionKey: string): string {
  return 'cg-ip-' + ingestionKey.slice(-16)
}

// ── Consented query identifiers ──────────────────────────────────────────

export interface ConsentedIds {
  userEmail: string | null
  userPar: string | null
  checkoutSessionId: string | null
}

/**
 * Pull consented identifiers from the query string:
 * `cg_email` (or `cgEmail`) → userEmail, `cg_par` (or `cgPar`) → userPar,
 * `checkout_session_id` (or `session_id`) → checkoutSessionId.
 * Absent params are null; values pass through verbatim.
 */
export function parseConsentParams(searchParams: URLSearchParams): ConsentedIds {
  return {
    userEmail: searchParams.get('cg_email') ?? searchParams.get('cgEmail'),
    userPar: searchParams.get('cg_par') ?? searchParams.get('cgPar'),
    checkoutSessionId:
      searchParams.get('checkout_session_id') ?? searchParams.get('session_id'),
  }
}

// ── Per-process nonce dedupe ─────────────────────────────────────────────

/** sha256 hashes of seen signatureInput nonces. FIFO-capped. */
const seenNonces = new Set<string>()
const MAX_NONCE_CACHE = 5000

function extractNonce(signatureInput: string | null | undefined): string | null {
  if (typeof signatureInput !== 'string') return null
  const match = signatureInput.match(/nonce="([^"]+)"/)
  return match !== null ? match[1] : null
}

/** Returns true when the nonce is fresh (and records it); false on replay. */
function markNonceSeen(nonceHash: string): boolean {
  if (seenNonces.has(nonceHash)) return false
  // Set preserves insertion order → deleting the first entry is FIFO eviction.
  if (seenNonces.size >= MAX_NONCE_CACHE) {
    const oldest = seenNonces.values().next().value
    if (oldest !== undefined) seenNonces.delete(oldest)
  }
  seenNonces.add(nonceHash)
  return true
}

/** Test hook: clear the per-process nonce cache. */
export function resetNonceCacheForTests(): void {
  seenNonces.clear()
}

// ── Forwarding ───────────────────────────────────────────────────────────

/**
 * POST one evidence record to the ChargeGuard ingestion API.
 *
 * - Fire-and-forget: resolves when the POST settles (or is skipped) and
 *   NEVER throws — failures are swallowed (optionally debug-logged).
 * - `Authorization: Bearer <ingestionKey>`, 3s abort timeout.
 * - Deduplicates per-process on the signatureInput nonce (sha256, FIFO cap
 *   of 5000) and honors `sampleRate` before anything is sent.
 * - rawHeaders are re-projected onto the safe allowlist as a final guard.
 */
export async function forwardEvidence(
  config: CaptureConfig,
  req: CapturedRequest,
): Promise<void> {
  try {
    // Nonce dedupe runs BEFORE the sampling decision: a sampled-out request
    // still marks its nonce so a later retry of the same signed request is
    // never forwarded twice.
    const nonce = extractNonce(req.signatureInput)
    if (nonce !== null) {
      const nonceHash = await sha256Hex(nonce)
      if (!markNonceSeen(nonceHash)) {
        if (config.debug) console.warn('[tap-capture] duplicate nonce, skipping forward')
        return
      }
    }

    const sampleRate = config.sampleRate ?? 1
    if (Math.random() >= sampleRate) return

    const payload = {
      signatureAgent: req.signatureAgent ?? null,
      signatureInput: req.signatureInput ?? null,
      signature: req.signature ?? null,
      authority: req.authority,
      path: req.path,
      rawHeaders: pickSafeHeaders(headerBagFrom(req.rawHeaders)),
      ua: req.ua ?? null,
      userEmail: req.userEmail ?? null,
      userPar: req.userPar ?? null,
      checkoutSessionId: req.checkoutSessionId ?? null,
      ipHash: req.ipHash ?? null,
    }

    await fetch(config.endpoint ?? DEFAULT_ENDPOINT, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${config.ingestionKey}`,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3_000),
    })
  } catch (err) {
    if (config.debug) {
      console.warn('[tap-capture] evidence forward failed:', err)
    }
  }
}
