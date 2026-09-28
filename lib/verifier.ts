/**
 * RFC 9421 / Visa TAP signature verifier.
 *
 * Ported from Visa's trusted-agent-protocol sample verifier
 * (docs/tap-reference/visa_sample_verifier.py, MIT © 2025 Visa) to
 * TypeScript on WebCrypto — no runtime deps.
 *
 * Header formats handled (per TAP sample):
 *   Signature-Input: sig1=("@authority" "@path"); nonce="…"; created=N; expires=N; keyid="…"; tag="…"
 *   Signature:       sig1=:base64:
 */

export interface ParsedSignatureInput {
  signatureParams: string[] // e.g. ["@authority","@path"]
  nonce: string
  created: number
  expires: number
  keyid: string
  tag: string
}

/** Request context used to rebuild the signed base. */
export interface SignatureBaseContext {
  authority: string
  path: string
  /** Lower-cased raw request headers, for non-@ signature params. */
  rawHeaders?: Record<string, string>
}

export type TapVerifyResult =
  | {
      ok: true
      keyid: string
      nonce: string
      created: number
      expires: number
      keyFingerprint: string
    }
  | { ok: false; reason: string }

// ── Parsing ─────────────────────────────────────────────────────────────

/**
 * Parse a Signature-Input header value.
 * Accepts RFC 9421 style individually-quoted params:
 *   sig1=("@authority" "@path"); nonce="…"; created=N; expires=N; keyid="…"; tag="…"
 * as well as the Visa sample's single-quoted-list variant:
 *   sig1=("@authority @path"); nonce="…"; …
 */
export function parseSignatureInput(si: string): ParsedSignatureInput | null {
  if (typeof si !== 'string') return null
  const m = si
    .trim()
    .match(
      /^sig1=\(([^)]*)\);\s*nonce="([^"]+)";\s*created=(\d+);\s*expires=(\d+);\s*keyid="([^"]+)";\s*tag="([^"]+)"$/,
    )
  if (!m) return null

  const paramList = m[1].trim()
  if (paramList.length === 0) return null

  const signatureParams: string[] = []
  if (/^"[^"]*"$/.test(paramList)) {
    // Visa sample variant: one quoted string of space-separated params.
    const inner = paramList.slice(1, -1).trim()
    if (inner.length === 0) return null
    for (const p of inner.split(/\s+/)) {
      if (p.length === 0) return null
      signatureParams.push(p)
    }
  } else {
    // RFC 9421 variant: individually quoted params.
    for (const token of paramList.split(/\s+/)) {
      if (!/^"[^"]+"$/.test(token)) return null
      signatureParams.push(token.slice(1, -1))
    }
  }
  if (signatureParams.length === 0) return null

  const created = Number(m[3])
  const expires = Number(m[4])
  if (!Number.isSafeInteger(created) || !Number.isSafeInteger(expires)) return null

  return {
    signatureParams,
    nonce: m[2],
    created,
    expires,
    keyid: m[5],
    tag: m[6],
  }
}

/** Parse a Signature-Agent header value → agent URL, or null if empty. */
export function parseSignatureAgent(sa: string): string | null {
  if (typeof sa !== 'string') return null
  const agentUrl = sa.trim().replace(/^"+|"+$/g, '').trim()
  return agentUrl.length > 0 ? agentUrl : null
}

/** Parse a Signature header value (`sig1=:base64:`) → base64 value, or null. */
export function parseSignatureValue(sig: string): string | null {
  if (typeof sig !== 'string') return null
  const m = sig.trim().match(/^sig1=:([^:]+):$/)
  return m ? m[1] : null
}

// ── Signature base ──────────────────────────────────────────────────────

/**
 * Build the signature base string, mirroring build_signature_string in the
 * Visa sample: one `"param": value` line per listed param (values quoted,
 * @authority/@path from ctx, any other param looked up lower-case in
 * ctx.rawHeaders, empty string when absent), then nonce/created/expires
 * lines (nonce quoted, numbers bare), all joined with "\n".
 */
export function buildSignatureBase(
  parsed: ParsedSignatureInput,
  ctx: SignatureBaseContext,
): string {
  const lines: string[] = []
  for (const param of parsed.signatureParams) {
    const lc = param.toLowerCase()
    let value: string
    if (lc === '@authority') value = ctx.authority
    else if (lc === '@path') value = ctx.path
    else value = ctx.rawHeaders?.[lc] ?? ''
    lines.push(`"${param}": ${JSON.stringify(value)}`)
  }
  lines.push(`"nonce": ${JSON.stringify(parsed.nonce)}`)
  lines.push(`"created": ${parsed.created}`)
  lines.push(`"expires": ${parsed.expires}`)
  return lines.join('\n')
}

// ── Verification ────────────────────────────────────────────────────────

function toBytes(b64: string): Uint8Array<ArrayBuffer> | null {
  try {
    const bin = atob(b64)
    const bytes = new Uint8Array(new ArrayBuffer(bin.length))
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return bytes
  } catch {
    return null
  }
}

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/** hex(sha256(exported raw public key bytes or DER/PEM-decoded SPKI)). */
async function keyFingerprint(key: CryptoKey): Promise<string> {
  // Literal format per branch keeps exportKey's return ArrayBuffer (not | JsonWebKey).
  const exported: ArrayBuffer =
    key.algorithm.name === 'Ed25519'
      ? await crypto.subtle.exportKey('raw', key)
      : await crypto.subtle.exportKey('spki', key)
  const digest = await crypto.subtle.digest('SHA-256', exported)
  return toHex(digest)
}

function rsaSaltLength(key: CryptoKey): number | null {
  const alg = key.algorithm as RsaHashedKeyAlgorithm
  return typeof alg.modulusLength === 'number' ? alg.modulusLength / 8 - 32 : null
}

export async function verifyTapSignature(args: {
  signatureAgent: string
  signatureInput: string
  signature: string
  authority: string
  path: string
  fetchKey: (keyid: string) => Promise<CryptoKey | null>
  now?: number
  rawHeaders?: Record<string, string>
}): Promise<TapVerifyResult> {
  const parsedInput = parseSignatureInput(args.signatureInput)
  if (!parsedInput) return { ok: false, reason: 'invalid_signature_input' }

  const signatureValue = parseSignatureValue(args.signature)
  if (!signatureValue) return { ok: false, reason: 'invalid_signature_format' }

  // Timestamp check: created ≤ now ≤ expires (seconds; injectable for tests).
  const now = args.now ?? Math.floor(Date.now() / 1000)
  if (now < parsedInput.created) {
    return { ok: false, reason: 'signature_created_in_future' }
  }
  if (now > parsedInput.expires) {
    return { ok: false, reason: 'signature_expired' }
  }

  const key = await args.fetchKey(parsedInput.keyid)
  if (!key) return { ok: false, reason: 'key_not_found' }

  const base = buildSignatureBase(parsedInput, {
    authority: args.authority,
    path: args.path,
    rawHeaders: args.rawHeaders,
  })
  const data = new TextEncoder().encode(base)

  const sigBytes = toBytes(signatureValue)
  if (!sigBytes) return { ok: false, reason: 'invalid_signature_encoding' }

  let valid: boolean
  if (key.algorithm.name === 'Ed25519') {
    valid = await crypto.subtle.verify('Ed25519', key, sigBytes, data)
  } else if (key.algorithm.name === 'RSA-PSS') {
    // TAP sample verifies RSA-PSS-SHA256 with PSS MAX_LENGTH salt
    // (= modulusBytes - hLen - 2). WebCrypto has no MAX_LENGTH mode, so we
    // try modulusBytes - 32 (largest spec-compliant-looking intent) and fall
    // back to 32 (digest length, the common default) if the attempt is
    // rejected. Documented per build spec.
    const primary = rsaSaltLength(key)
    try {
      valid =
        primary !== null &&
        (await crypto.subtle.verify(
          { name: 'RSA-PSS', saltLength: primary },
          key,
          sigBytes,
          data,
        ))
    } catch {
      valid = await crypto.subtle.verify(
        { name: 'RSA-PSS', saltLength: 32 },
        key,
        sigBytes,
        data,
      )
    }
  } else {
    return { ok: false, reason: `unsupported_key_algorithm:${key.algorithm.name}` }
  }

  if (!valid) return { ok: false, reason: 'invalid_signature' }

  return {
    ok: true,
    keyid: parsedInput.keyid,
    nonce: parsedInput.nonce,
    created: parsedInput.created,
    expires: parsedInput.expires,
    keyFingerprint: await keyFingerprint(key),
  }
}
