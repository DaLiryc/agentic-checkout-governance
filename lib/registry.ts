/**
 * Agent registry key resolution.
 *
 * Derives a JWKS-style registry endpoint from the Signature-Agent URL
 * (`<origin>/.well-known/agent-keys.json`, falling back to
 * `<origin>/.well-known/jwks.json`), caches documents for 5 minutes
 * in-memory, and imports matching keys (JWK Ed25519 / JWK RSA / PEM SPKI)
 * as WebCrypto CryptoKeys for verification.
 */

interface RegistryKeyEntry {
  kid?: string
  kty?: string
  crv?: string
  x?: string
  n?: string
  e?: string
  alg?: string
  pem?: string
  publicKeyPem?: string
}

interface RegistryDocument {
  keys?: RegistryKeyEntry[]
}

const CACHE_TTL_MS = 5 * 60 * 1000

const docCache = new Map<string, { doc: RegistryDocument; expires: number }>()

/** Test hook: clear the in-memory registry cache. */
export function resetRegistryCacheForTests(): void {
  docCache.clear()
}

function pemToDer(pem: string): Uint8Array<ArrayBuffer> | null {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '')
  if (body.length === 0) return null
  try {
    const bin = atob(body)
    const bytes = new Uint8Array(new ArrayBuffer(bin.length))
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return bytes
  } catch {
    return null
  }
}

async function importRegistryKey(entry: RegistryKeyEntry): Promise<CryptoKey | null> {
  // JWK Ed25519 (OKP)
  if (entry.kty === 'OKP' && entry.crv === 'Ed25519' && entry.x) {
    try {
      return await crypto.subtle.importKey(
        'jwk',
        { kty: 'OKP', crv: 'Ed25519', x: entry.x },
        'Ed25519',
        true,
        ['verify'],
      )
    } catch {
      return null
    }
  }

  // JWK RSA → RSASSA-PSS SHA-256 per TAP
  if (entry.kty === 'RSA' && entry.n && entry.e) {
    try {
      return await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', n: entry.n, e: entry.e },
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['verify'],
      )
    } catch {
      return null
    }
  }

  // PEM / SPKI (e.g. Visa sample registries publish PEM public keys)
  const pem = entry.pem ?? entry.publicKeyPem
  if (pem) {
    const der = pemToDer(pem)
    if (!der) return null
    try {
      return await crypto.subtle.importKey(
        'spki',
        der,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['verify'],
      )
    } catch {
      try {
        return await crypto.subtle.importKey('spki', der, 'Ed25519', true, ['verify'])
      } catch {
        return null
      }
    }
  }

  return null
}

async function fetchDocument(url: string): Promise<RegistryDocument | null> {
  const cached = docCache.get(url)
  if (cached && cached.expires > Date.now()) return cached.doc

  let doc: RegistryDocument
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/json' },
      // Next.js fetch caching off — we manage our own TTL.
      cache: 'no-store',
    })
    if (!res.ok) return null
    doc = (await res.json()) as RegistryDocument
  } catch {
    return null
  }
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.keys)) return null

  docCache.set(url, { doc, expires: Date.now() + CACHE_TTL_MS })
  return doc
}

/**
 * Resolve the verification key for `keyid` from the agent's registry.
 * Returns null when the agent URL is invalid, the registry is
 * unreachable/malformed, or the keyid is unknown.
 */
export async function fetchKeyFromRegistry(
  agentUrl: string,
  keyid: string,
): Promise<CryptoKey | null> {
  let origin: string
  try {
    origin = new URL(agentUrl).origin
  } catch {
    return null
  }

  const candidates = [
    `${origin}/.well-known/agent-keys.json`,
    `${origin}/.well-known/jwks.json`,
  ]

  for (const url of candidates) {
    const doc = await fetchDocument(url)
    if (!doc || !Array.isArray(doc.keys)) continue
    const entry = doc.keys.find((k) => k && k.kid === keyid)
    if (!entry) continue
    const key = await importRegistryKey(entry)
    if (key) return key
  }

  return null
}
