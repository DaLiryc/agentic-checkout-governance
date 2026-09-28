import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import worker, {
  type Env,
  type KVLike,
  DEFAULT_ENDPOINT,
  classifyAgentUA,
  hasTapHeaders,
  hashIp,
  markNonceSeen,
  nonceCacheSize,
  parseConsentParams,
  pickSafeHeaders,
  resetNonceCacheForTests,
} from './index'

// ── Helpers ─────────────────────────────────────────────────────────────

const ENDPOINT = 'https://ingest.test/evidence'
const ORIGIN_URL = 'https://shop.example.com/checkout'

/** signatureInput WITHOUT a nonce → never touches the nonce dedupe cache. */
const NO_NONCE_INPUT =
  'sig1=("@authority" "@path"); created=1000; expires=2000; keyid="k1"; tag="visa-tap"'

const TAP_HEADERS: Record<string, string> = {
  'signature-agent': 'https://agent.example',
  'signature-input': NO_NONCE_INPUT,
  signature: 'sig1=:abc123:',
}

function makeEnv(overrides: Partial<Env> = {}): Env {
  return { CG_INGESTION_KEY: 'key-1', CG_ENDPOINT: ENDPOINT, ...overrides }
}

function makeRequest(
  headers: Record<string, string> = {},
  url: string = ORIGIN_URL,
): Request {
  return new Request(url, { method: 'GET', headers })
}

function makeCtx(): { ctx: { waitUntil: (p: Promise<unknown>) => void }; waits: Promise<unknown>[] } {
  const waits: Promise<unknown>[] = []
  return { ctx: { waitUntil: (p: Promise<unknown>): void => void waits.push(p) }, waits }
}

type FetchCall = [input: RequestInfo | URL, init?: RequestInit]

/** Route mocked fetch: evidence POSTs (init.method POST), everything else = origin. */
function mockFetch(opts: { originStatus?: number; evidenceFail?: boolean } = {}): ReturnType<typeof vi.fn> {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    if (init?.method === 'POST') {
      if (opts.evidenceFail) throw new Error('ingestion down')
      return new Response(null, { status: 202 })
    }
    return new Response('origin ok', { status: opts.originStatus ?? 200 })
  })
}

function evidenceCalls(calls: FetchCall[]): FetchCall[] {
  return calls.filter(([, init]) => init?.method === 'POST')
}

function originCalls(calls: FetchCall[]): FetchCall[] {
  return calls.filter(([, init]) => init?.method !== 'POST')
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = mockFetch()
  vi.stubGlobal('fetch', fetchMock)
  resetNonceCacheForTests()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── classifyAgentUA (parity with the package's classify list) ───────────

describe('classifyAgentUA', () => {
  it('classifies known agents case-insensitively', () => {
    expect(classifyAgentUA('OpenAI Operator/1.0')).toBe('openai-operator')
    expect(classifyAgentUA('ChatGPT-User/1.0')).toBe('chatgpt')
    expect(classifyAgentUA('Mozilla/5.0 ClaudeBot/1.0')).toBe('claude')
    expect(classifyAgentUA('PerplexityBot/1.0')).toBe('perplexity')
    expect(classifyAgentUA('Amazon-Nova-Act/1.0')).toBe('amazon-nova')
    expect(classifyAgentUA('AmazonNova/2.0')).toBe('amazon-nova')
    expect(classifyAgentUA('nova act 1.0')).toBe('amazon-nova')
  })

  it('classifies generic bots before falling through to human', () => {
    expect(classifyAgentUA('MyShoppingBot/1.0')).toBe('unknown-bot')
    expect(classifyAgentUA('some spider')).toBe('unknown-bot')
    expect(classifyAgentUA('HeadlessChrome/120')).toBe('unknown-bot')
  })

  it('treats browser, empty and missing UAs as human', () => {
    expect(classifyAgentUA('Mozilla/5.0 (Windows NT 10.0) Chrome/126.0')).toBe('human')
    expect(classifyAgentUA('')).toBe('human')
    expect(classifyAgentUA(null)).toBe('human')
    expect(classifyAgentUA(undefined)).toBe('human')
  })
})

// ── hasTapHeaders truth table (parity with core.ts) ─────────────────────

describe('hasTapHeaders', () => {
  it('is false when all three headers are absent/null/empty', () => {
    expect(hasTapHeaders({})).toBe(false)
    expect(hasTapHeaders({ signatureAgent: null, signatureInput: null, signature: null })).toBe(false)
    expect(hasTapHeaders({ signatureAgent: '', signatureInput: '', signature: '  ' })).toBe(false)
    expect(hasTapHeaders({ signatureAgent: undefined, signatureInput: undefined, signature: undefined })).toBe(false)
  })

  it('is true when any single header is present', () => {
    expect(hasTapHeaders({ signatureAgent: 'https://agent.example' })).toBe(true)
    expect(hasTapHeaders({ signatureInput: 'sig1=("@authority"); nonce="n"' })).toBe(true)
    expect(hasTapHeaders({ signature: 'sig1=:abc123:' })).toBe(true)
    expect(hasTapHeaders({ signatureAgent: null, signatureInput: '', signature: 'sig1=:xyz:' })).toBe(true)
  })
})

// ── pickSafeHeaders / parseConsentParams / hashIp (parity) ──────────────

describe('pickSafeHeaders', () => {
  it('keeps only the allowlist, lower-cased, and strips secrets', () => {
    const bag = {
      get: (name: string): string | null =>
        ({
          'content-type': 'application/json',
          accept: '*/*',
          'accept-language': 'en-US',
          'user-agent': 'OpenAI Operator/1.0',
          cookie: 'session=secret',
          authorization: 'Bearer merchant-secret',
        })[name.toLowerCase()] ?? null,
    }
    expect(pickSafeHeaders(bag)).toEqual({
      'content-type': 'application/json',
      accept: '*/*',
      'accept-language': 'en-US',
      'user-agent': 'OpenAI Operator/1.0',
    })
  })

  it('omits absent headers rather than sending empty strings', () => {
    expect(pickSafeHeaders({ get: () => null })).toEqual({})
  })
})

describe('parseConsentParams', () => {
  it('reads snake_case and camelCase aliases with snake_case priority', () => {
    const both = parseConsentParams(
      new URLSearchParams('cg_email=a@x.test&cgEmail=b@x.test&cg_par=P1&cgPar=P2&checkout_session_id=cs1&session_id=s2'),
    )
    expect(both).toEqual({ userEmail: 'a@x.test', userPar: 'P1', checkoutSessionId: 'cs1' })

    const camel = parseConsentParams(
      new URLSearchParams('cgEmail=b@x.test&cgPar=P2&session_id=s2'),
    )
    expect(camel).toEqual({ userEmail: 'b@x.test', userPar: 'P2', checkoutSessionId: 's2' })
  })

  it('returns nulls when no consent params are present', () => {
    expect(parseConsentParams(new URLSearchParams('utm_source=x'))).toEqual({
      userEmail: null,
      userPar: null,
      checkoutSessionId: null,
    })
  })
})

describe('hashIp', () => {
  it('produces the same salted sha256 hex digest as the npm package', async () => {
    const expected = createHash('sha256').update('203.0.113.7cg-salt-v1').digest('hex')
    await expect(hashIp('203.0.113.7')).resolves.toBe(expected)
  })
})

// ── Nonce dedupe: FIFO cap ───────────────────────────────────────────────

describe('markNonceSeen', () => {
  it('caps the cache at 5000 entries with FIFO eviction', () => {
    for (let i = 0; i < 5_001; i++) expect(markNonceSeen(`h${i}`)).toBe(true)
    expect(nonceCacheSize()).toBe(5_000)
    // h0 was evicted first; the newest entry is still present.
    expect(markNonceSeen('h0')).toBe(true)
    expect(markNonceSeen('h5000')).toBe(false)
  })
})

// ── Worker fetch handler ─────────────────────────────────────────────────

describe('worker fetch handler', () => {
  it('passes through untouched when CG_INGESTION_KEY is missing', async () => {
    const { ctx, waits } = makeCtx()
    const res = await worker.fetch(makeRequest(TAP_HEADERS), {}, ctx)

    expect(res.status).toBe(200)
    expect(waits).toHaveLength(0)
    expect(evidenceCalls(fetchMock.mock.calls as FetchCall[])).toHaveLength(0)
    expect(originCalls(fetchMock.mock.calls as FetchCall[])).toHaveLength(1)
  })

  it('passes through immediately for human traffic without TAP headers', async () => {
    const { ctx } = makeCtx()
    const req = makeRequest({ 'user-agent': 'Mozilla/5.0 (Macintosh) Chrome/126.0' })
    const res = await worker.fetch(req, makeEnv(), ctx)

    expect(res.status).toBe(200)
    await expect(res.text()).resolves.toBe('origin ok')
    expect(fetchMock).toHaveBeenCalledTimes(1) // origin only, no evidence POST
  })

  it('captures TAP-signed requests and POSTs the exact package payload', async () => {
    const { ctx, waits } = makeCtx()
    const req = makeRequest(
      {
        ...TAP_HEADERS,
        'content-type': 'application/json',
        accept: '*/*',
        'user-agent': 'OpenAI Operator/1.0',
        cookie: 'session=secret',
        authorization: 'Bearer merchant-secret',
        'cf-connecting-ip': '203.0.113.7',
      },
      'https://shop.example.com/checkout?cg_email=buyer@example.com&cg_par=PAR-123&checkout_session_id=cs_test_1',
    )
    const res = await worker.fetch(req, makeEnv(), ctx)
    await Promise.all(waits)

    expect(res.status).toBe(200)
    expect(waits).toHaveLength(1)

    const [evidence] = evidenceCalls(fetchMock.mock.calls as FetchCall[])
    expect(evidence).toBeDefined()
    const [url, init] = evidence
    expect(String(url)).toBe(ENDPOINT)
    expect(init?.method).toBe('POST')

    const headers = new Headers(init?.headers)
    expect(headers.get('authorization')).toBe('Bearer key-1')
    expect(headers.get('content-type')).toBe('application/json')

    const ipHash = createHash('sha256').update('203.0.113.7cg-salt-v1').digest('hex')
    expect(JSON.parse(String(init?.body))).toEqual({
      signatureAgent: 'https://agent.example',
      signatureInput: NO_NONCE_INPUT,
      signature: 'sig1=:abc123:',
      authority: 'shop.example.com',
      path: '/checkout',
      // Only the safe allowlist survives — cookie/authorization stripped.
      rawHeaders: {
        'content-type': 'application/json',
        accept: '*/*',
        'user-agent': 'OpenAI Operator/1.0',
      },
      ua: 'OpenAI Operator/1.0',
      userEmail: 'buyer@example.com',
      userPar: 'PAR-123',
      checkoutSessionId: 'cs_test_1',
      ipHash,
    })
  })

  it('captures agent-UA-only traffic with null signature fields', async () => {
    const { ctx, waits } = makeCtx()
    const res = await worker.fetch(
      makeRequest({ 'user-agent': 'ChatGPT-User/1.0' }),
      makeEnv(),
      ctx,
    )
    await Promise.all(waits)

    expect(res.status).toBe(200)
    const [, init] = evidenceCalls(fetchMock.mock.calls as FetchCall[])[0]
    const body = JSON.parse(String(init?.body))
    expect(body).toMatchObject({
      signatureAgent: null,
      signatureInput: null,
      signature: null,
      ua: 'ChatGPT-User/1.0',
    })
  })

  it('defaults to the production endpoint when CG_ENDPOINT is unset', async () => {
    const { ctx, waits } = makeCtx()
    await worker.fetch(makeRequest(TAP_HEADERS), makeEnv({ CG_ENDPOINT: undefined }), ctx)
    await Promise.all(waits)

    const [url] = evidenceCalls(fetchMock.mock.calls as FetchCall[])[0]
    expect(String(url)).toBe(DEFAULT_ENDPOINT)
  })

  it('returns a plain-text 502 when the origin fetch throws', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (): Promise<Response> => {
        throw new Error('origin unreachable')
      }),
    )
    const res = await worker.fetch(makeRequest(TAP_HEADERS), makeEnv(), makeCtx().ctx)

    expect(res.status).toBe(502)
    expect(res.headers.get('content-type')).toBe('text/plain')
    const body = await res.text()
    expect(body.toLowerCase()).not.toContain('chargeguard')
  })

  it('still returns the origin response when the evidence POST fails', async () => {
    fetchMock = mockFetch({ evidenceFail: true })
    vi.stubGlobal('fetch', fetchMock)
    const { ctx, waits } = makeCtx()

    const res = await worker.fetch(makeRequest(TAP_HEADERS), makeEnv(), ctx)
    await expect(Promise.all(waits)).resolves.toHaveLength(1)

    expect(res.status).toBe(200)
    await expect(res.text()).resolves.toBe('origin ok')
  })

  it('forwards a repeated nonce only once', async () => {
    const signatureInput =
      'sig1=("@authority"); nonce="dedupe-worker-1"; created=1; expires=2; keyid="k"; tag="t"'
    const headers = { ...TAP_HEADERS, 'signature-input': signatureInput }

    const first = makeCtx()
    await worker.fetch(makeRequest(headers), makeEnv(), first.ctx)
    await Promise.all(first.waits)

    const second = makeCtx()
    await worker.fetch(makeRequest(headers), makeEnv(), second.ctx)
    await Promise.all(second.waits)

    expect(evidenceCalls(fetchMock.mock.calls as FetchCall[])).toHaveLength(1)
    expect(originCalls(fetchMock.mock.calls as FetchCall[])).toHaveLength(2)
  })
})

// ── KV-backed nonce dedupe (best-effort, optional) ───────────────────────

describe('KV nonce dedupe', () => {
  function makeKv(getImpl: (key: string) => Promise<string | null>) {
    return {
      kv: {
        get: vi.fn(getImpl),
        put: vi.fn(
          async (
            _key: string,
            _value: string,
            _options?: { expirationTtl?: number },
          ): Promise<void> => undefined,
        ),
      },
    }
  }

  const NONCE_INPUT =
    'sig1=("@authority"); nonce="kv-nonce-1"; created=1; expires=2; keyid="k"; tag="t"'
  const HEADERS = { ...TAP_HEADERS, 'signature-input': NONCE_INPUT }

  it('skips the forward when KV already knows the nonce (fresh isolate)', async () => {
    const { kv } = makeKv(async () => '123')
    const { ctx, waits } = makeCtx()

    await worker.fetch(makeRequest(HEADERS), makeEnv({ CG_KV_NAMESPACE: kv }), ctx)
    await Promise.all(waits)

    expect(evidenceCalls(fetchMock.mock.calls as FetchCall[])).toHaveLength(0)
  })

  it('persists fresh nonces to KV and forwards', async () => {
    const { kv } = makeKv(async () => null)
    const { ctx, waits } = makeCtx()

    await worker.fetch(makeRequest(HEADERS), makeEnv({ CG_KV_NAMESPACE: kv }), ctx)
    await Promise.all(waits)

    expect(kv.put).toHaveBeenCalledTimes(1)
    const [key, value, options] = kv.put.mock.calls[0] as [string, string, { expirationTtl?: number }]
    expect(key).toMatch(/^cg:nonce:[0-9a-f]{64}$/)
    expect(value).toMatch(/^\d+$/)
    expect(options?.expirationTtl).toBe(86_400)
    expect(evidenceCalls(fetchMock.mock.calls as FetchCall[])).toHaveLength(1)
  })

  it('still forwards when KV read/write fails (best-effort only)', async () => {
    const kv: KVLike = {
      get: vi.fn(async (): Promise<string | null> => {
        throw new Error('kv unavailable')
      }),
      put: vi.fn(async (): Promise<void> => {
        throw new Error('kv unavailable')
      }),
    }
    const { ctx, waits } = makeCtx()

    await worker.fetch(makeRequest(HEADERS), makeEnv({ CG_KV_NAMESPACE: kv }), ctx)
    await Promise.all(waits)

    expect(evidenceCalls(fetchMock.mock.calls as FetchCall[])).toHaveLength(1)
    expect(originCalls(fetchMock.mock.calls as FetchCall[])).toHaveLength(1)
  })
})
