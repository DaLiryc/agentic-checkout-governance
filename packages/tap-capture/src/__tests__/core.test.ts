import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import {
  DEFAULT_ENDPOINT,
  forwardEvidence,
  hasTapHeaders,
  hashIp,
  type CapturedRequest,
} from '../core'

// ── Helpers ─────────────────────────────────────────────────────────────

function makeCaptured(overrides: Partial<CapturedRequest> = {}): CapturedRequest {
  return {
    signatureAgent: null,
    signatureInput: null,
    signature: null,
    authority: 'shop.example.com',
    path: '/checkout',
    rawHeaders: {
      'content-type': 'application/json',
      accept: '*/*',
      'user-agent': 'OpenAI Operator/1.0',
      cookie: 'session=secret',
      authorization: 'Bearer merchant-secret',
    },
    ua: 'OpenAI Operator/1.0',
    userEmail: 'buyer@example.com',
    userPar: 'PAR-123',
    checkoutSessionId: 'cs_test_1',
    ipHash: 'deadbeef',
    ...overrides,
  }
}

const CONFIG = { ingestionKey: 'key-1', endpoint: 'https://ingest.test/evidence' }

/** signatureInput WITHOUT a nonce → never touches the nonce dedupe cache. */
const NO_NONCE_INPUT =
  'sig1=("@authority" "@path"); created=1000; expires=2000; keyid="k1"; tag="visa-tap"'

function mockFetchOk(): ReturnType<typeof vi.fn> {
  return vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
      new Response(null, { status: 202 }),
  )
}

let fetchMock: ReturnType<typeof mockFetchOk>

beforeEach(() => {
  fetchMock = mockFetchOk()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── hasTapHeaders truth table ───────────────────────────────────────────

describe('hasTapHeaders', () => {
  it('is false when all three headers are absent/null/empty', () => {
    expect(hasTapHeaders({})).toBe(false)
    expect(hasTapHeaders({ signatureAgent: null, signatureInput: null, signature: null })).toBe(false)
    expect(hasTapHeaders({ signatureAgent: '', signatureInput: '', signature: '  ' })).toBe(false)
    expect(hasTapHeaders({ signatureAgent: undefined, signatureInput: undefined, signature: undefined })).toBe(false)
  })

  it('is true for signatureAgent alone', () => {
    expect(hasTapHeaders({ signatureAgent: 'https://agent.example' })).toBe(true)
  })

  it('is true for signatureInput alone', () => {
    expect(
      hasTapHeaders({ signatureInput: 'sig1=("@authority"); nonce="n"' }),
    ).toBe(true)
  })

  it('is true for signature alone', () => {
    expect(hasTapHeaders({ signature: 'sig1=:abc123:' })).toBe(true)
  })

  it('is true when any header is present alongside empty ones', () => {
    expect(
      hasTapHeaders({ signatureAgent: null, signatureInput: '', signature: 'sig1=:xyz:' }),
    ).toBe(true)
  })
})

// ── hashIp ───────────────────────────────────────────────────────────────

describe('hashIp', () => {
  it('produces the salted sha256 hex digest of the IP', async () => {
    const expected = createHash('sha256').update('203.0.113.7cg-salt-v1').digest('hex')
    await expect(hashIp('203.0.113.7')).resolves.toBe(expected)
  })
})

// ── forwardEvidence ──────────────────────────────────────────────────────

describe('forwardEvidence', () => {
  it('POSTs the correct payload with a Bearer header to the configured endpoint', async () => {
    const captured = makeCaptured({ signatureInput: NO_NONCE_INPUT, signature: 'sig1=:aa==' })
    await forwardEvidence(CONFIG, captured)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('https://ingest.test/evidence')
    expect(init?.method).toBe('POST')

    const headers = new Headers(init?.headers)
    expect(headers.get('authorization')).toBe('Bearer key-1')
    expect(headers.get('content-type')).toBe('application/json')

    const body = JSON.parse(String(init?.body))
    expect(body).toEqual({
      signatureAgent: null,
      signatureInput: NO_NONCE_INPUT,
      signature: 'sig1=:aa==',
      authority: 'shop.example.com',
      path: '/checkout',
      // Only the safe allowlist survives — cookie/authorization are stripped.
      rawHeaders: {
        'content-type': 'application/json',
        accept: '*/*',
        'user-agent': 'OpenAI Operator/1.0',
      },
      ua: 'OpenAI Operator/1.0',
      userEmail: 'buyer@example.com',
      userPar: 'PAR-123',
      checkoutSessionId: 'cs_test_1',
      ipHash: 'deadbeef',
    })
  })

  it('defaults to the production endpoint when none is configured', async () => {
    await forwardEvidence({ ingestionKey: 'k' }, makeCaptured({ signatureInput: NO_NONCE_INPUT }))
    const [url] = fetchMock.mock.calls[0]
    expect(String(url)).toBe(DEFAULT_ENDPOINT)
  })

  it('never throws when fetch rejects', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down')
      }),
    )
    await expect(
      forwardEvidence(CONFIG, makeCaptured({ signatureInput: NO_NONCE_INPUT })),
    ).resolves.toBeUndefined()
  })

  it('skips the second forward for a repeated signatureInput nonce', async () => {
    const signatureInput =
      'sig1=("@authority"); nonce="dedupe-nonce-unique-1"; created=1; expires=2; keyid="k"; tag="t"'
    const captured = makeCaptured({ signatureInput })

    await forwardEvidence(CONFIG, captured)
    expect(fetchMock).toHaveBeenCalledTimes(1)

    await forwardEvidence(CONFIG, captured)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('never sends when sampleRate is 0', async () => {
    await forwardEvidence(
      { ...CONFIG, sampleRate: 0 },
      makeCaptured({ signatureInput: NO_NONCE_INPUT }),
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
