import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { maybeCapture } from '../next'

const CONFIG = { ingestionKey: 'key-1', endpoint: 'https://ingest.test/evidence' }

const HUMAN_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36'
const AGENT_UA = 'OpenAI Operator/1.0 (+https://operator.openai.com)'

/** Flush pending microtasks + the immediate queue so fire-and-forget settles. */
function flush(): Promise<void> {
  return new Promise<void>((resolve) => setImmediate(resolve))
}

function makeRequest(url: string, headers: Record<string, string>): NextRequest {
  return new NextRequest(url, { method: 'POST', headers })
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
      new Response(null, { status: 202 }),
  )
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('maybeCapture', () => {
  it('schedules a forward for a request with TAP headers (no nonce → no dedupe)', async () => {
    // signature-input deliberately has NO nonce so the nonce cache is untouched.
    const req = makeRequest('https://shop.example.com/checkout?cg_email=buyer@example.com', {
      'user-agent': HUMAN_UA,
      'signature-agent': 'https://agent.example/.well-known/tap.json',
      'signature-input': 'sig1=("@authority" "@path"); created=1; expires=2; keyid="k"; tag="t"',
      signature: 'sig1=:aGVsbG8=',
    })

    const result = await maybeCapture(req, CONFIG)
    expect(result).toBe(true)

    await flush()
    expect(fetchMock).toHaveBeenCalledTimes(1)

    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('https://ingest.test/evidence')
    expect(new Headers(init?.headers).get('authorization')).toBe('Bearer key-1')

    const body = JSON.parse(String(init?.body))
    expect(body.authority).toBe('shop.example.com')
    expect(body.path).toBe('/checkout')
    expect(body.userEmail).toBe('buyer@example.com')
    expect(body.signatureAgent).toBe('https://agent.example/.well-known/tap.json')
  })

  it('returns null and never forwards for a human UA without TAP headers', async () => {
    const req = makeRequest('https://shop.example.com/pricing', {
      'user-agent': HUMAN_UA,
    })

    const result = await maybeCapture(req, CONFIG)
    expect(result).toBeNull()

    await flush()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('still captures agent-UA-only traffic (no TAP headers)', async () => {
    const req = makeRequest('https://shop.example.com/cart', {
      'user-agent': AGENT_UA,
    })

    const result = await maybeCapture(req, CONFIG)
    expect(result).toBe(true)

    await flush()
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body))
    expect(body.ua).toBe(AGENT_UA)
    expect(body.signatureAgent).toBeNull()
  })
})
