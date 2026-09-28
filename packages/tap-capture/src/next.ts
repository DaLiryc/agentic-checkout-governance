/**
 * @chargeguard/tap-capture — Next.js middleware wrapper.
 *
 * Compose INSIDE your existing middleware (side-effect only, never mutates
 * the request, never blocks the response path):
 *
 *   import { maybeCapture } from '@chargeguard/tap-capture/next'
 *   export async function middleware(req: NextRequest) {
 *     await maybeCapture(req, { ingestionKey: process.env.CG_KEY! })
 *     return NextResponse.next()
 *   }
 */

// '.js' suffix is required: `next` has no `exports` map and its server entry
// is CJS, so the bare 'next/server' subpath cannot resolve under NodeNext ESM.
import { NextRequest, NextResponse } from 'next/server.js'
import {
  type CapturedRequest,
  type CaptureConfig,
  forwardEvidence,
  hasTapHeaders,
  hashIp,
  deriveIpSalt,
  looksLikeAgentUa,
  parseConsentParams,
  pickSafeHeaders,
} from './core.js'

/**
 * Detect + schedule evidence capture for one request. Side-effect only.
 *
 * Returns `null` when the request is skipped entirely (no TAP headers AND
 * a human-like User-Agent), otherwise `true` once a forward has been
 * scheduled. The forward itself is fire-and-forget: it is never awaited
 * here, so the merchant's response path is never blocked.
 */
export async function maybeCapture(
  req: NextRequest,
  config: CaptureConfig,
): Promise<boolean | null> {
  const ua = req.headers.get('user-agent')
  const signatureAgent = req.headers.get('signature-agent')
  const signatureInput = req.headers.get('signature-input')
  const signature = req.headers.get('signature')

  if (
    !hasTapHeaders({ signatureAgent, signatureInput, signature }) &&
    !looksLikeAgentUa(ua)
  ) {
    return null
  }

  const url = req.nextUrl
  const consent = parseConsentParams(url.searchParams)

  // Next middleware has no direct client-IP API; trust the first proxy hop.
  const forwardedFor = req.headers.get('x-forwarded-for')
  const firstIp = forwardedFor?.split(',')[0]?.trim()
  const ipSalt = deriveIpSalt(config.ingestionKey)
  const ipHash = firstIp !== undefined && firstIp.length > 0 ? await hashIp(firstIp, ipSalt) : null

  const captured: CapturedRequest = {
    signatureAgent,
    signatureInput,
    signature,
    authority: url.host,
    path: url.pathname,
    rawHeaders: pickSafeHeaders(req.headers),
    ua,
    userEmail: consent.userEmail,
    userPar: consent.userPar,
    checkoutSessionId: consent.checkoutSessionId,
    ipHash,
  }

  void forwardEvidence(config, captured).catch(() => undefined)
  return true
}

/**
 * Full middleware wrapper: capture (fire-and-forget) then `NextResponse.next()`.
 * Use `maybeCapture` instead when composing inside an existing middleware.
 */
export function captureNext(
  config: CaptureConfig,
): (req: NextRequest) => Promise<NextResponse> {
  return async (req: NextRequest): Promise<NextResponse> => {
    await maybeCapture(req, config)
    return NextResponse.next()
  }
}
