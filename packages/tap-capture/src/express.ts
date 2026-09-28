/**
 * @chargeguard/tap-capture — Express adapter.
 *
 *   import { captureExpress } from '@chargeguard/tap-capture/express'
 *   app.use(captureExpress({ ingestionKey: process.env.CG_KEY! }))
 *
 * Express types are imported type-only, so the package keeps ZERO runtime
 * dependencies and consumers without Express can still import core/next.
 */

import type { NextFunction, Request, Response } from 'express'
import {
  type CapturedRequest,
  type CaptureConfig,
  forwardEvidence,
  hasTapHeaders,
  hashIp,
  headerBagFrom,
  looksLikeAgentUa,
  parseConsentParams,
  pickSafeHeaders,
} from './core.js'

async function handleExpress(config: CaptureConfig, req: Request): Promise<void> {
  const headers = headerBagFrom(req.headers)
  const ua = headers.get('user-agent')
  const signatureAgent = headers.get('signature-agent')
  const signatureInput = headers.get('signature-input')
  const signature = headers.get('signature')

  if (
    !hasTapHeaders({ signatureAgent, signatureInput, signature }) &&
    !looksLikeAgentUa(ua)
  ) {
    return
  }

  // Behind a proxy the public host lives in x-forwarded-host; else the Host
  // header; else Express's derived hostname.
  const authority =
    headers.get('x-forwarded-host') ?? headers.get('host') ?? req.hostname

  const url = new URL(req.originalUrl ?? req.url ?? '/', `http://${authority}`)
  const consent = parseConsentParams(url.searchParams)

  const ip = typeof req.ip === 'string' && req.ip.length > 0 ? req.ip : null
  const ipHash = ip !== null ? await hashIp(ip) : null

  const captured: CapturedRequest = {
    signatureAgent,
    signatureInput,
    signature,
    authority,
    path: url.pathname,
    rawHeaders: pickSafeHeaders(headers),
    ua,
    userEmail: consent.userEmail,
    userPar: consent.userPar,
    checkoutSessionId: consent.checkoutSessionId,
    ipHash,
  }

  await forwardEvidence(config, captured)
}

/** Express middleware: detect + fire-and-forget forward, always `next()`. */
export function captureExpress(
  config: CaptureConfig,
): (req: Request, _res: Response, next: NextFunction) => void {
  return (req: Request, _res: Response, next: NextFunction): void => {
    void handleExpress(config, req).catch(() => undefined)
    next()
  }
}
