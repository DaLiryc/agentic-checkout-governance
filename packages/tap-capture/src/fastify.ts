/**
 * @chargeguard/tap-capture — Fastify adapter (onRequest hook).
 *
 *   import { captureFastify } from '@chargeguard/tap-capture/fastify'
 *   await app.register(captureFastify({ ingestionKey: process.env.CG_KEY! }))
 *
 * Fastify types are imported type-only, so the package keeps ZERO runtime
 * dependencies and consumers without Fastify can still import core/next.
 */

import type { FastifyPluginAsync, FastifyRequest } from 'fastify'
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

async function handleFastify(config: CaptureConfig, req: FastifyRequest): Promise<void> {
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

  const authority = headers.get('x-forwarded-host') ?? req.hostname
  const url = new URL(req.url ?? '/', `http://${authority}`)
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

/** Fastify plugin: registers an onRequest hook that never blocks the reply. */
export function captureFastify(config: CaptureConfig): FastifyPluginAsync {
  return async (instance) => {
    instance.addHook('onRequest', async (req, _reply) => {
      void handleFastify(config, req).catch(() => undefined)
    })
  }
}
