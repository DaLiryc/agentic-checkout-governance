/**
 * @chargeguard/tap-capture — public entry point.
 *
 * Framework-neutral exports only (the Next.js/Express/Fastify adapters are
 * separate subpath entries: '@chargeguard/tap-capture/next', '/express',
 * '/fastify') so importing this entry never pulls framework code in.
 */

export { classifyAgentUA, type AgentKind } from './classify.js'
export {
  DEFAULT_ENDPOINT,
  type CaptureConfig,
  type CapturedRequest,
  type ConsentedIds,
  type HeaderBag,
  forwardEvidence,
  hasTapHeaders,
  hashIp,
  headerBagFrom,
  looksLikeAgentUa,
  parseConsentParams,
  pickSafeHeaders,
} from './core.js'
