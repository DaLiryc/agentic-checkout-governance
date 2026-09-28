/**
 * @chargeguard/tap-capture — agent User-Agent classifier.
 *
 * Powers agent-traffic telemetry: requests from known shopping agents
 * (Visa TAP signers) and generic bots are worth capturing even when no
 * TAP signature headers are present.
 */

export type AgentKind =
  | 'openai-operator'
  | 'chatgpt'
  | 'claude'
  | 'perplexity'
  | 'amazon-nova'
  | 'unknown-bot'
  | 'human'

/**
 * Classify a User-Agent string.
 *
 * Known agents are matched case-insensitively on stable substrings, in
 * priority order (e.g. `ClaudeBot` must classify as `claude`, not the
 * generic `unknown-bot`). Null/undefined/empty UAs classify as `human`.
 */
export function classifyAgentUA(ua: string | null | undefined): AgentKind {
  if (typeof ua !== 'string' || ua.length === 0) return 'human'
  const s = ua.toLowerCase()

  if (s.includes('openai operator')) return 'openai-operator'
  if (s.includes('chatgpt')) return 'chatgpt'
  if (s.includes('claude')) return 'claude'
  if (s.includes('perplexity')) return 'perplexity'
  if (/amazon[ -]?nova|nova[ -]?act/.test(s)) return 'amazon-nova'
  if (/bot|spider|headless/.test(s)) return 'unknown-bot'

  return 'human'
}
