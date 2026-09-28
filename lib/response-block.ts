/**
 * Issuer-facing agent-evidence block builder (docs/AGENTIC-EVIDENCE-PLAN.md §D4).
 *
 * Produces the JSON block stored on the dispute row when agent evidence
 * matches a chargeback. Two variants:
 *  - tap_verified → "Authorized Agent Transaction": affirmative evidence
 *    that the purchase request was cryptographically signed by the
 *    cardholder's authorized AI agent (Visa TAP) and verified at capture.
 *  - tap_invalid / agent_ua_only → "Suspicious Agent Activity Detected":
 *    defensive supporting context only; agent-shaped traffic was present
 *    but no valid signature exists. Never overclaims.
 *
 * Copy constraints: plain English, issuer-friendly, no em dashes anywhere
 * in user-facing strings.
 */

import type { EvidenceMatch } from './match'

export interface AgentEvidenceBlock {
  title: string
  summary: string
  fields: Array<{ label: string; value: string }>
  classification: EvidenceMatch['classification']
}

const NOT_RECORDED = 'Not recorded'

function isoFromUnixSeconds(seconds: number | null | undefined): string {
  return typeof seconds === 'number' ? new Date(seconds * 1000).toISOString() : NOT_RECORDED
}

function basisLabel(basis: EvidenceMatch['matchBasis']): string {
  switch (basis) {
    case 'payment_intent':
      return 'Payment intent'
    case 'email':
      return 'Customer email'
    case 'par':
      return 'Payment account reference'
  }
}

function verifiedBlock(match: EvidenceMatch): AgentEvidenceBlock {
  return {
    title: 'Authorized Agent Transaction',
    summary:
      'This purchase request was cryptographically signed by an AI shopping agent authorized by the cardholder under the Visa Trusted Agent Protocol (TAP). ' +
      'The signature was verified independently by ChargeGuard at the time of capture against the key published in the agent registry. ' +
      'The signed request includes a unique session nonce that prevents replay of the evidence, and the signature is bound to the merchant domain, so the request cannot be reused on another site.',
    fields: [
      { label: 'Agent', value: match.agentUrl ?? NOT_RECORDED },
      { label: 'Key ID', value: match.keyid ?? NOT_RECORDED },
      { label: 'Key fingerprint', value: match.keyFingerprint ?? NOT_RECORDED },
      { label: 'Session nonce', value: match.nonce ?? NOT_RECORDED },
      { label: 'Signed at', value: isoFromUnixSeconds(match.sigCreated) },
      { label: 'Evidence captured at', value: match.capturedAt },
      { label: 'Match basis', value: basisLabel(match.matchBasis) },
    ],
    classification: match.classification,
  }
}

function suspiciousBlock(match: EvidenceMatch): AgentEvidenceBlock {
  const signatureFailed = match.classification === 'tap_invalid'
  const signatureStatus = signatureFailed
    ? 'Present but failed verification'
    : 'Not present'

  const fields: Array<{ label: string; value: string }> = [
    { label: 'Agent', value: match.agentUrl ?? NOT_RECORDED },
  ]
  if (match.keyid) {
    fields.push({ label: 'Key ID', value: match.keyid })
  }
  fields.push(
    { label: 'Signature status', value: signatureStatus },
    { label: 'Evidence captured at', value: match.capturedAt },
    { label: 'Match basis', value: basisLabel(match.matchBasis) },
  )

  return {
    title: 'Suspicious Agent Activity Detected',
    summary:
      'Automated AI agent traffic was detected at this checkout. ' +
      (signatureFailed
        ? 'The request carried an agent signature, but the signature did not pass verification.'
        : 'The request carried agent identifiers, but no cryptographic signature from an authorized agent was provided.') +
      ' This information is provided as supporting context for the dispute review. It does not by itself establish whether the transaction was authorized.',
    fields,
    classification: match.classification,
  }
}

/**
 * Build the issuer-facing evidence block for a matched evidence row.
 * tap_verified produces affirmative agent-authorization evidence; every
 * other classification produces defensive supporting context.
 */
export function buildAgentEvidenceBlock(match: EvidenceMatch): AgentEvidenceBlock {
  if (match.classification === 'tap_verified') {
    return verifiedBlock(match)
  }
  return suspiciousBlock(match)
}
