/**
 * Agentic evidence matcher — links an incoming dispute to captured
 * agent-transaction evidence (docs/AGENTIC-EVIDENCE-PLAN.md §D4).
 *
 * Lookup order: payment_intent_id → user_email (lowercased) → user_par.
 * Each basis queries `agentic_evidence` filtered by merchant_id + basis,
 * ordered captured_at desc, limit 5. Verified evidence (tap_verified) is
 * preferred over other classifications on the same basis; otherwise the
 * most recent row wins. The first basis with a hit ends the search.
 *
 * NOTE on merchant identity: `agentic_evidence.merchant_id` (and the
 * ingestion keys in `merchant_ingestion_keys`) reference `auth.users`,
 * i.e. the ChargeGuard profile id — NOT the `merchants.id` uuid. Callers
 * resolving a dispute through merchants → profiles must pass profiles.id.
 *
 * Server-side only: uses the SERVICE-ROLE Supabase client (bypasses RLS,
 * matching the webhook handler's existing pattern via getSupabaseAdmin).
 */

import { getSupabaseAdmin } from '@/lib/api-auth'

// ── Types ───────────────────────────────────────────────────────────────

export interface MatchInput {
  /** auth.users id (profiles.id) — the agentic_evidence merchant key. */
  merchantId: string
  paymentIntentId?: string | null
  customerEmail?: string | null
  customerPar?: string | null
}

export interface EvidenceMatch {
  evidenceId: string
  classification: 'tap_verified' | 'tap_invalid' | 'agent_ua_only'
  agentUrl?: string | null
  keyid?: string | null
  keyFingerprint?: string | null
  nonce?: string | null
  capturedAt: string
  sigCreated?: number | null
  sigExpires?: number | null
  matchBasis: 'payment_intent' | 'email' | 'par'
}

type MatchBasis = EvidenceMatch['matchBasis']
type Classification = EvidenceMatch['classification']

/** Row shape projected out of agentic_evidence (snake_case, as stored). */
interface EvidenceRow {
  id: string
  classification: string
  agent_url: string | null
  keyid: string | null
  key_fingerprint: string | null
  nonce: string | null
  captured_at: string
  sig_created_at: number | null
  sig_expires_at: number | null
}

const EVIDENCE_COLUMNS =
  'id, classification, agent_url, keyid, key_fingerprint, nonce, captured_at, sig_created_at, sig_expires_at'

/** Bases examined per lookup, most to least specific. */
const LOOKUP_LIMIT = 5

// ── Helpers ─────────────────────────────────────────────────────────────

function isClassification(value: string): value is Classification {
  return (
    value === 'tap_verified' || value === 'tap_invalid' || value === 'agent_ua_only'
  )
}

/** Prefer tap_verified rows; else take the most recent (rows arrive desc). */
function pickRow(rows: EvidenceRow[]): EvidenceRow | null {
  return rows.find((r) => r.classification === 'tap_verified') ?? rows[0] ?? null
}

function toMatch(row: EvidenceRow, basis: MatchBasis): EvidenceMatch | null {
  if (!isClassification(row.classification)) return null
  return {
    evidenceId: row.id,
    classification: row.classification,
    agentUrl: row.agent_url,
    keyid: row.keyid,
    keyFingerprint: row.key_fingerprint,
    nonce: row.nonce,
    capturedAt: row.captured_at,
    sigCreated: row.sig_created_at,
    sigExpires: row.sig_expires_at,
    matchBasis: basis,
  }
}

async function queryByBasis(
  merchantId: string,
  column: 'payment_intent_id' | 'user_email' | 'user_par',
  value: string,
): Promise<EvidenceRow[]> {
  const supabase = getSupabaseAdmin()
  const { data, error } = await supabase
    .from('agentic_evidence')
    .select(EVIDENCE_COLUMNS)
    .eq('merchant_id', merchantId)
    .eq(column, value)
    .order('captured_at', { ascending: false })
    .limit(LOOKUP_LIMIT)

  if (error) {
    console.error(`[agentic-evidence] match query failed on ${column}: ${error.message}`)
    return []
  }
  return (data ?? []) as EvidenceRow[]
}

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Find the best agent-evidence match for a dispute. Returns null when no
 * evidence row matches any basis. Query errors are logged and treated as
 * "no rows for this basis" so a transient failure on one basis (e.g.
 * payment_intent_id) still allows the next basis (email, PAR) to run.
 */
export async function findAgentEvidence(input: MatchInput): Promise<EvidenceMatch | null> {
  const email = input.customerEmail?.trim().toLowerCase() || null

  const bases: Array<{
    column: 'payment_intent_id' | 'user_email' | 'user_par'
    value: string
    basis: MatchBasis
  }> = []

  if (input.paymentIntentId) {
    bases.push({ column: 'payment_intent_id', value: input.paymentIntentId, basis: 'payment_intent' })
  }
  if (email) {
    bases.push({ column: 'user_email', value: email, basis: 'email' })
  }
  if (input.customerPar) {
    bases.push({ column: 'user_par', value: input.customerPar, basis: 'par' })
  }

  for (const { column, value, basis } of bases) {
    const row = pickRow(await queryByBasis(input.merchantId, column, value))
    if (!row) continue
    const match = toMatch(row, basis)
    if (match) return match
  }

  return null
}
