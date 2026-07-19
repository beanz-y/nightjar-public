// In-app warrant canary verifier (DESIGN 10; DESIGN 10.3). Fetches the
// operator's signed, dated statement from the same-origin relay, verifies it
// against the pinned public key, and classifies the result for the UI.
//
// The load-bearing honesty rules (do not weaken):
//  - This CANNOT detect a backdoored broad code swap and buys ZERO against a
//    targeted/selective attack (DESIGN 1.4). Its only teeth are lapse-detection
//    (a broad attacker who stops signing shows `stale` to everyone) plus the
//    out-of-band rebuild. The UI captions every state as a freshness/authorship
//    FACT, never a build-integrity verdict, and never with the SafetyNumber ✓.
//  - Alarming states are reserved for a REACHABLE server that returns a bad or
//    missing answer. Offline / transport failure is `unreachable` (quiet), so an
//    offline PWA load (the service worker caches nothing) never cries wolf.
//  - Fails closed: any parse/verify failure yields a non-`ok` status, never a green.

import { domainSeparate, ed25519Verify, utf8 } from '../crypto/primitives'
import { b64decode } from '../wire/codec'
import {
  CANARY_FRESH_DAYS,
  CANARY_FUTURE_SKEW_MS,
  CANARY_MAX_STATEMENT_LEN,
  CANARY_MAX_VERSION_LEN,
  CANARY_PUBKEY_BYTES,
  CANARY_SIG_BYTES,
  CANARY_STALE_DAYS,
  RELEASE_HASH_HEX_LEN,
  TAG_CANARY,
} from './constants'

/** Canary states, ordered loosely from benign to alarming.
 *  Quiet (About-only, never a banner): unconfigured, unreachable, ok, aging.
 *  Note (visible but neutral): version-mismatch.
 *  Warning (a banner): absent, invalid, stale. */
export type CanaryStatus =
  | 'unconfigured' // no key pinned in this build -> verification not yet online
  | 'unreachable' // could not fetch (offline / non-2xx / non-JSON) -> quiet
  | 'absent' // server reachable and says 404/410, but a key IS pinned -> the signal was removed
  | 'invalid' // fetched, but bad structure / signature / a future signedAt
  | 'version-mismatch' // valid signature, but vouches for a different release than this one
  | 'ok' // valid, fresh
  | 'aging' // valid, older than fresh but not yet stale
  | 'stale' // valid, older than the stale threshold

/** The canary document served at /canary.json (DESIGN 10). */
export interface CanaryDoc {
  v: number
  version: string
  releaseHash: string
  statement: string
  signedAt: string
  sig: string
}

/** Transport outcome, kept separate from verification so the UI can distinguish
 *  "could not reach" (quiet) from "reached, said no" (warn). */
export type CanaryFetch =
  | { kind: 'doc'; doc: unknown }
  | { kind: 'absent' } // reachable, 404/410
  | { kind: 'malformed' } // reachable 200 that CLAIMS JSON but does not parse -> warn (invalid)
  | { kind: 'unreachable' } // rejected, timed out, non-2xx, or not JSON (e.g. an SPA index.html fallback)

export interface CanaryResult {
  status: CanaryStatus
  /** Whether a public key is pinned in this build at all. */
  configured: boolean
  /** Whether the UI should show a warning banner (absent | invalid | stale). */
  alarming: boolean
  /** A short, honest human caption (a fact, not a verdict). */
  detail: string
  /** Fields the About view surfaces when the signature verified. */
  attestsVersion?: string
  attestsHash?: string
  signedAt?: string
  ageDays?: number
}

const DAY_MS = 24 * 60 * 60 * 1000
const HEX_RE = /^[0-9a-f]+$/

/** Fetch the canary from the same-origin relay. Never throws; maps every failure
 *  mode to a transport outcome. A non-JSON 200 (the SPA index.html fallback if the
 *  route were ever missing) is `unreachable`, NOT a parseable-but-bad doc, so it
 *  can never escalate to an alarming `invalid`. */
export async function fetchCanary(origin: string): Promise<CanaryFetch> {
  let res: Response
  try {
    res = await fetch(`${origin}/canary.json`, {
      cache: 'no-store',
      redirect: 'error',
      headers: { accept: 'application/json' },
    })
  } catch {
    return { kind: 'unreachable' }
  }
  if (res.status === 404 || res.status === 410) return { kind: 'absent' }
  if (!res.ok) return { kind: 'unreachable' }
  const ct = (res.headers.get('content-type') ?? '').toLowerCase()
  // A non-JSON 200 (e.g. an SPA index.html fallback if the route were ever missing)
  // is quiet `unreachable`, not an alarm: the operator is not claiming to have
  // served a canary. But a body that CLAIMS to be JSON and does not parse is a
  // reachable server returning a bad answer -> `malformed` -> warn (DESIGN 10).
  if (!ct.includes('application/json')) return { kind: 'unreachable' }
  try {
    return { kind: 'doc', doc: await res.json() }
  } catch {
    return { kind: 'malformed' }
  }
}

/** Structural validation of an untrusted canary body. Throws on anything off
 *  (fail-closed), so a malformed doc becomes `invalid`, never a silent green. */
function parseCanaryDoc(raw: unknown): CanaryDoc {
  if (typeof raw !== 'object' || raw === null) throw new Error('canary: not an object')
  const o = raw as Record<string, unknown>
  if (o.v !== 1) throw new Error('canary: bad version tag')
  const str = (v: unknown, max: number, what: string): string => {
    if (typeof v !== 'string' || v.length === 0 || v.length > max) throw new Error(`canary: bad ${what}`)
    return v
  }
  const version = str(o.version, CANARY_MAX_VERSION_LEN, 'version')
  const releaseHash = str(o.releaseHash, RELEASE_HASH_HEX_LEN, 'releaseHash')
  if (releaseHash.length !== RELEASE_HASH_HEX_LEN || !HEX_RE.test(releaseHash)) {
    throw new Error('canary: releaseHash is not sha-256 hex')
  }
  const statement = str(o.statement, CANARY_MAX_STATEMENT_LEN, 'statement')
  const signedAt = str(o.signedAt, 40, 'signedAt')
  const sig = str(o.sig, 128, 'sig')
  return { v: 1, version, releaseHash, statement, signedAt, sig }
}

/** The exact bytes the operator signs (DESIGN 10). Framed by domainSeparate,
 *  so every field is length-delimited and the tag is injective against all other
 *  Nightjar signatures. The signing tool (tools/canary-sign.mjs) must match. */
export function canarySignedMessage(doc: CanaryDoc): Uint8Array {
  return domainSeparate(
    TAG_CANARY,
    utf8(doc.version),
    utf8(doc.releaseHash),
    utf8(doc.signedAt),
    utf8(doc.statement),
  )
}

function result(status: CanaryStatus, detail: string, extra?: Partial<CanaryResult>): CanaryResult {
  const alarming = status === 'absent' || status === 'invalid' || status === 'stale'
  return { status, configured: true, alarming, detail, ...extra }
}

/**
 * Classify a fetched canary against the pinned key and the running build version.
 * Pure and synchronous; `now` is injected for testability. Order matters: the
 * benign quiet states (unconfigured, unreachable) are decided before anything that
 * could alarm, so being offline or shipping without a key never shows a warning.
 */
export function verifyCanary(
  fetched: CanaryFetch,
  pinnedPubKeyB64: string,
  runningVersion: string,
  now: number,
): CanaryResult {
  if (pinnedPubKeyB64.length === 0) {
    return {
      status: 'unconfigured',
      configured: false,
      alarming: false,
      detail: 'Independent build verification is being brought online.',
    }
  }
  if (fetched.kind === 'unreachable') {
    return result('unreachable', 'Could not check the canary right now. You may be offline.')
  }
  if (fetched.kind === 'absent') {
    return result('absent', 'The operator’s signed canary was removed. Ask why before trusting this build.')
  }
  if (fetched.kind === 'malformed') {
    return result('invalid', 'The canary body was not valid JSON. Ask the operator before trusting this build.')
  }

  let doc: CanaryDoc
  try {
    doc = parseCanaryDoc(fetched.doc)
  } catch {
    return result('invalid', 'The canary did not parse. Ask the operator before trusting this build.')
  }

  let pub: Uint8Array
  let sig: Uint8Array
  try {
    pub = b64decode(pinnedPubKeyB64, CANARY_PUBKEY_BYTES)
    sig = b64decode(doc.sig, CANARY_SIG_BYTES)
  } catch {
    return result('invalid', 'The canary signature was malformed. Ask the operator before trusting this build.')
  }
  if (!ed25519Verify(sig, canarySignedMessage(doc), pub)) {
    return result('invalid', 'The canary signature did not verify. Ask the operator before trusting this build.')
  }

  const t = Date.parse(doc.signedAt)
  if (Number.isNaN(t)) {
    return result('invalid', 'The canary date did not parse. Ask the operator before trusting this build.')
  }
  // A future-dated canary is never fresh (MF3): the guarantee is that the operator
  // cannot forge a future fresh date, so treat one as invalid rather than trust it.
  if (t > now + CANARY_FUTURE_SKEW_MS) {
    return result('invalid', 'The canary is dated in the future. Ask the operator before trusting this build.', {
      attestsVersion: doc.version,
      attestsHash: doc.releaseHash,
      signedAt: doc.signedAt,
    })
  }

  const ageDays = Math.max(0, Math.floor((now - t) / DAY_MS))
  const common = { attestsVersion: doc.version, attestsHash: doc.releaseHash, signedAt: doc.signedAt, ageDays }

  // Staleness wins over version-mismatch (impl-review fix): an ancient canary must
  // surface as `stale` even when it vouches for a different release, otherwise the
  // lapse-detection that is the canary's one real broad-attack tooth (DESIGN 10
  // §3.3) would be silently suppressed by a version-mismatch. A mismatch that is
  // NOT yet stale stays a neutral note (benign right after a deploy); if the
  // operator never refreshes it, it escalates to `stale` at the usual threshold.
  if (ageDays > CANARY_STALE_DAYS) {
    return result('stale', `The operator has not refreshed the canary in ${ageDays} days. Usually just lateness, but worth asking.`, common)
  }

  if (doc.version !== runningVersion) {
    return {
      status: 'version-mismatch',
      configured: true,
      alarming: false,
      detail: `The canary vouches for a different release (${doc.version}) than the one you are running (${runningVersion}). This is normal right after an update; worth a look if it sticks.`,
      ...common,
    }
  }

  if (ageDays <= CANARY_FRESH_DAYS) {
    return {
      status: 'ok',
      configured: true,
      alarming: false,
      detail: `The operator signed a statement about this release ${ageDays} day(s) ago.`,
      ...common,
    }
  }
  return {
    status: 'aging',
    configured: true,
    alarming: false,
    detail: `The operator last signed a statement about this release ${ageDays} days ago.`,
    ...common,
  }
}

/** Convenience: fetch + verify. Never throws. */
export async function checkCanary(
  origin: string,
  pinnedPubKeyB64: string,
  runningVersion: string,
  now: number,
): Promise<CanaryResult> {
  const fetched = await fetchCanary(origin)
  return verifyCanary(fetched, pinnedPubKeyB64, runningVersion, now)
}
