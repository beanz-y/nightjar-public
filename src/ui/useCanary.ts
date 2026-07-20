// Best-effort warrant-canary check (P7, DESIGN 10.3). Runs once on mount, off the
// critical path: it NEVER blocks or gates messaging, and checkCanary never throws
// (offline/failure -> a quiet `unreachable`). The result drives the About view and
// a dismissible App banner only when it is `alarming`.
//
// P8 hardening: the last VERIFIED canary's signedAt is remembered per device
// (localStorage). A selectively-suppressed /canary.json (persistent 5xx or
// unreachable while the app itself is online) previously stayed quiet forever;
// now, once the remembered signature passes the staleness horizon, the quiet
// `unreachable` escalates to an alarming stale-style result on a RETURNING
// device. A genuinely offline device (navigator.onLine false) never alarms.

import { useEffect, useState } from 'react'
import { getRelayOrigin } from '../platform'
import { type CanaryResult, checkCanary } from '../verify/canary'
import { CANARY_STALE_DAYS } from '../verify/constants'
import { CANARY_PUBKEY_B64 } from '../verify/canaryKey'

const LAST_GOOD_KEY = 'nightjar.canary.lastGood'
const DAY_MS = 24 * 60 * 60 * 1000

interface LastGood {
  signedAt: string
  seenAt: number
}

function readLastGood(): LastGood | null {
  try {
    const raw = localStorage.getItem(LAST_GOOD_KEY)
    if (!raw) return null
    const p = JSON.parse(raw) as LastGood
    return typeof p.signedAt === 'string' && Number.isFinite(p.seenAt) ? p : null
  } catch {
    return null
  }
}

function writeLastGood(signedAt: string, now: number): void {
  try {
    localStorage.setItem(LAST_GOOD_KEY, JSON.stringify({ signedAt, seenAt: now }))
  } catch {
    /* storage unavailable: the escalation just stays unavailable too */
  }
}

/** Escalate a quiet `unreachable` when this DEVICE has verified a canary before
 *  and that signature is now stale: an operator serving errors only for
 *  /canary.json should not be quieter than one serving a stale canary. */
function withLastGoodEscalation(r: CanaryResult, now: number): CanaryResult {
  if (r.status === 'ok' || r.status === 'aging') {
    if (r.signedAt) writeLastGood(r.signedAt, now)
    return r
  }
  if (r.status !== 'unreachable') return r
  if (typeof navigator !== 'undefined' && navigator.onLine === false) return r
  const last = readLastGood()
  if (!last) return r
  const signedMs = Date.parse(last.signedAt)
  if (!Number.isFinite(signedMs)) return r
  const ageDays = Math.floor((now - signedMs) / DAY_MS)
  if (ageDays <= CANARY_STALE_DAYS) return r
  return {
    ...r,
    status: 'stale',
    alarming: true,
    detail: `The canary has been unreachable for a while, and the last one this device verified was signed ${ageDays} days ago (the operator re-signs roughly monthly). Treat this like a stale canary until it returns.`,
  }
}

export function useCanary(): CanaryResult | null {
  const [result, setResult] = useState<CanaryResult | null>(null)
  useEffect(() => {
    let cancelled = false
    const now = Date.now()
    void checkCanary(getRelayOrigin(), CANARY_PUBKEY_B64, __APP_VERSION__, now)
      .then((r) => {
        if (!cancelled) setResult(withLastGoodEscalation(r, now))
      })
      .catch(() => {
        /* checkCanary is contracted never to throw; stay defensive regardless */
      })
    return () => {
      cancelled = true
    }
  }, [])
  return result
}
