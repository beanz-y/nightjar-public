// Best-effort warrant-canary check (P7, DESIGN 10.3). Runs once on mount, off the
// critical path: it NEVER blocks or gates messaging, and checkCanary never throws
// (offline/failure -> a quiet `unreachable`). The result drives the About view and
// a dismissible App banner only when it is `alarming`.

import { useEffect, useState } from 'react'
import { getRelayOrigin } from '../platform'
import { type CanaryResult, checkCanary } from '../verify/canary'
import { CANARY_PUBKEY_B64 } from '../verify/canaryKey'

export function useCanary(): CanaryResult | null {
  const [result, setResult] = useState<CanaryResult | null>(null)
  useEffect(() => {
    let cancelled = false
    void checkCanary(getRelayOrigin(), CANARY_PUBKEY_B64, __APP_VERSION__, Date.now())
      .then((r) => {
        if (!cancelled) setResult(r)
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
