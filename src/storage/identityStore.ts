// Eviction-safe device-identity startup against a KeyStore (DESIGN 8.1, 8.2).

import { type Identity, deserializeIdentity, generateIdentity, serializeIdentity } from '../crypto/identity'
import type { KeyStore } from './keystore'
import type { Lock } from './lock'
import type { Sentinel, StartupState } from './persist'

export const IDENTITY_KEY = 'identity.v1'

export interface Bootstrap {
  state: StartupState
  identity: Identity | null
}

/**
 * Eviction-safe identity startup (DESIGN 8.2). Distinguishes a genuine first run
 * from an evicted store using the sentinel, so we NEVER silently generate a new
 * identity after an eviction (which would change our key and alarm every
 * contact). On eviction the caller must restore from backup (P8).
 *
 * The whole check-then-act runs under the single-writer lock, so two tabs
 * booting concurrently on a genuine first run cannot both generate and (in P4)
 * publish divergent identities: the second waiter re-reads the store under the
 * lock and sees 'loaded'.
 */
export async function bootstrapIdentity(store: KeyStore, sentinel: Sentinel, lock: Lock): Promise<Bootstrap> {
  return lock.withLock<Bootstrap>('nightjar-identity', async () => {
    const existing = await store.get(IDENTITY_KEY)
    if (existing) {
      await sentinel.mark() // self-heal: ensure the sentinel exists for a known identity
      return { state: 'loaded', identity: deserializeIdentity(existing) }
    }
    if (await sentinel.exists()) {
      // Empty store but we registered before: the store was cleared. Route to
      // restore rather than regenerate.
      return { state: 'evicted-needs-restore', identity: null }
    }
    const identity = generateIdentity()
    await store.put(IDENTITY_KEY, serializeIdentity(identity))
    await sentinel.mark()
    return { state: 'first-run', identity }
  })
}
