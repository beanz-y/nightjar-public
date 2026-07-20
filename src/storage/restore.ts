// Restore staging (P8, DESIGN 8.3). Turning an opened backup into this
// device's identity is a multi-write operation with crash windows, so it is
// ordered for fail-safety and gated by a durable one-shot flag:
//
//   1. wipe session-layer state (old sessions/dedup/outbox/prekeys belong to a
//      dead ratchet world and could never be used by the restored identity);
//   2. set RESTORE_PENDING (BEFORE the identity: the flag must already be
//      durable when a loadable identity first exists, so the forced fresh-
//      prekey publish can never be skipped by a crash);
//   3. write contacts, then the identity + sentinel;
//   4. the caller reloads; after the next authenticated connect the flag is
//      consumed by client.reregister() (fresh SPK + OPKs, server-side
//      hard-invalidation of anything the Directory still serves) and cleared
//      ONLY on success. If the network is down it survives and refires.
//
// The whole staging runs under the same cross-tab lock as identity bootstrap,
// with a re-check so two tabs cannot interleave restores.

import type { BackupPayload } from '../crypto/backup'
import { serializeIdentity } from '../crypto/identity'
import type { ContactStore } from '../trust/contactStore'
import { IDENTITY_KEY } from './identityStore'
import type { KeyStore } from './keystore'
import type { Lock } from './lock'
import type { Sentinel } from './persist'
import { PREKEYS_KEY } from './prekeyStore'
import type { SessionStore } from './sessionStore'

export const RESTORE_PENDING_KEY = 'restore.pending.v1'
const IDENTITY_LOCK = 'nightjar-identity'

export interface RestoreDeps {
  keys: KeyStore
  sessions: SessionStore
  contacts: ContactStore
  sentinel: Sentinel
  lock: Lock
}

/** Stage an opened backup as this device's identity. The caller MUST reload the
 *  app afterwards (a clean re-bootstrap is the only supported path back). */
export async function stageRestore(deps: RestoreDeps, payload: BackupPayload): Promise<void> {
  await deps.lock.withLock(IDENTITY_LOCK, async () => {
    await deps.sessions.wipeAll()
    await deps.keys.delete(PREKEYS_KEY)
    await deps.keys.put(RESTORE_PENDING_KEY, Uint8Array.from([1]))
    await deps.contacts.replaceAllFromBackup(payload.contacts)
    await deps.keys.put(IDENTITY_KEY, serializeIdentity(payload.identity))
    await deps.sentinel.mark()
  })
}

export async function pendingRestore(keys: KeyStore): Promise<boolean> {
  return (await keys.get(RESTORE_PENDING_KEY)) !== null
}

export async function clearPendingRestore(keys: KeyStore): Promise<void> {
  await keys.delete(RESTORE_PENDING_KEY)
}
