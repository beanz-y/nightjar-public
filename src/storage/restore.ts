// Restore staging (P8, DESIGN 8.3) and move staging (Phase D). Turning an opened
// backup or move file into this device's identity is a multi-write operation
// with crash windows, so it is ordered for fail-safety around ONE invariant:
//
//   THE IDENTITY WRITE IS THE COMMIT POINT. Step 1 DELETES any identity already
//   present, so "an identity exists" is true only after the final write. A crash
//   anywhere before it leaves no identity + a marked sentinel, which boot routes
//   to the restore screen, and the user simply re-runs the import; wipe-first +
//   blind-overwrite writes make the re-run converge. Without the delete this
//   invariant was FALSE on the onboarding path: a fresh device persists a real
//   throwaway identity before onboarding ever renders, and a crash mid-stage
//   would boot that identity with the restore's staged data and RESTORE_PENDING
//   attributed to it (red-team finding, shipped-bug class).
//
// Order within a stage:
//   1. delete IDENTITY (the invariant), wipe session-layer state (old
//      sessions/dedup/outbox/prekeys belong to a dead ratchet world), and with
//      it the persistent history rows (sessions.wipeAll clears them);
//   2. set RESTORE_PENDING (BEFORE the identity: the flag must already be
//      durable when a loadable identity first exists, so the forced fresh-
//      prekey publish can never be skipped by a crash);
//   3. write contacts (and for a move: nicknames, deletion markers, the
//      refresh-ping list, and every history row re-sealed under this device's
//      lock, in bounded durable batches);
//   4. write the identity + sentinel (the commit point);
//   5. the caller reloads; after the next authenticated connect the flag is
//      consumed by client.reregister() (fresh SPK + OPKs, server-side
//      hard-invalidation of the old bundle AND of this user's fetcher-side
//      one-time-prekey vends) and cleared ONLY on success.
//
// The whole staging runs under the same cross-tab lock as identity bootstrap.
// (The lock serializes stagers; it does not re-check state in between, and does
// not need to: each stage is wipe-first, so sequential double-staging converges.)

import type { BackupPayload } from '../crypto/backup'
import { serializeIdentity } from '../crypto/identity'
import type { MovePayload } from '../crypto/move'
import type { ContactStore } from '../trust/contactStore'
import { HISTORY_LOCK_KEY } from './appLockStore'
import type { HistoryMessage, HistoryStore } from './historyStore'
import { IDENTITY_KEY } from './identityStore'
import type { KeyStore } from './keystore'
import type { Lock } from './lock'
import type { Sentinel } from './persist'
import { PREKEYS_KEY } from './prekeyStore'
import type { SessionStore } from './sessionStore'

export const RESTORE_PENDING_KEY = 'restore.pending.v1'
const IDENTITY_LOCK = 'nightjar-identity'
/** Rows per durable import transaction: large enough to amortize commit cost,
 *  small enough that progress is visible and memory stays flat. */
const MOVE_IMPORT_BATCH = 500


export interface RestoreDeps {
  keys: KeyStore
  sessions: SessionStore
  contacts: ContactStore
  sentinel: Sentinel
  lock: Lock
}

/** Stage an opened backup as this device's identity, wiping any prior lock so the
 *  device becomes UNCONFIGURED and re-enrolls (used when the caller has NOT already
 *  set up a lock). The caller MUST reload afterwards. */
export async function stageRestore(deps: RestoreDeps, payload: BackupPayload): Promise<void> {
  await deps.lock.withLock(IDENTITY_LOCK, async () => {
    await deps.keys.delete(IDENTITY_KEY) // the commit-point invariant (see header)
    await deps.sessions.wipeAll() // also clears the history store (P10c)
    await deps.keys.delete(PREKEYS_KEY)
    // Delete the app-lock record so a restored device is genuinely UNCONFIGURED
    // and re-enrolls a fresh lock (the red-team caught that leaving this stranded a
    // forgotten-secret user at an unopenable unlock screen). The old history rows
    // are wiped above and were unreadable without the old LDK regardless.
    await deps.keys.delete(HISTORY_LOCK_KEY)
    await deps.keys.put(RESTORE_PENDING_KEY, Uint8Array.from([1]))
    await deps.contacts.replaceAllFromBackup(payload.contacts)
    await deps.keys.put(IDENTITY_KEY, serializeIdentity(payload.identity))
    await deps.sentinel.mark()
  })
}

/** Stage an opened backup when the app-lock is ALREADY enrolled or unlocked in
 *  this session (P10c restore flow): the LDK is resident, so the contact import
 *  is encrypted at rest. Does NOT touch the lock record. The caller MUST reload
 *  afterwards (into the unlock screen). */
export async function stageRestoreEnrolled(deps: RestoreDeps, payload: BackupPayload): Promise<void> {
  await deps.lock.withLock(IDENTITY_LOCK, async () => {
    await deps.keys.delete(IDENTITY_KEY) // the commit-point invariant (see header)
    await deps.sessions.wipeAll()
    await deps.keys.delete(PREKEYS_KEY)
    await deps.keys.put(RESTORE_PENDING_KEY, Uint8Array.from([1]))
    await deps.contacts.replaceAllFromBackup(payload.contacts) // encrypted under the resident LDK
    await deps.keys.put(IDENTITY_KEY, serializeIdentity(payload.identity))
    await deps.sentinel.mark()
  })
}

/** Stage an opened MOVE file (Phase D): identity + contacts + nicknames +
 *  deletion markers + every saved message, the latter re-sealed under THIS
 *  device's resident LDK (the lock must already be enrolled or unlocked).
 *
 *  CONSUMES payload.messages destructively (batches are spliced off as they
 *  commit) so a large import's parsed rows become collectible as they land
 *  instead of all being pinned until the end. Any batch failure (quota, disk)
 *  rejects BEFORE the identity write, so a partial import can never read as a
 *  completed move; the caller surfaces the error and the user re-runs it.
 *  The caller MUST reload afterwards (into the unlock screen). */
export async function stageMove(
  deps: RestoreDeps,
  history: HistoryStore,
  payload: MovePayload,
  onProgress?: (done: number, total: number) => void,
): Promise<void> {
  await deps.lock.withLock(IDENTITY_LOCK, async () => {
    await deps.keys.delete(IDENTITY_KEY) // the commit-point invariant (see header)
    await deps.sessions.wipeAll()
    await deps.keys.delete(PREKEYS_KEY)
    await deps.keys.put(RESTORE_PENDING_KEY, Uint8Array.from([1]))
    await deps.contacts.replaceAllForMove(payload.contacts, payload.aliases, payload.dismissals)
    // The refresh-ping list: every imported contact EXCEPT dismissed peers (a
    // deleted conversation must not be re-established by the move itself). Sealed
    // with the rest of the contact data, not left beside the identity in the
    // clear: it is a roster of everyone just imported (8.5).
    const refresh = payload.contacts.map((c) => c.peerId).filter((p) => !payload.dismissals[p])
    await deps.contacts.setMoveRefresh(refresh)
    const total = payload.messages.length
    let done = 0
    while (payload.messages.length > 0) {
      const batch = payload.messages.splice(0, MOVE_IMPORT_BATCH).map((m) => {
        const msg: HistoryMessage = { id: m.id, peerId: m.peer, dir: m.dir, ts: m.ts, text: m.text }
        if (m.status) msg.status = m.status
        return history.seal(msg, m.failed)
      })
      await deps.sessions.historyPutMany(batch)
      done += batch.length
      onProgress?.(done, total)
      // Yield so the progress line paints; the seal loop is otherwise sync CPU.
      await new Promise((r) => setTimeout(r, 0))
    }
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
