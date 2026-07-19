// A ratchet session bound to durable storage and the single-writer lock. This
// is where the P2 pure state machine meets the runtime, and where the section
// 5.3 discipline becomes real rather than just a property of the API shape:
//
//   Every encrypt/decrypt runs INSIDE the lock, and always reloads the latest
//   persisted state, computes the pure transition, and PERSISTS the new state
//   BEFORE returning:
//     - decrypt: ratchetDecrypt throws on a forged/replayed/oversized packet, so
//       we never reach the save -> the stored state is unchanged (commit only on
//       AEAD success), and the plaintext is only returned after the advance is
//       durable (never shown before persisted).
//     - encrypt: the advanced state is persisted before the envelope is returned
//       to the caller (commit before release), so a crash cannot yield an
//       envelope whose ratchet advance was lost; a retry re-sends identical bytes.
//
// The lock (Web Locks where available) serializes these critical sections within
// and across tabs, so a load->compute->save can never interleave with another.

import {
  type MessageHeader,
  type RatchetState,
  deserializeRatchet,
  ratchetDecrypt,
  ratchetEncrypt,
  serializeRatchet,
} from '../crypto/ratchet'
import type { Lock } from '../storage/lock'
import type { SessionStore } from '../storage/sessionStore'

export class RatchetSession {
  private constructor(
    private readonly peerId: string,
    private readonly store: SessionStore,
    private readonly lock: Lock,
  ) {}

  /** Bind to an already-persisted session (e.g. after a reload). */
  static open(peerId: string, store: SessionStore, lock: Lock): RatchetSession {
    return new RatchetSession(peerId, store, lock)
  }

  /** Persist a freshly-initialised ratchet state and bind to it. */
  static async create(
    peerId: string,
    initial: RatchetState,
    store: SessionStore,
    lock: Lock,
  ): Promise<RatchetSession> {
    await store.save(peerId, serializeRatchet(initial))
    return new RatchetSession(peerId, store, lock)
  }

  async encrypt(plaintext: Uint8Array): Promise<{ header: MessageHeader; ciphertext: Uint8Array }> {
    return this.lock.withLock(this.lockName(), async () => {
      const state = await this.loadState()
      const { state: next, header, ciphertext } = ratchetEncrypt(state, plaintext)
      await this.store.save(this.peerId, serializeRatchet(next)) // commit BEFORE releasing the envelope
      return { header, ciphertext }
    })
  }

  // At-most-once: the advanced state is committed BEFORE the plaintext is
  // returned (never shown before persisted). Tradeoff: if the caller crashes
  // after this returns but before durably CONSUMING the plaintext, a redelivered
  // envelope fails to decrypt (nr advanced, the in-order key consumed). P4 closes
  // this: the transport dedups redelivered envelopes ABOVE the ratchet (by
  // message id / (dhPub,n)) and acks the server only after durable consume, with
  // the dedup entry persisted in the SAME transaction as the snapshot (DESIGN 5.3).
  async decrypt(header: MessageHeader, ciphertext: Uint8Array): Promise<Uint8Array> {
    return this.lock.withLock(this.lockName(), async () => {
      const state = await this.loadState()
      // Throws on a forged/replayed/oversized message -> we never save -> the
      // persisted state is left untouched.
      const { state: next, plaintext } = ratchetDecrypt(state, header, ciphertext)
      await this.store.save(this.peerId, serializeRatchet(next)) // commit BEFORE returning plaintext
      return plaintext
    })
  }

  private lockName(): string {
    return `nightjar-session:${this.peerId}`
  }

  private async loadState(): Promise<RatchetState> {
    const snap = await this.store.load(this.peerId)
    if (!snap) throw new Error(`no ratchet session for peer ${this.peerId}`)
    return deserializeRatchet(snap)
  }
}
