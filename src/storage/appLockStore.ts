// Stateful app-lock manager (P10c). Owns the persisted LockRecord and the in-RAM
// Local Data Key (LDK). The mandatory app-lock's whole security rests here:
//   - the LDK is generated at enrollment, wrapped under each method, and ONLY the
//     wraps are persisted (never the LDK itself);
//   - `enroll` requires at least one KNOWLEDGE factor (passphrase/PIN), so a lost
//     biometric authenticator can never be the sole path in (which would be a
//     permanent lockout);
//   - while locked the LDK is not in RAM, so history/contacts cannot be read;
//   - `reset` deletes the record for the forgot-secret escape (the caller wipes
//     the encrypted data first, since it is unreadable without the LDK anyway).
//
// Sub-keys for the actual at-rest uses (history body, history index, contacts) are
// derived from the LDK on demand and are only available while unlocked.

import {
  type Argon2Kdf,
  type BioWrap,
  type KnowledgeWrap,
  type LockRecord,
  type WrapRecord,
  AppLockAuthError,
  argon2idKdf,
  decodeLockRecord,
  encodeLockRecord,
  generateLdk,
  subKey,
  unwrapBiometric,
  unwrapKnowledge,
  wrapBiometric,
  wrapKnowledge,
} from '../crypto/appLock'
import { INFO_CONTACTS, INFO_HISTORY_BODY, INFO_HISTORY_INDEX } from '../crypto/constants'
import type { KeyStore } from './keystore'
import type { Lock } from './lock'

/** KeyStore key holding the LockRecord. Exported so boot + restore reference one
 *  constant (the red-team caught a name-drift bug where restore deleted the wrong
 *  key and left a user stuck at the unlock screen). */
export const HISTORY_LOCK_KEY = 'history.lock.v1'
const APPLOCK_LOCK = 'nightjar-applock'

export type LockStatus = 'unconfigured' | 'locked' | 'unlocked'

export interface EnrollKnowledge {
  kind: 'pass' | 'pin'
  secret: string
}
export interface EnrollBiometric {
  kind: 'bio'
  credentialId: Uint8Array
  prfSecret: Uint8Array
}
export type EnrollMethod = EnrollKnowledge | EnrollBiometric

/** Thrown when a caller reaches an LDK-requiring operation while locked. Given the
 *  gate (no messaging surface renders while locked), this indicates a logic error,
 *  not a user condition. */
export class AppLockedError extends Error {
  constructor() {
    super('app-lock: the local data key is not available (locked)')
    this.name = 'AppLockedError'
  }
}

const isKnowledge = (m: EnrollMethod): m is EnrollKnowledge => m.kind === 'pass' || m.kind === 'pin'

export class AppLockStore {
  private ldk: Uint8Array | null = null

  constructor(
    private readonly keys: KeyStore,
    private readonly lock: Lock,
    private readonly kdf: Argon2Kdf = argon2idKdf,
  ) {}

  get isUnlocked(): boolean {
    return this.ldk !== null
  }

  async isConfigured(): Promise<boolean> {
    return (await this.keys.get(HISTORY_LOCK_KEY)) !== null
  }

  async status(): Promise<LockStatus> {
    if (this.ldk) return 'unlocked'
    return (await this.isConfigured()) ? 'locked' : 'unconfigured'
  }

  private async loadRecord(): Promise<LockRecord | null> {
    const b = await this.keys.get(HISTORY_LOCK_KEY)
    return b ? decodeLockRecord(b) : null
  }

  /** Which methods are enrolled (for the unlock UI: show a biometric button etc). */
  async methods(): Promise<Array<WrapRecord['kind']>> {
    const rec = await this.loadRecord()
    return rec ? rec.methods.map((m) => m.kind) : []
  }

  /**
   * First-time enrollment. Generates the LDK, wraps it under every supplied
   * method, persists the record in ONE write, and leaves the LDK resident
   * (unlocked). Requires >=1 knowledge factor. Runs under a cross-tab lock with a
   * re-check so two tabs cannot enroll divergent records.
   */
  async enroll(methods: EnrollMethod[]): Promise<void> {
    if (!methods.some(isKnowledge)) throw new Error('app-lock: a passphrase or PIN is required')
    await this.lock.withLock(APPLOCK_LOCK, async () => {
      if (await this.isConfigured()) throw new Error('app-lock: already configured')
      const ldk = generateLdk()
      const wraps: WrapRecord[] = []
      for (const m of methods) {
        wraps.push(
          isKnowledge(m)
            ? await wrapKnowledge(ldk, m.secret, m.kind, { kdf: this.kdf })
            : wrapBiometric(ldk, m.credentialId, m.prfSecret),
        )
      }
      await this.keys.put(HISTORY_LOCK_KEY, encodeLockRecord({ version: 1, methods: wraps }))
      this.ldk = ldk
    })
  }

  /** Unlock with a typed passphrase/PIN. Tries each enrolled knowledge wrap; sets
   *  the LDK on the first that authenticates, else throws AppLockAuthError. */
  async unlockWithSecret(secret: string): Promise<void> {
    const rec = await this.loadRecord()
    if (!rec) throw new Error('app-lock: not configured')
    const knowledge = rec.methods.filter((m): m is KnowledgeWrap => m.kind === 'pass' || m.kind === 'pin')
    if (knowledge.length === 0) throw new Error('app-lock: no knowledge factor enrolled')
    for (const w of knowledge) {
      try {
        this.ldk = await unwrapKnowledge(w, secret, this.kdf)
        return
      } catch {
        /* try the next knowledge wrap */
      }
    }
    throw new AppLockAuthError()
  }

  /** Unlock with a biometric PRF secret (the UI runs the WebAuthn assertion,
   *  verifies user-verification, and passes the derived prfSecret). */
  async unlockWithBiometric(prfSecret: Uint8Array): Promise<void> {
    const rec = await this.loadRecord()
    if (!rec) throw new Error('app-lock: not configured')
    const bio = rec.methods.find((m): m is BioWrap => m.kind === 'bio')
    if (!bio) throw new Error('app-lock: no biometric enrolled')
    this.ldk = unwrapBiometric(bio, prfSecret)
  }

  /** The credential id for the enrolled biometric, or null. The UI needs it to
   *  target the WebAuthn assertion. */
  async biometricCredentialId(): Promise<Uint8Array | null> {
    const rec = await this.loadRecord()
    const bio = rec?.methods.find((m): m is BioWrap => m.kind === 'bio')
    return bio ? bio.credentialId : null
  }

  /** Clear the LDK from RAM (idle-lock / "lock now"). Reusable, unlike a teardown. */
  lockNow(): void {
    this.ldk = null
  }

  private requireLdk(): Uint8Array {
    if (!this.ldk) throw new AppLockedError()
    return this.ldk
  }

  /** Sub-keys for the at-rest uses (only while unlocked). */
  historyBodyKey(): Uint8Array {
    return subKey(this.requireLdk(), INFO_HISTORY_BODY)
  }
  historyIndexKey(): Uint8Array {
    return subKey(this.requireLdk(), INFO_HISTORY_INDEX)
  }
  contactsKey(): Uint8Array {
    return subKey(this.requireLdk(), INFO_CONTACTS)
  }

  /** Re-wrap the LDK under a new knowledge secret (change PIN/passphrase). Must be
   *  unlocked. Replaces the existing knowledge wrap, keeping any biometric. */
  async changeKnowledge(kind: 'pass' | 'pin', secret: string): Promise<void> {
    const ldk = this.requireLdk()
    await this.lock.withLock(APPLOCK_LOCK, async () => {
      const rec = await this.loadRecord()
      if (!rec) throw new Error('app-lock: not configured')
      const others = rec.methods.filter((m) => m.kind === 'bio')
      const fresh = await wrapKnowledge(ldk, secret, kind, { kdf: this.kdf })
      await this.keys.put(HISTORY_LOCK_KEY, encodeLockRecord({ version: 1, methods: [fresh, ...others] }))
    })
  }

  /** Add or replace the biometric wrap (must be unlocked). */
  async addBiometric(credentialId: Uint8Array, prfSecret: Uint8Array): Promise<void> {
    const ldk = this.requireLdk()
    await this.lock.withLock(APPLOCK_LOCK, async () => {
      const rec = await this.loadRecord()
      if (!rec) throw new Error('app-lock: not configured')
      const others = rec.methods.filter((m) => m.kind !== 'bio')
      const bio = wrapBiometric(ldk, credentialId, prfSecret)
      await this.keys.put(HISTORY_LOCK_KEY, encodeLockRecord({ version: 1, methods: [...others, bio] }))
    })
  }

  /** Remove the biometric wrap (a knowledge factor always remains; the biometric
   *  can never be the sole factor, so this can never orphan the LDK). */
  async removeBiometric(): Promise<void> {
    await this.lock.withLock(APPLOCK_LOCK, async () => {
      const rec = await this.loadRecord()
      if (!rec) return
      const remaining = rec.methods.filter((m) => m.kind !== 'bio')
      if (!remaining.some((m) => m.kind === 'pass' || m.kind === 'pin')) {
        throw new Error('app-lock: cannot remove the last knowledge factor')
      }
      await this.keys.put(HISTORY_LOCK_KEY, encodeLockRecord({ version: 1, methods: remaining }))
    })
  }

  /** Forget-secret escape: delete the lock record and clear the LDK. The caller
   *  MUST wipe the encrypted at-rest data first (it is unreadable without the LDK,
   *  but a clean wipe avoids orphaned ciphertext). Returns to `unconfigured`. */
  async reset(): Promise<void> {
    await this.lock.withLock(APPLOCK_LOCK, async () => {
      await this.keys.delete(HISTORY_LOCK_KEY)
      this.ldk = null
    })
  }
}
