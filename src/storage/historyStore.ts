// Persistent message history at-rest encryption (P10b, DESIGN 8.1/8.3).
//
// History ROWS live in the sessions IndexedDB (so a row commits in the SAME
// transaction as the ratchet advance + dedup marker; see sessionStore.ts). This
// module owns the KEY those rows are sealed with and the per-record AEAD, keeping
// the crypto in one place and the storage layer oblivious to it.
//
// Key hierarchy (a DEK/KEK split so P10c can add an app-lock without touching the
// row format):
//   - a random 32-byte History Master Key (HMK) is the data key; each row's body
//     is XChaCha20-Poly1305'd under key||nonce = HKDF(HMK, FRESH per-record salt,
//     "Nightjar_History_v1"), with the salt stored beside the row.
//   - the HMK itself is stored in the KeyStore (the `nightjar` keyval DB) as a
//     1-byte-tagged record. P10b writes only the UNWRAPPED tag (history is
//     plaintext-at-rest, disclosed in the README/DESIGN). P10c will add a WRAPPED
//     tag (HMK sealed under a PIN/passphrase- or biometric-derived KEK) and gate
//     unlock; the row format and this module's seal/open are unchanged by that.
//
// Write contract (fail-closed): seal/open REQUIRE the HMK in RAM. In P10b the HMK
// is always available (unwrapped, loaded/generated on demand). In P10c a
// configured-but-locked state has no HMK, and seal/open MUST reject rather than
// fall back to plaintext. `ensureKey` is the single place that establishes the
// HMK; a locked P10c app never reaches a receive/persist path (the unlock screen
// gates it), so a fail-closed throw here is a belt-and-braces invariant.

import { HISTORY_FORMAT_VERSION, HISTORY_HMK_BYTES, HISTORY_SALT_BYTES, INFO_HISTORY } from '../crypto/constants'
import {
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
  aeadOpen,
  aeadSeal,
  domainSeparate,
  hkdfSha256,
  randomBytes,
  utf8,
} from '../crypto/primitives'
import type { KeyStore } from './keystore'
import type { Lock } from './lock'
import type { HistoryRow } from './sessionStore'

/** KeyStore key holding the tagged HMK record. */
export const HISTORY_HMK_KEY = 'history.hmk.v1'
const HMK_LOCK = 'nightjar-history-hmk'

// HMK record format tags (first byte of the KeyStore value). P10b only ever
// writes PLAINTEXT; WRAPPED is reserved so P10c is purely additive.
const HMK_TAG_PLAINTEXT = 0x01
const HMK_TAG_WRAPPED = 0x02

const AAD_TAG = 'Nightjar-history-aad-v1'
const decoder = new TextDecoder()

/** The at-rest history key is unavailable: no HMK in RAM and (P10c) the app is
 *  locked. A hard fail, never a plaintext fallback. */
export class HistoryLockedError extends Error {
  constructor() {
    super('history: at-rest key is not available (locked)')
    this.name = 'HistoryLockedError'
  }
}

/** The stored HMK record is not a shape this version understands (corruption, or
 *  a P10c wrapped record reached by a P10b build). */
export class HistoryKeyFormatError extends Error {
  constructor(msg: string) {
    super(msg)
    this.name = 'HistoryKeyFormatError'
  }
}

function encodePlaintextHmk(hmk: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + hmk.length)
  out[0] = HMK_TAG_PLAINTEXT
  out.set(hmk, 1)
  return out
}

/** AAD binds the row to its conversation, DIRECTION, content id, and history
 *  format version, so a sealed body cannot be relabelled to another peer, moved
 *  across the in/out boundary, or given another id and still open. Direction is
 *  load-bearing: an inbound content id is peer-chosen, so without `dir` a peer
 *  could reuse the content id of a message YOU sent and address the same slot as
 *  your outbound row. The version is a dedicated HISTORY format version, NOT the
 *  wire ciphersuite VERSION, so a protocol bump never invalidates stored rows. */
function aadFor(peerId: string, dir: 'in' | 'out', id: string): Uint8Array {
  return domainSeparate(AAD_TAG, utf8(peerId), utf8(dir), utf8(id), Uint8Array.from([HISTORY_FORMAT_VERSION]))
}

export class HistoryStore {
  private hmk: Uint8Array | null = null

  constructor(
    private readonly keys: KeyStore,
    private readonly lock: Lock,
  ) {}

  /** True once the HMK is resident (P10b: after the first ensureKey; P10c: after
   *  an unlock). Used by callers that want to skip persistence when locked. */
  get isUnlocked(): boolean {
    return this.hmk !== null
  }

  /**
   * Make the HMK resident. P10b: load the unwrapped record, or generate + persist
   * one on first use. Runs under a lock with a re-check so two tabs on first use
   * cannot generate divergent HMKs (the second waiter re-reads and reuses the
   * first's). Reaching a WRAPPED record in a P10b build means an app-lock was set
   * by a newer build and this one cannot open it: fail closed, never regenerate
   * (regenerating would orphan every existing row).
   */
  async ensureKey(): Promise<void> {
    if (this.hmk) return
    await this.lock.withLock(HMK_LOCK, async () => {
      if (this.hmk) return
      const stored = await this.keys.get(HISTORY_HMK_KEY)
      if (stored) {
        this.hmk = this.parseHmkRecord(stored)
        return
      }
      const hmk = randomBytes(HISTORY_HMK_BYTES)
      await this.keys.put(HISTORY_HMK_KEY, encodePlaintextHmk(hmk))
      this.hmk = hmk
    })
  }

  private parseHmkRecord(bytes: Uint8Array): Uint8Array {
    if (bytes.length < 1) throw new HistoryKeyFormatError('empty HMK record')
    if (bytes[0] === HMK_TAG_PLAINTEXT) {
      if (bytes.length !== 1 + HISTORY_HMK_BYTES) throw new HistoryKeyFormatError('bad plaintext HMK length')
      return bytes.slice(1)
    }
    if (bytes[0] === HMK_TAG_WRAPPED) {
      // A newer build wrapped the HMK under an app-lock. A P10b build cannot
      // unwrap it; fail closed rather than lose history by regenerating.
      throw new HistoryLockedError()
    }
    throw new HistoryKeyFormatError(`unknown HMK record tag 0x${bytes[0].toString(16)}`)
  }

  /** Forget the in-RAM HMK (P10c "lock now"; also lets tests reset). */
  lockNow(): void {
    this.hmk = null
  }

  private requireKey(): Uint8Array {
    if (!this.hmk) throw new HistoryLockedError()
    return this.hmk
  }

  private deriveKeyNonce(salt: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
    const out = hkdfSha256(this.requireKey(), salt, utf8(INFO_HISTORY), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
    return { key: out.slice(0, XCHACHA_KEY_BYTES), nonce: out.slice(XCHACHA_KEY_BYTES) }
  }

  /** Seal a message body into a storable row. `id` is the content msgId hex for a
   *  structured message, or the transport envelope id for a legacy (pre-P10) one.
   *  Fresh salt per call -> fresh key+nonce, so no keystream is ever reused. */
  async seal(id: string, peerId: string, dir: 'in' | 'out', ts: number, body: string): Promise<HistoryRow> {
    await this.ensureKey()
    const salt = randomBytes(HISTORY_SALT_BYTES)
    const { key, nonce } = this.deriveKeyNonce(salt)
    const ct = aeadSeal(key, nonce, utf8(body), aadFor(peerId, dir, id))
    return { id, peerId, dir, ts, salt, ct }
  }

  /** Open a stored row back into a plaintext message. Throws if the row does not
   *  authenticate (wrong HMK, corruption, or a relabelled peer/dir/id). */
  async open(row: HistoryRow): Promise<{ id: string; dir: 'in' | 'out'; text: string; ts: number }> {
    await this.ensureKey()
    const { key, nonce } = this.deriveKeyNonce(row.salt)
    const body = aeadOpen(key, nonce, row.ct, aadFor(row.peerId, row.dir, row.id))
    return { id: row.id, dir: row.dir, text: decoder.decode(body), ts: row.ts }
  }
}
