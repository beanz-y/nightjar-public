// Inbound message processing (P4 + the P5 glare fix + poison drop). Turns a
// delivered envelope into plaintext, realising the receive-side discipline of
// DESIGN 4.3 / 5.3 over a per-peer SESSION BOOK (docs/SESSION-GLARE.md):
//
//   - Everything runs under the per-peer lock (single writer) so a load ->
//     decrypt -> persist critical section cannot interleave with a send.
//   - A message id already durably consumed (or poison-dropped) short-circuits to
//     `duplicate`, so a redelivery is ack-and-dropped, never reprocessed.
//   - An INITIAL (X3DH) message is checked against the persisted replay guard
//     (H(initial header)) and, on success, PROMOTED to the book's current session
//     (the old current is archived, not clobbered): this is what makes glare and
//     re-establishment safe.
//   - A NORMAL message is tried against each session in the book (current first);
//     the one whose AEAD authenticates wins and only its slot advances. A message
//     encrypted on the other arm of a glare, or in flight across a
//     re-establishment, still decrypts.
//   - ratchetDecrypt / x3dhRespond throw on a forged/replayed/unbound message, so
//     we only ever persist on AEAD success, and the dedup entry is written in the
//     SAME transaction as the session book (atomic).
//   - A message that never decrypts is normally NOT acked, so a legitimately
//     reordered message (a normal arriving before its initial) is retried on
//     redelivery. After POISON_MAX_ATTEMPTS it is marked seen and dropped, so a
//     permanently-undecryptable envelope is not redelivered forever (DESIGN 5.3).

import { bytesToHex } from '@noble/hashes/utils'
import { POISON_MAX_ATTEMPTS } from '../crypto/constants'
import { type Identity, deriveUserId } from '../crypto/identity'
import { deserializeRatchet, initRatchetResponder, pruneSkippedKeys, ratchetDecrypt, serializeRatchet } from '../crypto/ratchet'
import { initialMessageId, x3dhRespond } from '../crypto/x3dh'
import { type ContactStore, KeyConflictError } from '../trust/contactStore'
import { decryptOrder, promoteSession, updateSession } from '../session/sessionBook'
import type { PrekeyStore } from '../storage/prekeyStore'
import type { Lock } from '../storage/lock'
import type { SessionStore } from '../storage/sessionStore'
import { type Envelope, b64encode } from '../wire/codec'

export type InboundResult =
  | { kind: 'delivered'; peerId: string; plaintext: Uint8Array; consumedOpk: boolean }
  | { kind: 'duplicate'; peerId: string }
  /** Permanently un-processable (replayed, or never decrypted after the poison
   *  bound). The caller ACKS so the relay stops redelivering. */
  | { kind: 'dropped'; peerId: string; reason: string }

export interface InboundDeps {
  me: Identity
  prekeys: PrekeyStore
  store: SessionStore
  lock: Lock
  now: number
  /** Contact trust store (DESIGN 6). When present it drives first-contact
   *  recording and fails closed on a stored-key conflict. */
  contacts?: ContactStore
  /** Explicit pinned peer IK_sig, used only when no contact store is supplied. */
  knownPeerIkSig?: Uint8Array
}

const lockName = (peerId: string) => `nightjar-session:${peerId}`

/** A rejection that is permanent, so the envelope is acked-and-dropped rather
 *  than retried (a replayed initial). */
class PermanentReject extends Error {}

/**
 * Process one delivered envelope from `from`. Returns the plaintext (to hand to
 * the app, then ack), `duplicate` (already consumed; just re-ack), or `dropped`
 * (permanently un-processable; ack to stop redelivery). Throws only for a
 * transient failure the caller must NOT ack (it will be retried on redelivery),
 * or a KeyConflictError to surface loudly.
 */
export async function processInbound(env: Envelope, from: string, deps: InboundDeps): Promise<InboundResult> {
  const { store, lock } = deps
  return lock.withLock(lockName(from), async () => {
    if (await store.hasSeen(env.id)) return { kind: 'duplicate', peerId: from }

    try {
      const res = env.kind === 'initial' ? await handleInitial(env, from, deps) : await handleNormal(env, from, deps)
      // A message that had transiently failed before (e.g. a normal that arrived
      // ahead of its initial) can now drop its failure counter.
      void store.clearFailure(env.id).catch(() => {})
      return res
    } catch (e) {
      if (e instanceof KeyConflictError) throw e // surface loudly; do not ack, do not count
      if (e instanceof PermanentReject) return dropAndAck(store, env.id, from, e.message)
      // Generic decrypt / x3dh / no-session failure: retry a bounded number of
      // times (a reordered message may become decryptable once its initial lands),
      // then drop so it is not redelivered forever.
      const attempts = await store.bumpFailure(env.id)
      if (attempts >= POISON_MAX_ATTEMPTS) {
        return dropAndAck(store, env.id, from, e instanceof Error ? e.message : String(e))
      }
      throw e
    }
  })
}

// Mark the envelope id consumed so a redelivery short-circuits to `duplicate`,
// and tell the caller to ack it (stopping the relay from redelivering forever).
async function dropAndAck(store: SessionStore, envId: string, from: string, reason: string): Promise<InboundResult> {
  await store.markSeen(envId)
  await store.clearFailure(envId).catch(() => {})
  return { kind: 'dropped', peerId: from, reason }
}

async function handleInitial(env: Envelope, from: string, deps: InboundDeps): Promise<InboundResult> {
  const { me, prekeys, store, now } = deps
  const ih = env.initialHeader
  if (!ih) throw new Error('inbound: initial envelope missing its initial header')
  // Bind the relay's routing label to the cryptographic identity, so the session
  // is keyed consistently with the `from` that later normal messages use.
  if (deriveUserId(ih.ikSigPub) !== from) {
    throw new Error('inbound: initial header identity does not match sender')
  }

  // Trust (DESIGN 6). The key<->userId binding is enforced above; the contact
  // store adds first-contact recording and a fail-closed guard on the
  // (collision-only) case where a stored key disagrees for the same userId.
  let firstContact = false
  if (deps.contacts) {
    const a = await deps.contacts.assess(from, ih.ikSigPub)
    if (a.outcome === 'conflict') throw new KeyConflictError(from)
    firstContact = a.outcome === 'first-contact'
  }

  const initId = bytesToHex(initialMessageId(ih))
  if (await store.hasReplayedInitial(initId)) throw new PermanentReject('replayed initial message')

  const responder = await prekeys.responderKeys()
  const resp = x3dhRespond(
    me,
    ih,
    { spkPrivById: responder.spkPrivById, opkPrivById: responder.opkPrivById },
    now,
    deps.knownPeerIkSig,
  )
  const spkPriv = responder.spkPrivById.get(ih.spkId)
  const spkPub = responder.spkPubById.get(ih.spkId)
  if (!spkPriv || !spkPub) throw new Error('inbound: unknown signed-prekey id for initial message')

  const state0 = initRatchetResponder(resp.sk, resp.ad, { privateKey: spkPriv, publicKey: spkPub })
  // Throws on AEAD failure -> no persist below, the book is left untouched.
  const { state, plaintext } = ratchetDecrypt(state0, env.header, env.ciphertext, now)

  // Promote the new responder session to current, archiving the prior current
  // (glare/re-establishment safety), then commit book + seen + replay atomically.
  const book = promoteSession(await store.loadBook(from), serializeRatchet(state), now)
  await store.saveBookWithSeenReplay(from, book, env.id, initId)

  // Single-use OPK: consume after the session is durable. A redelivery is caught
  // by hasSeen above, so the OPK is never needed again. Best-effort: the message
  // is already durably consumed, so a consume hiccup must not strand it.
  let consumedOpk = false
  if (ih.opkId !== null) {
    try {
      await prekeys.consumeOpk(ih.opkId)
      consumedOpk = true
    } catch {
      /* best-effort; the private half lingering is benign (single-vend server-side) */
    }
  }
  // Trust-on-first-use: record the peer's key now that a session is durable.
  // A failed write must not poison the already-committed message, but it must
  // not be LOST either (the peer would be unverifiable forever): park it in the
  // pending-trust ledger, flushed on every connect (P8).
  if (firstContact && deps.contacts) {
    try {
      await deps.contacts.recordFirstContact(from, ih.ikSigPub, now)
    } catch {
      const ikSigB64 = b64encode(ih.ikSigPub)
      await deps.contacts
        .mutatePendingTrust((p) => {
          if (!p.records.some((r) => r.peerId === from)) p.records.push({ peerId: from, ikSig: ikSigB64 })
        })
        .catch(() => {})
    }
  }
  return { kind: 'delivered', peerId: from, plaintext, consumedOpk }
}

async function handleNormal(env: Envelope, from: string, deps: InboundDeps): Promise<InboundResult> {
  const { store, now } = deps
  const book = await store.loadBook(from)
  if (!book || book.sessions.length === 0) {
    // No session yet: a normal message ahead of its initial, or on a session we
    // no longer hold. Throw so it is retried (until the poison bound drops it).
    throw new Error(`inbound: no session for ${from} (normal message before initial?)`)
  }

  // Try each session, current first. The one whose AEAD authenticates wins; a
  // wrong session throws (leaving its state untouched) and we move on.
  let lastErr: unknown = new Error('inbound: message did not match any session')
  for (const s of decryptOrder(book)) {
    try {
      const { state, plaintext } = ratchetDecrypt(deserializeRatchet(s.snapshot, now), env.header, env.ciphertext, now)
      // Expire aged skipped keys on the state we are about to persist (DESIGN
      // 5.3/14: the count cap lives in the ratchet; the time bound is enforced
      // here, where a real clock exists).
      const { state: pruned } = pruneSkippedKeys(state, now)
      const advanced = updateSession(book, s.id, serializeRatchet(pruned), now)
      await store.saveBookWithSeen(from, advanced, env.id)
      return { kind: 'delivered', peerId: from, plaintext, consumedOpk: false }
    } catch (e) {
      lastErr = e
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr))
}
