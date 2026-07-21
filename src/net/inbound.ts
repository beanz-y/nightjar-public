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
import { decodeMessage } from '../crypto/message'
import { deserializeRatchet, initRatchetResponder, pruneSkippedKeys, ratchetDecrypt, serializeRatchet } from '../crypto/ratchet'
import { initialMessageId, x3dhRespond } from '../crypto/x3dh'
import { type ContactStore, KeyConflictError } from '../trust/contactStore'
import { decryptOrder, promoteSession, updateSession } from '../session/sessionBook'
import type { HistoryStore } from '../storage/historyStore'
import type { PrekeyStore } from '../storage/prekeyStore'
import type { Lock } from '../storage/lock'
import type { HistoryRecord, SessionStore } from '../storage/sessionStore'
import { type Envelope, b64encode } from '../wire/codec'

export type InboundResult =
  | {
      kind: 'delivered'
      peerId: string
      plaintext: Uint8Array
      consumedOpk: boolean
      /** P10d: this inbound TEXT was already deleted-for-everyone (its delete
       *  control arrived earlier and left a tombstone), so it was NOT persisted
       *  and the caller must NOT render it. The ratchet still advanced and the
       *  envelope is acked (it decrypted); only the display + storage are skipped. */
      suppressed?: boolean
    }
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
  /** Persistent history (P10b). When present, a persistable inbound message is
   *  sealed and written in the SAME transaction as the ratchet advance + dedup
   *  marker, so an acked message is always durably in history. Absent in tests
   *  and pre-P10 callers (persistence simply skipped). */
  history?: HistoryStore
}

const lockName = (peerId: string) => `nightjar-session:${peerId}`

/** A rejection that is permanent, so the envelope is acked-and-dropped rather
 *  than retried (a replayed initial). */
class PermanentReject extends Error {}

/** A message DECRYPTED fine but could not be durably persisted (history seal or
 *  the atomic commit failed). It must be retried on redelivery, NOT counted
 *  toward the poison bound: poison-dropping a decryptable message would ack-and-
 *  lose real content, violating the "no ack-without-history" invariant. Thrown
 *  only after a session authenticated, so it is never confused with a decrypt
 *  miss (a genuinely undecryptable envelope still bumps toward the poison drop). */
class HistoryPersistError extends Error {}

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
      // A post-decrypt persistence failure: retry on redelivery, but NEVER count
      // it toward the poison bound (the message decrypted, so dropping it would be
      // silent content loss). Not acked -> the relay redelivers within its TTL.
      if (e instanceof HistoryPersistError) throw e
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

/** What a just-decrypted inbound plaintext does to persistent history, decided
 *  under the per-peer lock and applied ATOMICALLY in the same commit as the
 *  ratchet advance + dedup marker (so an acked message is always durably reflected
 *  in history):
 *   - `put`      persist this message (non-ephemeral text, or legacy plain text);
 *   - `delete`   this was a delete-for-everyone control -> remove the target row
 *                and record its tombstone (P10d);
 *   - `suppress` this text was ALREADY deleted (a tombstone exists) -> do not
 *                persist and do not render;
 *   - `none`     nothing to persist (ephemeral / malformed / no history wired). */
type HistoryPlan =
  | { kind: 'put'; row: HistoryRecord }
  | { kind: 'delete'; key: string }
  | { kind: 'suppress' }
  | { kind: 'none' }

// Classify the plaintext for history. The persist gate FAILS CLOSED (P10e):
// persist ONLY an explicitly non-ephemeral structured text or a legacy (pre-P10)
// plain-text message; an ephemeral text, a delete control, or a malformed record is
// never persisted. decodeMessage is total, so this never throws for parsing
// reasons. A tombstone check (P10d) makes a text whose delete already arrived a
// `suppress`, and a delete control a `delete` op targeting the opaque history key
// of (peer, 'in', targetContentId). All history work needs the LDK-backed
// HistoryStore; without it (tests / pre-P10 callers) everything is `none`.
async function planHistory(
  deps: InboundDeps,
  from: string,
  seenId: string,
  plaintext: Uint8Array,
): Promise<HistoryPlan> {
  if (!deps.history) return { kind: 'none' }
  const decoded = decodeMessage(plaintext)
  if (decoded.kind === 'text') {
    if (decoded.ephemeral) return { kind: 'none' }
    const id = bytesToHex(decoded.id)
    const key = deps.history.storageKey(from, 'in', id)
    // A delete-for-everyone for this id may have arrived first: suppress it.
    if (await deps.store.hasTombstone(key)) return { kind: 'suppress' }
    return { kind: 'put', row: deps.history.seal({ id, peerId: from, dir: 'in', ts: deps.now, text: decoded.body }) }
  }
  if (decoded.kind === 'legacy') {
    // Legacy (pre-P10) plain text has no content id; key the row on the transport
    // envelope id so a redelivery still upserts the same row. Legacy messages are
    // never a delete target (deletes only address NJM1 content ids), so no tombstone
    // check is needed.
    return { kind: 'put', row: deps.history.seal({ id: seenId, peerId: from, dir: 'in', ts: deps.now, text: decoded.body }) }
  }
  if (decoded.kind === 'delete') {
    // Remove the (inbound-from-this-peer) target and tombstone it. The compound key
    // (this peer AND dir='in' AND the target content id) means a delete from a peer
    // can only remove a message THEY sent us, never our own or another peer's.
    return { kind: 'delete', key: deps.history.storageKey(from, 'in', bytesToHex(decoded.id)) }
  }
  return { kind: 'none' } // malformed -> clean-ignore
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
  // (glare/re-establishment safety), then commit book + seen + replay + history
  // atomically. Sealing happens before the commit so the history row rides the
  // same transaction (ack only after durable history). A seal-or-commit failure
  // is raised as HistoryPersistError so it is retried on redelivery and never
  // poison-dropped (the message decrypted; losing it would break no-ack-without-
  // history), and the OPK/contact steps below are skipped (session not committed).
  const book = promoteSession(await store.loadBook(from), serializeRatchet(state), now)
  let suppressed = false
  try {
    const plan = await planHistory(deps, from, env.id, plaintext)
    suppressed = plan.kind === 'suppress'
    await store.saveBookWithSeenReplay(
      from,
      book,
      env.id,
      initId,
      plan.kind === 'put' ? plan.row : undefined,
      plan.kind === 'delete' ? { key: plan.key } : undefined,
    )
  } catch (e) {
    throw new HistoryPersistError(e instanceof Error ? e.message : String(e))
  }

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
  return { kind: 'delivered', peerId: from, plaintext, consumedOpk, ...(suppressed ? { suppressed: true } : {}) }
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
  // wrong session throws (leaving its state untouched) and we move on. Only the
  // DECRYPT is inside this loop's catch: a persistence failure must not be
  // mistaken for a decrypt miss (that would poison-drop a decryptable message).
  let matched: { sid: string; state: ReturnType<typeof deserializeRatchet>; plaintext: Uint8Array } | null = null
  let lastErr: unknown = new Error('inbound: message did not match any session')
  for (const s of decryptOrder(book)) {
    try {
      const { state, plaintext } = ratchetDecrypt(deserializeRatchet(s.snapshot, now), env.header, env.ciphertext, now)
      matched = { sid: s.id, state, plaintext }
      break
    } catch (e) {
      lastErr = e
    }
  }
  if (!matched) throw lastErr instanceof Error ? lastErr : new Error(String(lastErr))

  // A session authenticated. Expire aged skipped keys on the state we persist
  // (DESIGN 5.3/14: the count cap lives in the ratchet; the time bound is enforced
  // here, where a real clock exists), seal the message for history (if
  // persistable), and commit the advance + dedup + history in one transaction. A
  // seal-or-commit failure is a HistoryPersistError (retry on redelivery, never
  // poison-dropped), NOT a decrypt miss.
  const { state: pruned } = pruneSkippedKeys(matched.state, now)
  const advanced = updateSession(book, matched.sid, serializeRatchet(pruned), now)
  let suppressed = false
  try {
    const plan = await planHistory(deps, from, env.id, matched.plaintext)
    suppressed = plan.kind === 'suppress'
    await store.saveBookWithSeen(
      from,
      advanced,
      env.id,
      plan.kind === 'put' ? plan.row : undefined,
      plan.kind === 'delete' ? { key: plan.key } : undefined,
    )
  } catch (e) {
    throw new HistoryPersistError(e instanceof Error ? e.message : String(e))
  }
  return { kind: 'delivered', peerId: from, plaintext: matched.plaintext, consumedOpk: false, ...(suppressed ? { suppressed: true } : {}) }
}
