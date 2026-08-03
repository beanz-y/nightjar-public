// The retry-receipt (DESIGN 8.10): recovering messages that were lost because one
// side no longer held the session they were encrypted to, while the relay reported
// them delivered to the sender.
//
// The two halves are tested separately because they defend different things:
//   - the ASKING side's throttle is politeness, and only has to be shown to bound
//     an honestly broken conversation;
//   - the ANSWERING side's bounds are the real control, because a hostile requester
//     runs whatever client it likes, so every limit that matters is asserted here
//     against a caller that ignores its own.
//
// The client's transport is never connected, so fire() throws internally and is
// swallowed (the envelope stays queued), exactly as on a real dropped socket. That
// makes the outbox the observable record of what was actually transmitted.

import { beforeEach, describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  MAX_RETRY_LEDGER,
  RETRY_HONOR_MIN_INTERVAL_MS,
  RETRY_REQUEST_MAX_ATTEMPTS,
  RETRY_REQUEST_MIN_INTERVAL_MS,
  RETRY_RESEND_MAX_MESSAGES,
  RETRY_RESEND_WINDOW_MS,
} from '../crypto/constants'
import { type Identity, generateIdentity } from '../crypto/identity'
import { decodeMessage } from '../crypto/message'
import { hash256 } from '../crypto/primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { initRatchetInitiator, serializeRatchet } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore, singleSessionBook } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

const NOW = 1_700_000_000_000
const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

/** The private inbound-driven entry points, reached the way the other client tests
 *  reach `recoverContact`: they are triggered by a decrypted envelope, and there is
 *  no public seam for "a message just arrived that could not be read". */
interface Internals {
  maybeRequestRetry(peer: string, toDevice?: string): Promise<void>
  honorRetryRequest(peer: string, toDevice?: string): Promise<void>
  collectResendable(peer: string, now: number): Promise<Array<{ id: string; text: string; ts: number }>>
}

async function makePeerBundle(): Promise<{ id: Identity; bundle: FetchedBundle }> {
  const id = generateIdentity()
  const own = buildOwnBundle(id, NOW, { spkId: 1, opkStartId: 1, opkCount: 3 })
  return {
    id,
    bundle: {
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opk: own.opks[0],
    },
  }
}

async function harness() {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const store = new MemorySessionStore()
  const prekeys = new PrekeyStore(keys, lock)
  const contacts = new ContactStore(keys, lock)
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'x' }])
  const history = new HistoryStore(appLock)
  const asked: string[] = []
  const exhausted: string[] = []
  const honored: Array<{ peer: string; count: number }> = []
  const client = new NightjarClient(
    identity,
    store,
    prekeys,
    contacts,
    lock,
    {
      onMessage: () => {},
      onRetryRequested: (peer) => asked.push(peer),
      onRetryExhausted: (peer) => exhausted.push(peer),
      onRetryHonored: (peer, count) => honored.push({ peer, count }),
    },
    history,
  )

  // A live session to `peer`, so both halves can encrypt without a directory.
  const seedSession = async (peer: Identity, bundle: FetchedBundle) => {
    const ini = x3dhInitiate(identity, bundle, NOW)
    const state = initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub)
    await store.saveBook(peer.userId, singleSessionBook(serializeRatchet(state), NOW))
  }
  // A persisted message as if it had been sent to (or received from) `peer`.
  const seedRow = async (
    peer: string,
    id: string,
    opts: { dir?: 'in' | 'out'; ts?: number; text?: string; failed?: boolean } = {},
  ) => {
    const dir = opts.dir ?? 'out'
    // Default to "just now": the resend window is measured against the real clock,
    // so a fixture timestamp from years ago would be correctly refused.
    const row = history.seal(
      { id, peerId: peer, dir, ts: opts.ts ?? Date.now(), text: opts.text ?? `body-${id}` },
      opts.failed === true,
    )
    const book = (await store.loadBook(peer)) ?? singleSessionBook('00'.repeat(32) as never, NOW)
    await store.saveBookWithSeen(peer, book, `seed-${dir}-${id}`, row)
  }
  const known = async (peer: Identity) => {
    await contacts.recordFirstContact(peer.userId, peer.ikSig.publicKey, NOW)
  }
  // What was actually put on the wire, minus the seeded dedup entries.
  const queued = async () => (await store.pendingOutbox()).entries

  return { client: client as unknown as Internals, store, history, contacts, seedSession, seedRow, known, queued, asked, exhausted, honored }
}

const idOf = (n: number) => bytesToHex(new Uint8Array(16).fill(n))

describe('retry-receipt: answering a request (the bound that holds)', () => {
  let peer: Identity
  let bundle: FetchedBundle
  beforeEach(async () => {
    const p = await makePeerBundle()
    peer = p.id
    bundle = p.bundle
  })

  it('resends recent messages under their ORIGINAL content ids with FRESH transport ids', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)
    await h.seedRow(peer.userId, idOf(1), { text: 'first' })
    await h.seedRow(peer.userId, idOf(2), { text: 'second' })

    await h.client.honorRetryRequest(peer.userId)

    const out = await h.queued()
    expect(out).toHaveLength(2)
    // Fresh transport ids: reusing the content id would let a receiver that once
    // saw the original ack-and-drop this as a relay duplicate, which is exactly
    // the case being repaired.
    expect(out.map((e) => e.id)).not.toContain(idOf(1))
    expect(out.map((e) => e.id)).not.toContain(idOf(2))
    // Silent: the requesting device just asked, so a push per message would be a
    // notification storm for no benefit.
    expect(out.every((e) => e.silent === true)).toBe(true)
    expect(out.every((e) => e.to === peer.userId)).toBe(true)
    // No NEW history rows: this device already holds these, and re-sealing them
    // would rewrite their timestamps.
    expect((await h.store.historyLoadAll()).length).toBe(2)
    expect(h.honored).toEqual([{ peer: peer.userId, count: 2 }])
  })

  it('honors one request per requester per window, however many arrive', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)
    await h.seedRow(peer.userId, idOf(1))

    await h.client.honorRetryRequest(peer.userId)
    expect(await h.queued()).toHaveLength(1)
    // A requester that ignores its own throttle and asks again immediately.
    await h.client.honorRetryRequest(peer.userId)
    await h.client.honorRetryRequest(peer.userId)
    expect(await h.queued()).toHaveLength(1)
    expect(h.honored).toHaveLength(1)

    // Past the window it is allowed again.
    await h.contacts.mutateRetryState(peer.userId, (r) => {
      r.honoredAt = Date.now() - RETRY_HONOR_MIN_INTERVAL_MS - 1
    })
    await h.client.honorRetryRequest(peer.userId)
    expect(await h.queued()).toHaveLength(2)
  })

  it('never resends more than the message cap, and keeps the NEWEST', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)
    const total = RETRY_RESEND_MAX_MESSAGES + 10
    const base = Date.now() - total
    for (let i = 0; i < total; i++) {
      await h.seedRow(peer.userId, bytesToHex(new Uint8Array(16).fill(i)), { ts: base + i, text: `m${i}` })
    }

    // What the bound actually selected. Asserted here rather than on the outbox,
    // whose envelopes are ciphertext under fresh transport ids by then.
    const picked = await h.client.collectResendable(peer.userId, Date.now())
    expect(picked).toHaveLength(RETRY_RESEND_MAX_MESSAGES)
    // The OLDEST ten were dropped, and the survivors are still oldest-first so they
    // arrive in the order they were written.
    expect(picked[0].text).toBe(`m${total - RETRY_RESEND_MAX_MESSAGES}`)
    expect(picked[picked.length - 1].text).toBe(`m${total - 1}`)
    expect(picked.map((p) => p.ts)).toEqual([...picked.map((p) => p.ts)].sort((a, b) => a - b))

    await h.client.honorRetryRequest(peer.userId)
    expect(await h.queued()).toHaveLength(RETRY_RESEND_MAX_MESSAGES)
    expect(h.honored).toEqual([{ peer: peer.userId, count: RETRY_RESEND_MAX_MESSAGES }])
  })

  it('never reaches back past the window, however old the history is', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)
    const now = Date.now()
    await h.seedRow(peer.userId, idOf(1), { ts: now - RETRY_RESEND_WINDOW_MS - 60_000 }) // too old
    await h.seedRow(peer.userId, idOf(2), { ts: now - 1000 }) // inside

    await h.client.honorRetryRequest(peer.userId)

    expect(await h.queued()).toHaveLength(1)
    expect(h.honored).toEqual([{ peer: peer.userId, count: 1 }])
  })

  it('resends only our OWN messages to THIS peer, and never one marked failed', async () => {
    const h = await harness()
    const other = await makePeerBundle()
    await h.seedSession(peer, bundle)
    await h.seedSession(other.id, other.bundle)
    await h.known(peer)
    await h.seedRow(peer.userId, idOf(1)) // ours to them: resent
    await h.seedRow(peer.userId, idOf(2), { dir: 'in' }) // theirs to us: not ours to resend
    await h.seedRow(peer.userId, idOf(3), { failed: true }) // never left this device
    await h.seedRow(other.id.userId, idOf(4)) // a different conversation entirely

    await h.client.honorRetryRequest(peer.userId)

    const out = await h.queued()
    expect(out).toHaveLength(1)
    expect(out[0].to).toBe(peer.userId)
    expect(h.honored).toEqual([{ peer: peer.userId, count: 1 }])
  })

  it('refuses a requester this device holds no contact record for', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.seedRow(peer.userId, idOf(1))
    // No `known(peer)`: nothing binds this id to anyone here.
    await h.client.honorRetryRequest(peer.userId)
    expect(await h.queued()).toHaveLength(0)
    expect(h.honored).toEqual([])
  })

  it('sends the resend to the device that asked, not to the account', async () => {
    // Once a contact reads on more than one device, the device that could not
    // decrypt is the one that needs the messages back. Answering the ACCOUNT would
    // deliver them to their first device, which was probably never broken, and the
    // asking device would sit there having been told nothing.
    const h = await harness()
    const laptop = await makePeerBundle() // the contact's SECOND device
    await h.seedSession(peer, bundle)
    await h.seedSession(laptop.id, laptop.bundle)
    await h.known(peer)
    await h.seedRow(peer.userId, idOf(1))

    await h.client.honorRetryRequest(peer.userId, laptop.id.userId)

    const out = await h.queued()
    expect(out).toHaveLength(1)
    expect(out[0].to).toBe(laptop.id.userId)
    expect(out[0].to).not.toBe(peer.userId)
    // The user is still told about the PERSON: which of their machines asked is
    // not something worth putting on screen.
    expect(h.honored).toEqual([{ peer: peer.userId, count: 1 }])
  })

  it('bounds the resend per person, not per device', async () => {
    // Otherwise somebody reading on three devices could pull three times the cap by
    // asking from each in turn, and that cap is precisely what limits what a stolen
    // identity is worth.
    const h = await harness()
    const laptop = await makePeerBundle()
    await h.seedSession(peer, bundle)
    await h.seedSession(laptop.id, laptop.bundle)
    await h.known(peer)
    await h.seedRow(peer.userId, idOf(1))

    await h.client.honorRetryRequest(peer.userId, peer.userId)
    expect(await h.queued()).toHaveLength(1)
    // A second device of the SAME person, asking immediately afterwards.
    await h.client.honorRetryRequest(peer.userId, laptop.id.userId)
    expect(await h.queued()).toHaveLength(1)
    expect(h.honored).toHaveLength(1)
  })

  it('reports even when there was nothing to send, so an ask is never invisible', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)
    await h.client.honorRetryRequest(peer.userId)
    expect(await h.queued()).toHaveLength(0)
    expect(h.honored).toEqual([{ peer: peer.userId, count: 0 }])
  })
})

describe('retry-receipt: asking for a resend', () => {
  let peer: Identity
  let bundle: FetchedBundle
  beforeEach(async () => {
    const p = await makePeerBundle()
    peer = p.id
    bundle = p.bundle
  })

  it('queues one request that names nothing, and records the attempt durably', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)

    await h.client.maybeRequestRetry(peer.userId)

    const out = await h.queued()
    expect(out).toHaveLength(1)
    expect(out[0].to).toBe(peer.userId)
    expect(out[0].silent).toBe(true)
    expect(h.asked).toEqual([peer.userId])
    const state = await h.contacts.getRetryState(peer.userId)
    expect(state.attempts).toBe(1)
    expect(typeof state.askedAt).toBe('number')
  })

  it('asks the device whose messages will not open, while throttling per person', async () => {
    // The mirror of the answering side: the ask is addressed to a machine and
    // bounded by a person, so a contact with three broken sessions is asked once.
    const h = await harness()
    const laptop = await makePeerBundle()
    await h.seedSession(peer, bundle)
    await h.seedSession(laptop.id, laptop.bundle)
    await h.known(peer)

    await h.client.maybeRequestRetry(peer.userId, laptop.id.userId)
    const out = await h.queued()
    expect(out).toHaveLength(1)
    expect(out[0].to).toBe(laptop.id.userId)
    expect(h.asked).toEqual([peer.userId])
  })

  it('does not ask the same contact twice inside the window', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)

    await h.client.maybeRequestRetry(peer.userId)
    await h.client.maybeRequestRetry(peer.userId)
    expect(await h.queued()).toHaveLength(1)
    expect(h.asked).toHaveLength(1)
    expect((await h.contacts.getRetryState(peer.userId)).attempts).toBe(1)
  })

  it('stops after the attempt cap and says so instead of asking forever', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)

    // Each round: ask, then age the throttle out as a stuck conversation would.
    for (let i = 0; i < RETRY_REQUEST_MAX_ATTEMPTS; i++) {
      await h.client.maybeRequestRetry(peer.userId)
      ;(h.client as unknown as { askedRetryFrom: Set<string> }).askedRetryFrom.delete(peer.userId)
      await h.contacts.mutateRetryState(peer.userId, (r) => {
        r.askedAt = Date.now() - RETRY_REQUEST_MIN_INTERVAL_MS - 1
      })
    }
    expect(await h.queued()).toHaveLength(RETRY_REQUEST_MAX_ATTEMPTS)
    expect(h.exhausted).toEqual([])

    await h.client.maybeRequestRetry(peer.userId)
    expect(await h.queued()).toHaveLength(RETRY_REQUEST_MAX_ATTEMPTS) // nothing further
    expect(h.exhausted).toEqual([peer.userId])
  })

  it('asks nobody this device does not hold, and nobody the user deleted', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)

    await h.client.maybeRequestRetry(peer.userId) // unknown peer
    expect(await h.queued()).toHaveLength(0)

    await h.known(peer)
    await h.contacts.remove(peer.userId, Date.now()) // deleted here
    await h.client.maybeRequestRetry(peer.userId)
    expect(await h.queued()).toHaveLength(0)
    expect(h.asked).toEqual([])
  })

  it('does not count an ask that never left the device', async () => {
    const h = await harness()
    await h.known(peer)
    // No session and no reachable directory, so the request cannot be built. The
    // user must not later be told we asked and got no answer.
    await h.client.maybeRequestRetry(peer.userId)
    expect(await h.queued()).toHaveLength(0)
    expect(h.asked).toEqual([])
    const state = await h.contacts.getRetryState(peer.userId)
    expect(state.attempts).toBe(0)
    // The interval still applies, so a queue full of redeliveries cannot make this
    // retry immediately.
    expect(typeof state.askedAt).toBe('number')
  })

  it('forgets it ever asked once something from that contact decrypts again', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    await h.known(peer)
    await h.client.maybeRequestRetry(peer.userId)
    expect((await h.contacts.getRetryState(peer.userId)).attempts).toBe(1)

    // The evidence that the conversation recovered is a message that opens.
    await (h.client as unknown as { clearRetryAsk(p: string): Promise<void> }).clearRetryAsk(peer.userId)

    const state = await h.contacts.getRetryState(peer.userId)
    expect(state.attempts).toBeUndefined()
    expect(state.askedAt).toBeUndefined()
    // ...so a LATER break is allowed to ask again rather than being stuck at the cap.
    await h.client.maybeRequestRetry(peer.userId)
    expect(await h.queued()).toHaveLength(2)
  })

  it('the request it sends carries no target: it can only ever mean "resend recent"', async () => {
    // A device that could not decrypt never learned any content id, so the wire
    // format gives it no way to name a message. Assert that on the encoder.
    const { encodeRetryRequest, newMsgId } = await import('../crypto/message')
    const decoded = decodeMessage(encodeRetryRequest(newMsgId()))
    expect(decoded.kind).toBe('retry')
    expect(Object.keys(decoded)).toEqual(['kind', 'id'])
  })
})

describe('retry-receipt: end to end, a message lost to a dead session comes back', () => {
  // Two REAL clients with in-memory stores and a hand-cranked ferry between them,
  // so the whole path runs: the failed decrypts, the ask, the answer, and the
  // repaired message landing in history. This is the claim the feature makes, and
  // the units above cannot make it on their own.

  interface Ferry {
    handleDeliver(from: string, env: unknown): Promise<void>
  }

  async function party() {
    const id = generateIdentity()
    const keys = new MemoryKeyStore()
    const lock = new InMemoryLock()
    const store = new MemorySessionStore()
    const prekeys = new PrekeyStore(keys, lock)
    const contacts = new ContactStore(keys, lock)
    const appLock = new AppLockStore(keys, lock, stubKdf)
    await appLock.enroll([{ kind: 'pass', secret: 'x' }])
    const history = new HistoryStore(appLock)
    const own = buildOwnBundle(id, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 5 })
    await prekeys.setFromRegistration({
      spk: { id: own.spk.id, createdAt: own.spk.createdAt, expiry: own.spk.expiry, pub: own.spk.pub, sig: own.spk.sig },
      spkPrivById: own.spkPrivById,
      opks: own.opks,
      opkPrivById: own.opkPrivById,
    })
    const bundle: FetchedBundle = {
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opk: own.opks[0],
    }
    const honored: Array<{ peer: string; count: number }> = []
    const client = new NightjarClient(
      id,
      store,
      prekeys,
      contacts,
      lock,
      { onMessage: () => {}, onRetryHonored: (peer, count) => honored.push({ peer, count }) },
      history,
    )
    return { id, client, store, contacts, bundle, honored }
  }

  it('recovers it: two failed decrypts, one ask, one answer', async () => {
    const alice = await party()
    const bob = await party()
    // Each can fetch the other's bundle, and each knows the other as a contact.
    const dir = (who: typeof alice, other: typeof bob) => {
      ;(who.client as unknown as { directory: unknown }).directory = {
        fetchBundle: async () => ({ bundle: other.bundle }),
      }
    }
    dir(alice, bob)
    dir(bob, alice)
    await alice.contacts.recordFirstContact(bob.id.userId, bob.id.ikSig.publicKey, Date.now())
    await bob.contacts.recordFirstContact(alice.id.userId, alice.id.ikSig.publicKey, Date.now())

    // Both halves are deliberately fire-and-forget inside handleDeliver: recovery
    // must never sit between a decrypted message and its acknowledgement. So the
    // ferry waits for the detached work to settle before the next assertion.
    const ferry = async (to: typeof alice, from: string, env: unknown) => {
      await (to.client as unknown as Ferry).handleDeliver(from, env)
      for (let i = 0; i < 25; i++) await new Promise((r) => setTimeout(r, 0))
    }

    // First an established conversation. This matters: a FIRST message is an X3DH
    // initial, which opens its own session and would survive the loss below. What a
    // move actually swallows is everything on an already-established ratchet.
    await bob.client.sendText(alice.id.userId, 'hello from before')
    const opener = (await bob.store.pendingOutbox()).entries[0]
    await ferry(alice, bob.id.userId, opener.env)

    // Now the one that gets lost: a normal message on the session Bob holds.
    await bob.client.sendText(alice.id.userId, 'the message that got lost')
    const lost = (await bob.store.pendingOutbox()).entries.find((e) => e.id !== opener.id)!
    expect((lost.env as { kind: string }).kind).toBe('normal')

    // Alice moves to a new device: her sessions do not travel with her (Phase D),
    // so Bob is still encrypting to a ratchet she no longer holds.
    await alice.store.delete(bob.id.userId)

    // The relay redelivers Bob's message on each connect. Alice cannot read it.
    await ferry(alice, bob.id.userId, lost.env)
    await ferry(alice, bob.id.userId, lost.env)

    // She has now asked Bob to resend, on a fresh session of her own.
    const ask = (await alice.store.pendingOutbox()).entries.filter((e) => e.to === bob.id.userId)
    expect(ask).toHaveLength(1)
    expect(ask[0].silent).toBe(true)

    // Bob receives the ask and answers it without being told to.
    await ferry(bob, alice.id.userId, ask[0].env)
    // Both of Bob's recent messages come back, the lost one among them.
    expect(bob.honored).toEqual([{ peer: alice.id.userId, count: 2 }])
    const known = new Set([opener.id, lost.id])
    const resent = (await bob.store.pendingOutbox()).entries.filter((e) => !known.has(e.id))
    expect(resent).toHaveLength(2)

    // And they land. This is the message the relay had already told Bob was delivered.
    for (const r of resent) await ferry(alice, bob.id.userId, r.env)
    const conversation = (await alice.client.loadAllHistory())[bob.id.userId] ?? []
    expect(conversation.map((m) => m.text)).toContain('the message that got lost')
    expect(conversation.every((m) => m.dir === 'in')).toBe(true)
    // The one she already had was upserted under its own content id, not duplicated.
    expect(conversation).toHaveLength(2)
  })

  it('a second copy of the same message does not appear twice', async () => {
    // The original content id is what makes the repair idempotent: if the lost
    // message HAD arrived, the resend upserts the same row rather than duplicating.
    const alice = await party()
    const bob = await party()
    ;(bob.client as unknown as { directory: unknown }).directory = { fetchBundle: async () => ({ bundle: alice.bundle }) }
    ;(alice.client as unknown as { directory: unknown }).directory = { fetchBundle: async () => ({ bundle: bob.bundle }) }
    await bob.contacts.recordFirstContact(alice.id.userId, alice.id.ikSig.publicKey, Date.now())

    await bob.client.sendText(alice.id.userId, 'delivered once already')
    const first = (await bob.store.pendingOutbox()).entries[0]
    // Both halves are deliberately fire-and-forget inside handleDeliver: recovery
    // must never sit between a decrypted message and its acknowledgement. So the
    // ferry waits for the detached work to settle before the next assertion.
    const ferry = async (to: typeof alice, from: string, env: unknown) => {
      await (to.client as unknown as Ferry).handleDeliver(from, env)
      for (let i = 0; i < 25; i++) await new Promise((r) => setTimeout(r, 0))
    }
    await ferry(alice, bob.id.userId, first.env) // it DID arrive
    expect(((await alice.client.loadAllHistory())[bob.id.userId] ?? []).length).toBe(1)

    // Bob answers a request anyway (Alice asked about something else she missed).
    await (bob.client as unknown as Internals).honorRetryRequest(alice.id.userId)
    const resent = (await bob.store.pendingOutbox()).entries.find((e) => e.id !== first.id)!
    await ferry(alice, bob.id.userId, resent.env)

    const conversation = (await alice.client.loadAllHistory())[bob.id.userId] ?? []
    expect(conversation).toHaveLength(1)
    expect(conversation[0].text).toBe('delivered once already')
  })
})

describe('retry-receipt: the throttling ledger', () => {
  const peerId = 'a'.repeat(52)
  const otherId = 'b'.repeat(52)

  async function store() {
    const keys = new MemoryKeyStore()
    const lock = new InMemoryLock()
    const appLock = new AppLockStore(keys, lock, stubKdf)
    await appLock.enroll([{ kind: 'pass', secret: 'x' }])
    return { contacts: new ContactStore(keys, lock, appLock), keys }
  }

  it('survives a restart, which is the whole point of not keeping it in memory', async () => {
    const { contacts } = await store()
    const now = Date.now()
    await contacts.mutateRetryState(peerId, (r) => {
      r.askedAt = now - 1000
      r.attempts = 2
      r.honoredAt = now - 500
    })
    expect(await contacts.getRetryState(peerId)).toEqual({ askedAt: now - 1000, attempts: 2, honoredAt: now - 500 })
    // Untouched peers are unaffected by another's entry.
    expect(await contacts.getRetryState(otherId)).toEqual({})
  })

  it('is sealed at rest: the ledger names people, so it must not be readable raw', async () => {
    const { contacts, keys } = await store()
    await contacts.mutateRetryState(peerId, (r) => {
      r.honoredAt = Date.now()
    })
    const raw = await keys.get('contacts.retry.v1')
    expect(raw).toBeTruthy()
    expect(new TextDecoder().decode(raw!)).not.toContain(peerId)
  })

  it('ages entries out, so it cannot become a permanent record of broken conversations', async () => {
    const { contacts } = await store()
    const now = Date.now()
    await contacts.mutateRetryState(peerId, (r) => {
      r.askedAt = now
    })
    // Read far enough in the future that the relay no longer holds the messages
    // that caused the entry, so it can throttle nothing that still exists.
    const later = now + 31 * 24 * 60 * 60 * 1000
    expect(await contacts.getRetryState(peerId, later)).toEqual({})
  })

  it('is bounded, keeping the most recent entries', async () => {
    const { contacts } = await store()
    const now = Date.now()
    for (let i = 0; i < MAX_RETRY_LEDGER + 5; i++) {
      const id = i.toString().padStart(52, 'z')
      await contacts.mutateRetryState(id, (r) => {
        r.askedAt = now - (MAX_RETRY_LEDGER + 5 - i) * 1000
      })
    }
    // The oldest fell off; the newest is still throttled.
    expect(await contacts.getRetryState('0'.padStart(52, 'z'))).toEqual({})
    const newest = (MAX_RETRY_LEDGER + 4).toString().padStart(52, 'z')
    expect(typeof (await contacts.getRetryState(newest)).askedAt).toBe('number')
  })

  it('does not ride a restore or a move: a fresh device must be free to ask', async () => {
    const { contacts } = await store()
    await contacts.mutateRetryState(peerId, (r) => {
      r.askedAt = Date.now()
      r.attempts = 3
    })
    await contacts.replaceAllForMove([], {}, {})
    expect(await contacts.getRetryState(peerId)).toEqual({})
  })
})
