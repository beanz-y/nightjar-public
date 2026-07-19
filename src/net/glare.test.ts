// The session-glare regression suite (DESIGN 6.4/8.3; docs/SESSION-GLARE.md).
//
// It drives two parties through the REAL receive path (processInbound) and a send
// helper that mirrors NightjarClient.sendText's book logic (the ~10 lines of glue
// around the shared sessionBook + ratchet + store). The end-to-end send+receive
// glue over the real relay is separately covered by the in-browser self-test.

import { beforeEach, describe, expect, it } from 'vitest'
import { type Identity, generateIdentity } from '../crypto/identity'
import { utf8 } from '../crypto/primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { deserializeRatchet, initRatchetInitiator, ratchetEncrypt, serializeRatchet } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { currentSession, promoteSession, updateSession } from '../session/sessionBook'
import type { Envelope } from '../wire/codec'
import { type InboundResult, processInbound } from './inbound'

const NOW = 1_700_000_000_000
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

interface Party {
  id: Identity
  store: MemorySessionStore
  prekeys: PrekeyStore
  contacts: ContactStore
  lock: InMemoryLock
  bundle: FetchedBundle // what a peer fetches to open a session with this party
}

let clock = NOW

async function makeParty(): Promise<Party> {
  const id = generateIdentity()
  const lock = new InMemoryLock()
  const keys = new MemoryKeyStore()
  const prekeys = new PrekeyStore(keys, lock)
  const own = buildOwnBundle(id, NOW, { spkId: 1, opkStartId: 1, opkCount: 5 })
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
  return { id, store: new MemorySessionStore(), prekeys, contacts: new ContactStore(keys, lock), lock, bundle }
}

// Mirrors NightjarClient.sendText: use the current session, else open a new
// initiator session (X3DH) and make it current. `bundle` overrides what the
// initiator "fetches" (e.g. a fresh re-fetch after restore).
async function send(from: Party, to: Party, text: string, bundle: FetchedBundle = to.bundle): Promise<Envelope> {
  const now = clock++
  const id = `msg-${now}`
  const book = await from.store.loadBook(to.id.userId)
  const current = currentSession(book)
  if (current) {
    const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot), utf8(text))
    const env: Envelope = { id, kind: 'normal', header, ciphertext }
    const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
    await from.store.saveBookWithOutbox(to.id.userId, advanced, { id, to: to.id.userId, env, createdAt: now })
    return env
  }
  const ini = x3dhInitiate(from.id, bundle, now)
  const { state, header, ciphertext } = ratchetEncrypt(initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub), utf8(text))
  const env: Envelope = { id, kind: 'initial', header, ciphertext, initialHeader: ini.header }
  const promoted = promoteSession(book, serializeRatchet(state), now)
  await from.store.saveBookWithOutbox(to.id.userId, promoted, { id, to: to.id.userId, env, createdAt: now })
  return env
}

async function recv(at: Party, fromId: string, env: Envelope): Promise<InboundResult> {
  return processInbound(env, fromId, {
    me: at.id,
    prekeys: at.prekeys,
    store: at.store,
    contacts: at.contacts,
    lock: at.lock,
    now: clock++,
  })
}

function delivered(r: InboundResult): string {
  if (r.kind !== 'delivered') throw new Error(`expected delivered, got ${r.kind}`)
  return dec(r.plaintext)
}

describe('session glare', () => {
  beforeEach(() => {
    clock = NOW
  })

  it('sequential first contact still works (the common case, no glare)', async () => {
    const alice = await makeParty()
    const bob = await makeParty()
    const a1 = await send(alice, bob, 'hello')
    expect(delivered(await recv(bob, alice.id.userId, a1))).toBe('hello')
    const b1 = await send(bob, alice, 'hi')
    expect(delivered(await recv(alice, bob.id.userId, b1))).toBe('hi')
    const a2 = await send(alice, bob, 'how are you')
    expect(delivered(await recv(bob, alice.id.userId, a2))).toBe('how are you')
  })

  it('simultaneous first contact converges: follow-ups decrypt both ways', async () => {
    const alice = await makeParty()
    const bob = await makeParty()

    // Both send a first-contact initial before either has received.
    const a1 = await send(alice, bob, 'A: hi')
    const b1 = await send(bob, alice, 'B: hi')

    // Each receives the other's initial (promotes a responder session; the old
    // initiator session is archived, NOT clobbered).
    expect(delivered(await recv(bob, alice.id.userId, a1))).toBe('A: hi')
    expect(delivered(await recv(alice, bob.id.userId, b1))).toBe('B: hi')

    // Both books now hold two sessions.
    expect((await alice.store.loadBook(bob.id.userId))!.sessions).toHaveLength(2)
    expect((await bob.store.loadBook(alice.id.userId))!.sessions).toHaveLength(2)

    // The follow-ups (normal messages) each land on the OTHER arm of the glare
    // and must still decrypt via try-all. This is exactly what regressed before.
    const a2 = await send(alice, bob, 'A: still here')
    expect(delivered(await recv(bob, alice.id.userId, a2))).toBe('A: still here')
    const b2 = await send(bob, alice, 'B: me too')
    expect(delivered(await recv(alice, bob.id.userId, b2))).toBe('B: me too')

    // And it keeps working for several more rounds.
    for (let i = 0; i < 3; i++) {
      const am = await send(alice, bob, `A${i}`)
      expect(delivered(await recv(bob, alice.id.userId, am))).toBe(`A${i}`)
      const bm = await send(bob, alice, `B${i}`)
      expect(delivered(await recv(alice, bob.id.userId, bm))).toBe(`B${i}`)
    }
  })

  it('a message sent before receiving the peer initial still decrypts after glare', async () => {
    const alice = await makeParty()
    const bob = await makeParty()

    const a1 = await send(alice, bob, 'A1')
    const b1 = await send(bob, alice, 'B1')
    // Alice fires a SECOND message before she has seen Bob's initial: it rides her
    // own initiator session (still current).
    const a2 = await send(alice, bob, 'A2')

    // Bob processes Alice's initial then her a2 (normal on the same session).
    expect(delivered(await recv(bob, alice.id.userId, a1))).toBe('A1')
    expect(delivered(await recv(bob, alice.id.userId, a2))).toBe('A2')
    // Alice then catches up on Bob's initial.
    expect(delivered(await recv(alice, bob.id.userId, b1))).toBe('B1')
    // Continued traffic converges.
    const b2 = await send(bob, alice, 'B2')
    expect(delivered(await recv(alice, bob.id.userId, b2))).toBe('B2')
  })

  it('re-establishment: a fresh initial replaces a stale session (restore, 8.3)', async () => {
    const alice = await makeParty()
    let bob = await makeParty()

    // A normal established conversation.
    const a1 = await send(alice, bob, 'hi bob')
    expect(delivered(await recv(bob, alice.id.userId, a1))).toBe('hi bob')
    const b1 = await send(bob, alice, 'hi alice')
    expect(delivered(await recv(alice, bob.id.userId, b1))).toBe('hi alice')

    // Bob "restores": same identity + prekeys, but a FRESH (empty) session store,
    // so he has no ratchet state for Alice and must re-initiate.
    const freshStore = new MemorySessionStore()
    bob = { ...bob, store: freshStore }
    // On restore the client re-fetches a fresh bundle; here Alice's original OPK
    // was already consumed, so the re-fetch degrades to the no-OPK path.
    const aliceReFetch: FetchedBundle = { ...alice.bundle, opk: null }
    const b2 = await send(bob, alice, 're-established', aliceReFetch) // a new initial
    expect(b2.kind).toBe('initial')

    // Alice already has a session for Bob; the new initial is promoted to current
    // (the stale one archived), and future traffic on the new session works.
    expect(delivered(await recv(alice, bob.id.userId, b2))).toBe('re-established')
    const a2 = await send(alice, bob, 'welcome back')
    expect(delivered(await recv(bob, alice.id.userId, a2))).toBe('welcome back')
  })
})
