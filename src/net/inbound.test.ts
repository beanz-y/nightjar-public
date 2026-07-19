import { beforeEach, describe, expect, it } from 'vitest'
import { POISON_MAX_ATTEMPTS } from '../crypto/constants'
import { type Identity, generateIdentity } from '../crypto/identity'
import { utf8 } from '../crypto/primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { type RatchetState, initRatchetInitiator, ratchetEncrypt } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import type { Envelope } from '../wire/codec'
import { processInbound } from './inbound'

const NOW = 1_700_000_000_000
const decode = (b: Uint8Array) => new TextDecoder().decode(b)

// Build Bob's persisted prekeys and return a live PrekeyStore plus the material
// Alice needs to open a session.
async function setup() {
  const alice = generateIdentity()
  const bob = generateIdentity()
  const lock = new InMemoryLock()
  const store = new MemorySessionStore()
  const own = buildOwnBundle(bob, NOW, { spkId: 1, opkStartId: 1, opkCount: 3 })
  const prekeys = new PrekeyStore(new MemoryKeyStore(), lock)
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
  return { alice, bob, lock, store, prekeys, bundle }
}

interface AliceMsg {
  env: Envelope
  state: RatchetState
}

function aliceInitial(alice: Identity, bundle: FetchedBundle, id: string, text: string): AliceMsg {
  const ini = x3dhInitiate(alice, bundle, NOW)
  const enc = ratchetEncrypt(initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub), utf8(text))
  return {
    state: enc.state,
    env: { id, kind: 'initial', header: enc.header, ciphertext: enc.ciphertext, initialHeader: ini.header },
  }
}

function aliceNormal(state: RatchetState, id: string, text: string): AliceMsg {
  const enc = ratchetEncrypt(state, utf8(text))
  return { state: enc.state, env: { id, kind: 'normal', header: enc.header, ciphertext: enc.ciphertext } }
}

describe('processInbound', () => {
  let ctx: Awaited<ReturnType<typeof setup>>
  const deps = () => ({ me: ctx.bob, prekeys: ctx.prekeys, store: ctx.store, lock: ctx.lock, now: NOW })

  beforeEach(async () => {
    ctx = await setup()
  })

  it('delivers an initial X3DH message and consumes its one-time prekey', async () => {
    const m = aliceInitial(ctx.alice, ctx.bundle, 'm1', 'hello bob')
    const before = await ctx.prekeys.availableOpkCount()
    const res = await processInbound(m.env, ctx.alice.userId, deps())
    expect(res.kind).toBe('delivered')
    if (res.kind === 'delivered') expect(decode(res.plaintext)).toBe('hello bob')
    // The referenced OPK (id 1) is consumed single-use.
    expect(await ctx.prekeys.availableOpkCount()).toBe(before - 1)
  })

  it('treats a redelivery of the same id as a duplicate (re-ack, no reprocess)', async () => {
    const m = aliceInitial(ctx.alice, ctx.bundle, 'm1', 'hello bob')
    await processInbound(m.env, ctx.alice.userId, deps())
    const again = await processInbound(m.env, ctx.alice.userId, deps())
    expect(again.kind).toBe('duplicate')
    // A duplicate must NOT consume another OPK.
    expect(await ctx.prekeys.availableOpkCount()).toBe(2)
  })

  it('drops (acks) a replayed initial message under a fresh id', async () => {
    const m = aliceInitial(ctx.alice, ctx.bundle, 'm1', 'hello bob')
    await processInbound(m.env, ctx.alice.userId, deps())
    // Same initial header (same initId), new envelope id: a replay attempt. It is
    // permanently rejected -> dropped-and-acked so the relay stops redelivering.
    const replay: Envelope = { ...m.env, id: 'm1-replay' }
    const res = await processInbound(replay, ctx.alice.userId, deps())
    expect(res.kind).toBe('dropped')
    if (res.kind === 'dropped') expect(res.reason).toMatch(/replayed/)
    // A redelivery of the dropped id short-circuits to duplicate (marked seen).
    expect((await processInbound(replay, ctx.alice.userId, deps())).kind).toBe('duplicate')
  })

  it('delivers a normal message on the established session', async () => {
    const first = aliceInitial(ctx.alice, ctx.bundle, 'm1', 'hello')
    await processInbound(first.env, ctx.alice.userId, deps())
    const second = aliceNormal(first.state, 'm2', 'second message')
    const res = await processInbound(second.env, ctx.alice.userId, deps())
    expect(res.kind).toBe('delivered')
    if (res.kind === 'delivered') expect(decode(res.plaintext)).toBe('second message')
  })

  it('a forged message throws and does not corrupt the session', async () => {
    const first = aliceInitial(ctx.alice, ctx.bundle, 'm1', 'hello')
    await processInbound(first.env, ctx.alice.userId, deps())
    const good = aliceNormal(first.state, 'm2', 'legit')
    // Forge a DIFFERENT envelope on the same chain by flipping a ciphertext byte.
    const forged: Envelope = { ...good.env, id: 'forged', ciphertext: good.env.ciphertext.slice() }
    forged.ciphertext[0] ^= 0xff
    await expect(processInbound(forged, ctx.alice.userId, deps())).rejects.toThrow()
    // The genuine message still decrypts: state was not advanced by the forgery.
    const res = await processInbound(good.env, ctx.alice.userId, deps())
    expect(res.kind).toBe('delivered')
    if (res.kind === 'delivered') expect(decode(res.plaintext)).toBe('legit')
  })

  it('rejects a normal message with no established session (retryable, not yet dropped)', async () => {
    const alice2 = generateIdentity()
    const orphan: Envelope = {
      id: 'x',
      kind: 'normal',
      header: { version: 1, dhPub: new Uint8Array(32), pn: 0, n: 0 },
      ciphertext: new Uint8Array(48),
    }
    // Thrown (not acked) so a reordered message ahead of its initial is retried.
    await expect(processInbound(orphan, alice2.userId, deps())).rejects.toThrow(/no session/)
  })

  it('drops a never-decryptable message after the poison bound, then dedups it', async () => {
    const from = generateIdentity().userId
    const orphan: Envelope = {
      id: 'poison',
      kind: 'normal',
      header: { version: 1, dhPub: new Uint8Array(32), pn: 0, n: 0 },
      ciphertext: new Uint8Array(48),
    }
    // The first attempts are retryable throws; the POISON_MAX_ATTEMPTS-th drops.
    for (let i = 0; i < POISON_MAX_ATTEMPTS - 1; i++) {
      await expect(processInbound(orphan, from, deps())).rejects.toThrow()
    }
    const res = await processInbound(orphan, from, deps())
    expect(res.kind).toBe('dropped')
    // Once dropped it is marked seen, so a later redelivery is a duplicate.
    expect((await processInbound(orphan, from, deps())).kind).toBe('duplicate')
  })

  it('rejects an initial whose header identity does not match the sender label', async () => {
    const m = aliceInitial(ctx.alice, ctx.bundle, 'm1', 'hello')
    // A malicious relay mislabels the sender.
    await expect(processInbound(m.env, generateIdentity().userId, deps())).rejects.toThrow(/does not match sender/)
  })

  it('records the sender as a TOFU contact on first inbound contact', async () => {
    const contacts = new ContactStore(new MemoryKeyStore(), ctx.lock)
    const m = aliceInitial(ctx.alice, ctx.bundle, 'm1', 'hello')
    const res = await processInbound(m.env, ctx.alice.userId, { ...deps(), contacts })
    expect(res.kind).toBe('delivered')
    const c = await contacts.get(ctx.alice.userId)
    expect(c?.trust).toBe('unverified')
    expect(c?.peerId).toBe(ctx.alice.userId)
  })
})
