import { beforeEach, describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { POISON_MAX_ATTEMPTS } from '../crypto/constants'
import { type Identity, generateIdentity } from '../crypto/identity'
import { encodeDeleteMessage, encodeTextMessage, newMsgId } from '../crypto/message'
import { hash256, utf8 } from '../crypto/primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { type RatchetState, initRatchetInitiator, ratchetEncrypt } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
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

// Same as aliceInitial/aliceNormal but with an arbitrary ratchet PLAINTEXT (so a
// test can send a structured NJM1 record, an ephemeral one, a delete, or legacy
// raw bytes).
function aliceInitialBytes(alice: Identity, bundle: FetchedBundle, id: string, plaintext: Uint8Array): AliceMsg {
  const ini = x3dhInitiate(alice, bundle, NOW)
  const enc = ratchetEncrypt(initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub), plaintext)
  return {
    state: enc.state,
    env: { id, kind: 'initial', header: enc.header, ciphertext: enc.ciphertext, initialHeader: ini.header },
  }
}

function aliceNormalBytes(state: RatchetState, id: string, plaintext: Uint8Array): AliceMsg {
  const enc = ratchetEncrypt(state, plaintext)
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

describe('processInbound + persistent history (P10c)', () => {
  let ctx: Awaited<ReturnType<typeof setup>>
  let appLock: AppLockStore
  let history: HistoryStore

  beforeEach(async () => {
    ctx = await setup()
    appLock = new AppLockStore(new MemoryKeyStore(), ctx.lock, stubKdf)
    await appLock.enroll([{ kind: 'pass', secret: 'x' }])
    history = new HistoryStore(appLock)
  })

  const deps = () => ({ me: ctx.bob, prekeys: ctx.prekeys, store: ctx.store, lock: ctx.lock, now: NOW, history })
  const storedMsgs = async () => (await ctx.store.historyLoadAll()).map((r) => history.open(r))

  it('persists a structured text message (full metadata sealed), in the same commit', async () => {
    const cid = newMsgId()
    const m = aliceInitialBytes(ctx.alice, ctx.bundle, 'env-1', encodeTextMessage(cid, 'persist me', false))
    const res = await processInbound(m.env, ctx.alice.userId, deps())
    expect(res.kind).toBe('delivered')
    const msgs = await storedMsgs()
    expect(msgs).toEqual([{ id: bytesToHex(cid), peerId: ctx.alice.userId, dir: 'in', ts: NOW, text: 'persist me' }])
    // The record and the dedup marker landed together (delivered -> caller acks).
    expect(await ctx.store.hasSeen('env-1')).toBe(true)
  })

  it('does NOT persist an ephemeral message (persist gate fails closed)', async () => {
    const m = aliceInitialBytes(ctx.alice, ctx.bundle, 'env-2', encodeTextMessage(newMsgId(), 'poof', true))
    const res = await processInbound(m.env, ctx.alice.userId, deps())
    expect(res.kind).toBe('delivered') // still delivered live; simply not stored
    expect(await ctx.store.historyLoadAll()).toEqual([])
  })

  it('persists a legacy (pre-P10) plain-text message keyed by the envelope id', async () => {
    const m = aliceInitialBytes(ctx.alice, ctx.bundle, 'env-3', utf8('old style'))
    await processInbound(m.env, ctx.alice.userId, deps())
    expect(await storedMsgs()).toEqual([{ id: 'env-3', peerId: ctx.alice.userId, dir: 'in', ts: NOW, text: 'old style' }])
  })

  it('does NOT persist a delete control message, but records a tombstone (P10d)', async () => {
    const target = newMsgId()
    const m = aliceInitialBytes(ctx.alice, ctx.bundle, 'env-4', encodeDeleteMessage(target))
    const res = await processInbound(m.env, ctx.alice.userId, deps())
    expect(res.kind).toBe('delivered')
    expect(await ctx.store.historyLoadAll()).toEqual([]) // the control itself is never stored
    // A tombstone for the (inbound, from-this-peer) target is recorded, so a target
    // that arrives after its delete is later suppressed.
    const key = history.storageKey(ctx.alice.userId, 'in', bytesToHex(target))
    expect(await ctx.store.hasTombstone(key)).toBe(true)
  })

  it('a delete removes an already-persisted inbound message and tombstones it (P10d)', async () => {
    const cid = newMsgId()
    // Establish + persist the target (initial), then delete it (a normal on the
    // same ratchet).
    const first = aliceInitialBytes(ctx.alice, ctx.bundle, 'env-t', encodeTextMessage(cid, 'delete me', false))
    await processInbound(first.env, ctx.alice.userId, deps())
    expect((await storedMsgs()).map((m) => m.id)).toEqual([bytesToHex(cid)])

    const del = aliceNormalBytes(first.state, 'env-d', encodeDeleteMessage(cid))
    const res = await processInbound(del.env, ctx.alice.userId, deps())
    expect(res.kind).toBe('delivered')
    expect(await ctx.store.hasSeen('env-d')).toBe(true) // ratchet advanced + acked
    expect(await ctx.store.historyLoadAll()).toEqual([]) // the target row is gone
    const key = history.storageKey(ctx.alice.userId, 'in', bytesToHex(cid))
    expect(await ctx.store.hasTombstone(key)).toBe(true)
  })

  it('a delete arriving BEFORE its target suppresses the later target (reorder, P10d)', async () => {
    const cid = newMsgId()
    // Establish a session with an unrelated first message.
    const est = aliceInitialBytes(ctx.alice, ctx.bundle, 'env-e', encodeTextMessage(newMsgId(), 'hi', false))
    await processInbound(est.env, ctx.alice.userId, deps())

    // Alice sends the target then a delete for it; Bob receives the DELETE first
    // (the target is a skipped message key), then the target.
    const target = aliceNormalBytes(est.state, 'env-target', encodeTextMessage(cid, 'to be deleted', false))
    const del = aliceNormalBytes(target.state, 'env-del', encodeDeleteMessage(cid))

    const rDel = await processInbound(del.env, ctx.alice.userId, deps())
    expect(rDel.kind).toBe('delivered')
    const key = history.storageKey(ctx.alice.userId, 'in', bytesToHex(cid))
    expect(await ctx.store.hasTombstone(key)).toBe(true)

    const rTarget = await processInbound(target.env, ctx.alice.userId, deps())
    expect(rTarget.kind).toBe('delivered')
    // The target decrypted (so it is acked) but was SUPPRESSED: not persisted, not
    // rendered by the caller.
    if (rTarget.kind === 'delivered') expect(rTarget.suppressed).toBe(true)
    expect(await ctx.store.hasSeen('env-target')).toBe(true)
    // Only the establishing "hi" remains; the deleted target was never stored.
    expect((await storedMsgs()).map((m) => m.text)).toEqual(['hi'])
  })

  it('persists a normal established-session message and a redelivery does not double-store', async () => {
    const first = aliceInitialBytes(ctx.alice, ctx.bundle, 'env-5', encodeTextMessage(newMsgId(), 'first', false))
    await processInbound(first.env, ctx.alice.userId, deps())
    const cid = newMsgId()
    const second = aliceNormalBytes(first.state, 'env-6', encodeTextMessage(cid, 'second', false))
    await processInbound(second.env, ctx.alice.userId, deps())
    const again = await processInbound(second.env, ctx.alice.userId, deps())
    expect(again.kind).toBe('duplicate')
    const msgs = await storedMsgs()
    expect(msgs.length).toBe(2)
    expect(msgs.map((m) => m.id)).toContain(bytesToHex(cid))
  })

  it('a decryptable message whose history seal fails is retried, NEVER poison-dropped', async () => {
    // A seal failure on a decryptable message must not be conflated with a decrypt
    // miss and acked-and-dropped. Force it with a LOCKED app-lock (fail closed).
    const lockedAppLock = new AppLockStore(new MemoryKeyStore(), ctx.lock, stubKdf) // never unlocked
    const brokenHistory = new HistoryStore(lockedAppLock)
    const brokenDeps = () => ({ me: ctx.bob, prekeys: ctx.prekeys, store: ctx.store, lock: ctx.lock, now: NOW, history: brokenHistory })
    const m = aliceInitialBytes(ctx.alice, ctx.bundle, 'env-x', encodeTextMessage(newMsgId(), 'important', false))
    for (let i = 0; i < POISON_MAX_ATTEMPTS + 3; i++) {
      await expect(processInbound(m.env, ctx.alice.userId, brokenDeps())).rejects.toThrow()
    }
    expect(await ctx.store.hasSeen('env-x')).toBe(false)
    expect(await ctx.store.historyLoadAll()).toEqual([])
    // Once history is available, the same message delivers + persists.
    const res = await processInbound(m.env, ctx.alice.userId, deps())
    expect(res.kind).toBe('delivered')
    expect((await ctx.store.historyLoadAll()).length).toBe(1)
  })
})
