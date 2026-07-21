// Session-only (ephemeral, P10e) SEND side: NightjarClient.sendText(..., ephemeral).
// The receive-side gate ("does NOT persist an ephemeral message") is covered in
// inbound.test.ts; here we assert the sender's symmetric non-persistence AND that
// ephemeral messages are otherwise delivered EXACTLY like any message (same outbox /
// retransmit), so a session-establishing initial is never dropped:
//   - an ephemeral send writes NO history row, but DOES queue an outbox entry and
//     fire (reliable delivery, not best-effort);
//   - a NON-ephemeral send (control) writes both a history row and an outbox entry,
//     proving the skip is conditional on the flag alone;
//   - an ephemeral send while offline is QUEUED for retry (not lost), still with no
//     history row.

import { type Identity, generateIdentity } from '../crypto/identity'
import { beforeEach, describe, expect, it } from 'vitest'
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
import type { WireEnvelope } from '../wire/codec'

const NOW = 1_700_000_000_000
const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

async function makePeerBundle(): Promise<{ id: Identity; bundle: FetchedBundle }> {
  const id = generateIdentity()
  // Build the bundle at the real current time: sendText's first-contact branch runs
  // x3dhInitiate at Date.now(), which rejects a signed prekey older than 14 days.
  const own = buildOwnBundle(id, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 3 })
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

async function harness(opts: { connected?: boolean } = {}) {
  const connected = opts.connected !== false
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const store = new MemorySessionStore()
  const prekeys = new PrekeyStore(keys, lock)
  const contacts = new ContactStore(keys, lock)
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'x' }])
  const history = new HistoryStore(appLock)
  const client = new NightjarClient(identity, store, prekeys, contacts, lock, { onMessage: () => {} }, history)

  // Stub the transport, mirroring the real one: raw() throws when not connected (so
  // fire() catches it and the outbox entry stays queued), and waitSent never resolves
  // so a queued entry is not auto-removed during the test.
  const sent: Array<{ t: string; to: string; env: WireEnvelope }> = []
  ;(client as unknown as { transport: unknown }).transport = {
    isOpen: connected,
    raw: (m: { t: string; to: string; env: WireEnvelope }) => {
      if (!connected) throw new Error('transport: not connected')
      sent.push(m)
    },
    waitSent: () => new Promise<void>(() => {}),
  }

  const seedSession = async (peer: Identity, bundle: FetchedBundle) => {
    const ini = x3dhInitiate(identity, bundle, Date.now())
    const state = initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub)
    await store.saveBook(peer.userId, singleSessionBook(serializeRatchet(state), Date.now()))
  }

  return { client, store, history, sent, seedSession }
}

describe('sendText session-only (P10e)', () => {
  let peer: Identity
  let bundle: FetchedBundle
  beforeEach(async () => {
    const p = await makePeerBundle()
    peer = p.id
    bundle = p.bundle
  })

  it('an ephemeral send writes NO history row, but queues + fires like any message', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)

    const id = await h.client.sendText(peer.userId, 'off the record', undefined, NOW, true)

    // Symmetric with the receive gate: nothing sealed to history on the sender.
    expect(await h.store.historyLoadAll()).toEqual([])
    // But delivery is UNCHANGED: an outbox entry is committed and the envelope fired,
    // so a session-establishing initial is never dropped (the reliability that a
    // naive outbox-skip would have broken).
    expect((await h.store.pendingOutbox()).map((e) => e.id)).toEqual([id])
    expect(h.sent).toHaveLength(1)
    expect(h.sent[0].env.id).toBe(id)
    expect(['normal', 'initial']).toContain(h.sent[0].env.kind)
  })

  it('a NON-ephemeral send (control) writes both a history row and an outbox entry', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)

    const id = await h.client.sendText(peer.userId, 'keep me', undefined, NOW, false)

    const rows = await h.store.historyLoadAll()
    expect(rows).toHaveLength(1)
    expect(h.history.open(rows[0])).toMatchObject({ id, peerId: peer.userId, dir: 'out', text: 'keep me' })
    expect((await h.store.pendingOutbox()).map((e) => e.id)).toEqual([id])
    expect(h.sent).toHaveLength(1)
  })

  it('an ephemeral FIRST-CONTACT send establishes the session via the durable outbox (initial is reliably retransmitted, not fire-and-forget)', async () => {
    // Regression guard for the impl-review HIGH finding: a session-ESTABLISHING
    // ephemeral message must NOT be delivered best-effort-once (a lost initial would
    // orphan the session and break ALL future traffic, including non-ephemeral). With
    // no seeded session, the send takes the X3DH first-contact branch; assert the
    // establishing `initial` is committed to the durable outbox (so flushOutbox retries
    // it until acked) and the contact is recorded, all with NO history row.
    const h = await harness()
    ;(h.client as unknown as { directory: unknown }).directory = { fetchBundle: async () => ({ bundle }) }

    const id = await h.client.sendText(peer.userId, 'off the record, first ever', undefined, NOW, true)

    const out = await h.store.pendingOutbox()
    expect(out.map((e) => e.id)).toEqual([id]) // durably queued, not fire-once
    expect((out[0].env as WireEnvelope).kind).toBe('initial') // the X3DH bootstrap
    expect(h.sent).toHaveLength(1) // also fired now
    expect(await h.store.historyLoadAll()).toEqual([]) // but never sealed to history
    // The contact/trust was still recorded (contact is not message content).
    expect(await h.client.trustOf(peer.userId)).not.toBeNull()
  })

  it('an ephemeral send while offline is QUEUED for retry (not lost), still with no history row', async () => {
    const h = await harness({ connected: false })
    await h.seedSession(peer, bundle)

    const id = await h.client.sendText(peer.userId, 'later', undefined, NOW, true)

    // Reliable delivery: the entry is queued (fire caught the not-connected throw),
    // so it flushes on reconnect - a session-only message is NOT silently dropped.
    expect((await h.store.pendingOutbox()).map((e) => e.id)).toEqual([id])
    expect(h.sent).toEqual([]) // nothing left the socket while offline
    // ...and it is still never sealed to history.
    expect(await h.store.historyLoadAll()).toEqual([])
  })
})
