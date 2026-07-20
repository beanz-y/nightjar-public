// maybeRotateSpk decision matrix (P8). The Directory is stubbed; the real
// PrekeyStore backs the decisions so the storage semantics (newest-wins,
// published marker, retention) are exercised end to end. The wire-level
// rotate-publish path runs for real in test/worker/relay.test.ts.

import { describe, expect, it } from 'vitest'
import { generateIdentity } from '../crypto/identity'
import { buildOwnBundle, generateSignedPrekey } from '../crypto/prekeys'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'
import type { WireOneTimePrekey, WireSignedPrekey } from '../wire/codec'

const NOW = 1_700_000_000_000
const DAY = 86_400_000

function harness(opts: { confirmed?: boolean } = {}) {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const prekeys = new PrekeyStore(keys, lock)
  const client = new NightjarClient(identity, new MemorySessionStore(), prekeys, new ContactStore(keys, lock), lock, {
    onMessage: () => {},
  })

  const published: Array<{ spk: WireSignedPrekey; opks: WireOneTimePrekey[] }> = []
  let reregistered = 0
  // Test seam: swap the directory for a recorder (readonly is compile-time only).
  ;(client as unknown as { directory: unknown }).directory = {
    publishBundle: async (spk: WireSignedPrekey, opks: WireOneTimePrekey[]) => {
      published.push({ spk, opks })
      return 100
    },
    register: async () => {
      reregistered += 1
      return 100
    },
  }
  ;(client as unknown as { authed: unknown }).authed = {
    userId: identity.userId,
    registered: true,
    opkCount: 100,
    pushKey: null,
  }

  const seed = async () => {
    const own = buildOwnBundle(identity, NOW, { spkId: 1, opkStartId: 1, opkCount: 3 })
    await prekeys.setFromRegistration({
      spk: { id: own.spk.id, createdAt: own.spk.createdAt, expiry: own.spk.expiry, pub: own.spk.pub, sig: own.spk.sig },
      spkPrivById: own.spkPrivById,
      opks: own.opks,
      opkPrivById: own.opkPrivById,
    })
    // A healthy seed is a CONFIRMED registration (server acked): clears
    // regUnconfirmed and marks SPK 1 published. `confirmed:false` leaves the
    // set unconfirmed, simulating an interrupted full registration.
    if (opts.confirmed !== false) await prekeys.confirmRegistration(1)
  }

  return { client, prekeys, published, seed, reregistered: () => reregistered }
}

describe('maybeRotateSpk (P8)', () => {
  it('does nothing while the published SPK is fresh', async () => {
    const h = harness()
    await h.seed()
    await h.client.maybeRotateSpk(NOW + 1 * DAY)
    expect(h.published).toHaveLength(0)
    expect((await h.prekeys.newestSpk())?.id).toBe(1)
  })

  it('generates and publishes a successor once the cadence passes, keeping the old private half', async () => {
    const h = harness()
    await h.seed()
    await h.client.maybeRotateSpk(NOW + 8 * DAY)
    expect(h.published).toHaveLength(1)
    expect(h.published[0].spk.id).toBe(2)
    expect(h.published[0].opks).toHaveLength(0)
    expect(await h.prekeys.publishedSpkId()).toBe(2)
    // Old SPK private half retained for late in-flight initials.
    const keys = await h.prekeys.responderKeys()
    expect([...keys.spkPrivById.keys()].sort((a, b) => a - b)).toEqual([1, 2])
    // Idempotent: a second pass inside the cadence publishes nothing new.
    await h.client.maybeRotateSpk(NOW + 8 * DAY + 1000)
    expect(h.published).toHaveLength(1)
  })

  it('retries an unpublished ROTATION via publishBundle (crash between addSpk and publish)', async () => {
    const h = harness()
    await h.seed() // confirmed registration of SPK 1
    // Simulate a rotation that added SPK 2 locally but crashed before publishing:
    // publishedSpkId still 1, newest 2, regUnconfirmed false (an established set,
    // so publishBundle is the correct recovery, not a full re-register). The
    // recorder stub does not verify the SPK sig, so any identity may sign it.
    const rotated = generateSignedPrekey(generateIdentity(), 2, NOW + 8 * DAY)
    await h.prekeys.addSpk({
      id: 2,
      createdAt: rotated.spk.createdAt,
      expiry: rotated.spk.expiry,
      priv: rotated.priv,
      pub: rotated.spk.pub,
      sig: rotated.spk.sig,
    })
    await h.client.maybeRotateSpk(NOW + 8 * DAY + 1000)
    expect(h.reregistered()).toBe(0) // NOT a full re-register
    expect(h.published).toHaveLength(1)
    expect(h.published[0].spk.id).toBe(2)
    expect(await h.prekeys.publishedSpkId()).toBe(2)
  })

  it('recovers an INTERRUPTED full registration via a purging re-register, not publishBundle', async () => {
    const h = harness({ confirmed: false })
    await h.seed() // SPK 1 stored locally but the Directory never acked (regUnconfirmed)
    await h.client.maybeRotateSpk(NOW + 1 * DAY)
    // Must re-register (which purges the Directory's stale OPKs), NOT publishBundle
    // (which would leave stale OPKs served): the P9 stale-OPK finding.
    expect(h.reregistered()).toBe(1)
    expect(h.published).toHaveLength(0)
  })

  it('re-registers from scratch when no local SPK exists (interrupted restore self-heal)', async () => {
    const h = harness()
    // No seed: registered per the server, nothing in the local prekey store.
    await h.client.maybeRotateSpk(NOW)
    expect(h.reregistered()).toBe(1)
  })
})
