// client.addContact (the verify fix): adding a peer by userId fetches their bundle,
// enforces the key<->userId binding, and records a TOFU contact so a safety number
// can be shown + verified WITHOUT first exchanging a message (previously the verify
// screen silently did nothing because no contact record existed).

import { beforeEach, describe, expect, it } from 'vitest'
import { type Identity, generateIdentity } from '../crypto/identity'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

const NOW = 1_700_000_000_000

function bundleFor(id: Identity): FetchedBundle {
  const own = buildOwnBundle(id, NOW, { spkId: 1, opkStartId: 1, opkCount: 3 })
  return {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opk: own.opks[0],
  }
}

function harness() {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const client = new NightjarClient(identity, new MemorySessionStore(), new PrekeyStore(keys, lock), new ContactStore(keys, lock), lock, {
    onMessage: () => {},
  })
  // Stub the directory so fetchBundle returns whatever the test wired.
  const setBundle = (fn: (id: string) => FetchedBundle | null) => {
    ;(client as unknown as { directory: unknown }).directory = { fetchBundle: async (id: string) => ({ bundle: fn(id) }) }
  }
  return { client, setBundle }
}

describe('client.addContact (verify without a prior message)', () => {
  let peer: Identity
  beforeEach(() => {
    peer = generateIdentity()
  })

  it('records a TOFU (unverified) contact with the fetched key', async () => {
    const h = harness()
    const b = bundleFor(peer)
    h.setBundle((id) => (id === peer.userId ? b : null))

    expect(await h.client.trustOf(peer.userId)).toBeNull() // no contact yet
    await h.client.addContact(peer.userId)
    expect(await h.client.trustOf(peer.userId)).toBe('unverified') // now verifiable
    expect((await h.client.listContacts()).map((c) => c.peerId)).toContain(peer.userId)
  })

  it('throws when the peer is not registered (no bundle)', async () => {
    const h = harness()
    h.setBundle(() => null)
    await expect(h.client.addContact(peer.userId)).rejects.toThrow(/not registered/i)
  })

  it('fails closed when the directory serves a key that does not match the id', async () => {
    const h = harness()
    const impostorBundle = bundleFor(generateIdentity()) // a DIFFERENT identity's key
    h.setBundle(() => impostorBundle) // returned for whatever id we ask for
    await expect(h.client.addContact(peer.userId)).rejects.toThrow(/does not match/i)
    expect(await h.client.trustOf(peer.userId)).toBeNull() // nothing recorded
  })
})
