// client.syncInviteContacts (the mutual-invite fix): the inviter fetches who
// redeemed its invites and records each unknown joiner as a TOFU ('unverified')
// contact, so it can verify them WITHOUT waiting for a first message. These tests
// cover the orchestration (dedupe, known-skip, self-exclusion, malformed-id skip,
// the registered gate, best-effort failure, and surfacing a key conflict); the
// real 'unverified' recording is covered by addContact.test.ts and the relay/self
// tests exercise it end to end.

import { describe, expect, it } from 'vitest'
import { type Identity, generateIdentity } from '../crypto/identity'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore, KeyConflictError } from '../trust/contactStore'
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
  const sec: string[] = []
  let changed = 0
  const client = new NightjarClient(identity, new MemorySessionStore(), new PrekeyStore(keys, lock), new ContactStore(keys, lock), lock, {
    onMessage: () => {},
    onSecurity: (d) => sec.push(d),
    onContactsChanged: () => {
      changed++
    },
  })
  // Pretend the socket is up + registered (the sync is gated on it).
  ;(client as unknown as { authed: unknown }).authed = { registered: true, opkCount: 0, pushKey: null }

  let joiners: string[] = []
  let fetchCount = 0
  const bundles = new Map<string, FetchedBundle>()
  ;(client as unknown as { directory: unknown }).directory = {
    inviteRedemptions: async () => joiners,
    fetchBundle: async (id: string) => {
      fetchCount++
      return { bundle: bundles.get(id) ?? null }
    },
  }

  return {
    client,
    sec,
    setJoiners: (j: string[]) => {
      joiners = j
    },
    addPeer: (id: Identity): string => {
      bundles.set(id.userId, bundleFor(id))
      return id.userId
    },
    changedCount: () => changed,
    fetchCount: () => fetchCount,
  }
}

describe('client.syncInviteContacts (mutual invite)', () => {
  it('records each unknown joiner as an unverified contact and fires onContactsChanged once', async () => {
    const h = harness()
    const b1 = generateIdentity()
    const b2 = generateIdentity()
    h.addPeer(b1)
    h.addPeer(b2)
    h.setJoiners([b1.userId, b2.userId])

    expect(await h.client.syncInviteContacts()).toBe(2)
    expect(await h.client.trustOf(b1.userId)).toBe('unverified')
    expect(await h.client.trustOf(b2.userId)).toBe('unverified')
    expect(h.changedCount()).toBe(1)
  })

  it('skips already-known joiners without re-fetching a bundle', async () => {
    const h = harness()
    const b = generateIdentity()
    h.addPeer(b)
    h.setJoiners([b.userId])

    expect(await h.client.syncInviteContacts()).toBe(1) // first learns them
    const fetchesAfterFirst = h.fetchCount()
    expect(await h.client.syncInviteContacts()).toBe(0) // now known: nothing new
    expect(h.fetchCount()).toBe(fetchesAfterFirst) // and no wasted bundle fetch
    expect(h.changedCount()).toBe(1) // no spurious refresh on the second pass
  })

  it('dedupes a joiner that appears more than once (single fetch)', async () => {
    const h = harness()
    const b = generateIdentity()
    h.addPeer(b)
    h.setJoiners([b.userId, b.userId, b.userId])

    expect(await h.client.syncInviteContacts()).toBe(1)
    expect(h.fetchCount()).toBe(1)
  })

  it('never adds itself, even if the relay reports the caller as a joiner', async () => {
    const h = harness()
    h.setJoiners([h.client.userId])
    expect(await h.client.syncInviteContacts()).toBe(0)
    expect(h.fetchCount()).toBe(0)
  })

  it('skips a malformed joiner id without a bundle fetch', async () => {
    const h = harness()
    h.setJoiners(['not-a-valid-user-id'])
    expect(await h.client.syncInviteContacts()).toBe(0)
    expect(h.fetchCount()).toBe(0)
  })

  it('does nothing when not yet registered', async () => {
    const h = harness()
    ;(h.client as unknown as { authed: unknown }).authed = { registered: false }
    const b = generateIdentity()
    h.addPeer(b)
    h.setJoiners([b.userId])
    expect(await h.client.syncInviteContacts()).toBe(0)
    expect(h.fetchCount()).toBe(0)
  })

  it('is best-effort: a directory failure resolves to 0, never throws', async () => {
    const h = harness()
    ;(h.client as unknown as { directory: unknown }).directory = {
      inviteRedemptions: async () => {
        throw new Error('relay unreachable')
      },
    }
    await expect(h.client.syncInviteContacts()).resolves.toBe(0)
  })

  it('skips a joiner whose bundle has not propagated yet, and learns them on a later sync', async () => {
    const h = harness()
    const ready = generateIdentity()
    const notYet = generateIdentity()
    h.addPeer(ready) // bundle available now
    // notYet has NO bundle yet -> fetchBundle returns null -> addContact throws a
    // plain "not registered" error (NOT a key conflict): the common real-world race.
    h.setJoiners([ready.userId, notYet.userId])

    expect(await h.client.syncInviteContacts()).toBe(1) // only the propagated one lands
    expect(await h.client.trustOf(ready.userId)).toBe('unverified')
    expect(await h.client.trustOf(notYet.userId)).toBeNull() // not recorded, no leak
    expect(h.sec).toHaveLength(0) // a missing bundle is not a security event
    expect(h.changedCount()).toBe(1)

    // Their bundle propagates; a later sync learns them (retried on the next connect).
    h.addPeer(notYet)
    expect(await h.client.syncInviteContacts()).toBe(1)
    expect(await h.client.trustOf(notYet.userId)).toBe('unverified')
  })

  it('surfaces a key conflict via onSecurity and keeps processing the rest', async () => {
    const h = harness()
    const bad = generateIdentity()
    const good = generateIdentity()
    // A conflict is unreachable under honest operation (userId == hash(IK_sig)), so
    // stub addContact to force the branch and prove it is not silently swallowed.
    ;(h.client as unknown as { addContact: (peerId: string) => Promise<void> }).addContact = async (peerId: string) => {
      if (peerId === bad.userId) throw new KeyConflictError(peerId)
    }
    h.setJoiners([bad.userId, good.userId])

    expect(await h.client.syncInviteContacts()).toBe(1) // good landed, bad did not
    expect(h.sec).toHaveLength(1)
    expect(h.sec[0]).toMatch(/verify safety numbers/i)
  })
})
