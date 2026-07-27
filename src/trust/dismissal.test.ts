// Deleting a contact has to STAY deleted. The mutual invite (DESIGN 6.3) re-learns
// anyone who redeemed one of your invites on every connect, reading the relay's
// record, so without a marker a deleted contact silently returns within about a
// minute and keeps returning for as long as the relay retains that invite.
//
// The marker is deliberately narrow, and these tests pin both halves of that:
// it refuses only the RELAY-DRIVEN paths, and it never stops the peer themselves
// or the user from bringing the contact back. Nightjar has no block, and a delete
// must not quietly become one.

import { describe, expect, it } from 'vitest'
import { generateIdentity } from '../crypto/identity'
import { MemoryKeyStore } from '../storage/keystore'
import { InMemoryLock } from '../storage/lock'
import { ContactStore } from './contactStore'

// Real wall-clock: dismissals expire 30 days after the deletion, so a fixture
// dated years in the past would be pruned the moment it was read.
const NOW = Date.now()
const fresh = () => new ContactStore(new MemoryKeyStore(), new InMemoryLock())

describe('deleting a contact', () => {
  it('removes the contact, its verification, and its nickname', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.markVerified(a.userId, NOW)
    await store.setAlias(a.userId, 'Gran')

    await store.remove(a.userId, NOW)

    expect(await store.get(a.userId)).toBeNull()
    expect(await store.trustLevel(a.userId)).toBeNull()
    expect(await store.getAliases()).toEqual({})
  })

  it('drops parked pending-trust work for that peer, and only that peer', async () => {
    // Otherwise the retry loop would re-add them on the next connect.
    const store = fresh()
    const gone = generateIdentity()
    const kept = generateIdentity()
    await store.mutatePendingTrust((p) => {
      p.inviterPin = gone.userId
      p.records = [
        { peerId: gone.userId, ikSig: 'x' },
        { peerId: kept.userId, ikSig: 'y' },
      ]
    })

    await store.remove(gone.userId, NOW)

    const pending = await store.getPendingTrust()
    expect(pending.inviterPin).toBeUndefined()
    expect(pending.records.map((r) => r.peerId)).toEqual([kept.userId])
  })

  it('REFUSES a relay-driven re-add: the mutual invite cannot resurrect them', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.remove(a.userId, NOW)

    // This is what syncInviteContacts does on every connect.
    const recorded = await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW + 1000, 'unverified', true)

    expect(recorded).toBe(false)
    expect(await store.get(a.userId)).toBeNull()
  })

  it('does not gate a non-relay-driven record, so a peer can be re-learned as a stranger', async () => {
    // Delete is not block: this is the store-level path taken whenever a message
    // genuinely arrives from the peer, or the user adds them back. Because a delete
    // KEEPS the ratchet session (DESIGN 8.9), the usual arrival is a `normal`
    // message, which reaches here via client.recoverContact rather than
    // handleInitial. Either way the record is written and the marker is lifted.
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.markVerified(a.userId, NOW)
    await store.remove(a.userId, NOW)

    const recorded = await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW + 5000)

    expect(recorded).toBe(true)
    // Back at square one: the in-person verification does not survive a delete.
    expect(await store.trustLevel(a.userId)).toBe('unverified')
  })

  it('lets the USER add them back, and lifts the relay block once they do', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.remove(a.userId, NOW)
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW + 100) // user re-adds

    // Deleting them again must re-arm it, or a second delete would not stick.
    await store.remove(a.userId, NOW + 200)
    expect(await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW + 300, 'unverified', true)).toBe(false)
  })

  it('keeps the deletion TIMESTAMP after a re-add, for the stale-prekey guard', async () => {
    // The send path needs it: re-establishing inside the directory's vend window
    // would otherwise reuse a one-time prekey the peer already consumed.
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.remove(a.userId, NOW)
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW + 100)

    expect(await store.dismissedAt(a.userId)).toBe(NOW)
  })

  it('records whether a session existed, so the prekey guard cannot fire on a peer who consumed nothing', async () => {
    // A peer deleted before any session existed never consumed a one-time prekey, so
    // stripping it from their next handshake would downgrade a healthy exchange to
    // the degraded no-OPK path for nothing.
    const store = fresh()
    const withSession = generateIdentity()
    const never = generateIdentity()
    await store.markDismissed(withSession.userId, NOW, true)
    await store.markDismissed(never.userId, NOW, false)

    expect(await store.getDismissal(withSession.userId)).toEqual({ at: NOW, hadSession: true })
    expect(await store.getDismissal(never.userId)).toEqual({ at: NOW, hadSession: false })
    expect(await store.getDismissal(generateIdentity().userId)).toBeNull()
  })

  it('remove() preserves the session flag markDismissed recorded', async () => {
    // deleteConversation calls markDismissed (while the book is still readable) and
    // then remove(); the second write must not flatten what the first learned.
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.markDismissed(a.userId, NOW, true)

    await store.remove(a.userId, NOW + 1)

    expect(await store.getDismissal(a.userId)).toEqual({ at: NOW + 1, hadSession: true })
  })

  it('does NOT erase the whole list when it cannot be read', async () => {
    // The housekeeping pass used to treat an unreadable blob as an empty one and
    // delete it, which would let the mutual invite re-learn every deleted contact.
    const keys = new MemoryKeyStore()
    const store = new ContactStore(keys, new InMemoryLock())
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.remove(a.userId, NOW)

    const raw = await keys.get('contacts.dismissed.v1')
    expect(raw).not.toBeNull()
    // Corrupt it the way a wrong key or a partial write would.
    await keys.put('contacts.dismissed.v1', new Uint8Array([0x7b, 0xff, 0x00, 0x01]))

    await store.pruneDismissals()

    expect(await keys.get('contacts.dismissed.v1')).not.toBeNull() // left alone, not destroyed
  })

  it('blocks the inviter-pin retry too, not just the redemption sync', async () => {
    // addInviteContact records at 'invite' trust. Its RETRY path is relay-driven, so
    // it must be refused as well: otherwise deleting your inviter would re-add them
    // at a HIGHER trust level than a normal re-add, and clear the marker doing it.
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW, 'invite')
    await store.remove(a.userId, NOW)

    expect(await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW + 10, 'invite', true)).toBe(false)
    expect(await store.get(a.userId)).toBeNull()
  })

  it('markDismissed arms the marker without touching the contact map', async () => {
    // Written before the session is destroyed, so an interrupted delete still leaves
    // the guard that keeps a re-establishment off the peer's consumed prekey.
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)

    await store.markDismissed(a.userId, NOW)

    expect(await store.dismissedAt(a.userId)).toBe(NOW)
    expect(await store.get(a.userId)).not.toBeNull() // contact still there at this point
  })

  it('does not gate anyone else', async () => {
    const store = fresh()
    const gone = generateIdentity()
    const other = generateIdentity()
    await store.recordFirstContact(gone.userId, gone.ikSig.publicKey, NOW)
    await store.remove(gone.userId, NOW)

    expect(await store.recordFirstContact(other.userId, other.ikSig.publicKey, NOW, 'unverified', true)).toBe(true)
    expect(await store.trustLevel(other.userId)).toBe('unverified')
  })

  it('is forgotten by the forgot-secret reset, which cannot keep sealed state', async () => {
    // wipeLocalData discards everything sealed under the old key. The marker has to
    // go with it, or it would be unopenable ciphertext under the new one.
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.remove(a.userId, NOW)
    await store.wipeLocalData()

    expect(await store.dismissedAt(a.userId)).toBeNull()
    expect(await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW, 'unverified', true)).toBe(true)
  })

  it('does not follow a restored identity onto this device', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.remove(a.userId, NOW)

    await store.replaceAllFromBackup([])

    expect(await store.dismissedAt(a.userId)).toBeNull()
  })

  it('scrubs expired markers from DISK, not just from reads', async () => {
    // The 30-day bound is a claim about what is stored, so filtering on read is not
    // enough on its own: the blob has to be rewritten.
    const store = fresh()
    const old = generateIdentity()
    const recent = generateIdentity()
    await store.recordFirstContact(old.userId, old.ikSig.publicKey, NOW)
    await store.recordFirstContact(recent.userId, recent.ikSig.publicKey, NOW)
    await store.remove(old.userId, Date.now() - 31 * 24 * 60 * 60 * 1000)
    await store.remove(recent.userId, NOW)

    await store.pruneDismissals()

    expect(await store.dismissedAt(old.userId)).toBeNull()
    expect(await store.dismissedAt(recent.userId)).toBe(NOW) // the live one survives
  })

  it('expires, so it never becomes a permanent list of everyone you deleted', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    // Deleted long enough ago that the relay's own invite record is gone too.
    await store.remove(a.userId, Date.now() - 31 * 24 * 60 * 60 * 1000)

    expect(await store.dismissedAt(a.userId)).toBeNull()
    expect(await store.recordFirstContact(a.userId, a.ikSig.publicKey, Date.now(), 'unverified', true)).toBe(true)
  })
})
