// Following a contact's account-key rotation, client side.
//
// A rotation gives one person a new account id, and this is the half that makes
// "rotation preserves the relationship" true of the stored state rather than only
// of the protocol. If saved messages, the name you gave them and a dismissal do
// not move, the conversation splits into a dead half and a live half with nothing
// saying they are the same person, which is exactly the outcome rotation exists to
// avoid.
//
// Note what deliberately does NOT move: trust, and sessions. Trust cannot be
// carried because an attacker holding the old key can sign a rotation as validly
// as the owner, so carrying a verified badge across would hand it to them.
// Sessions do not need to: they are keyed by DEVICE, and a rotation changes the
// account key, not the devices.

import { describe, expect, it } from 'vitest'
import { accountIdOf, generateIdentity } from '../crypto/identity'
import { hash256 } from '../crypto/primitives'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'
import { b64encode } from '../wire/codec'
import { decodeMessage, encodeRotationMessage, newMsgId } from '../crypto/message'
import { type RotationStatement, signRotation, verifyRotation } from '../crypto/rotation'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

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
  const client = new NightjarClient(identity, store, prekeys, contacts, lock, { onMessage: () => {} }, history)
  return { client, contacts, store, history }
}

/** Save a message the way the receive path does, so the row under test is a real
 *  sealed row at a real opaque key rather than a fixture. */
async function save(
  h: Awaited<ReturnType<typeof harness>>,
  peer: string,
  dir: 'in' | 'out',
  id: string,
  text: string,
): Promise<void> {
  await h.store.historyPutMany([h.history.seal({ id, peerId: peer, dir, ts: 1000, text })])
}

async function messagesFor(h: Awaited<ReturnType<typeof harness>>, peer: string): Promise<string[]> {
  const rows = await h.store.historyLoadAll()
  return rows
    .map((r) => h.history.open(r))
    .filter((m) => m.peerId === peer)
    .map((m) => m.text)
    .sort()
}

describe('following a rotation', () => {
  it('moves the conversation, the name and the dismissal to the new account id', async () => {
    const h = await harness()
    const before = generateIdentity()
    const after = generateIdentity()
    const oldId = accountIdOf(before.ikSig.publicKey)
    const newId = accountIdOf(after.ikSig.publicKey)

    await h.contacts.recordFirstContact(oldId, before.ikSig.publicKey, 1000)
    await h.contacts.markVerified(oldId, 1000)
    await h.contacts.setAlias(oldId, 'Sam')
    await save(h, oldId, 'in', 'm1', 'first')
    await save(h, oldId, 'out', 'm2', 'second')
    await save(h, accountIdOf(generateIdentity().ikSig.publicKey), 'in', 'm3', 'somebody else')

    const { moved } = await h.client.applyRotation(oldId, newId, b64encode(after.ikSig.publicKey))

    expect(moved).toBe(2)
    expect(await messagesFor(h, newId)).toEqual(['first', 'second'])
    expect(await messagesFor(h, oldId)).toEqual([]) // nothing left behind
    expect((await h.contacts.getAliases())[newId]).toBe('Sam')
    expect(await h.contacts.get(oldId)).toBeNull()
    const now = await h.contacts.get(newId)
    expect(now?.peerId).toBe(newId)
    // Somebody else's conversation is untouched.
    expect((await h.store.historyLoadAll()).length).toBe(3)
  })

  it('lands the new binding as UNVERIFIED, whatever the old one was', async () => {
    // The load-bearing rule. An attacker holding the old account key can sign a
    // rotation exactly as validly as the owner, so a verification carried across
    // would be handed to whoever wrote the statement.
    const h = await harness()
    const before = generateIdentity()
    const after = generateIdentity()
    const oldId = accountIdOf(before.ikSig.publicKey)
    const newId = accountIdOf(after.ikSig.publicKey)
    await h.contacts.recordFirstContact(oldId, before.ikSig.publicKey, 1000)
    await h.contacts.markVerified(oldId, 1000)
    expect((await h.contacts.get(oldId))?.trust).toBe('verified')

    await h.client.applyRotation(oldId, newId, b64encode(after.ikSig.publicKey))

    expect((await h.contacts.get(newId))?.trust).toBe('unverified')
  })

  it('refuses a rename whose id and key disagree', async () => {
    // The same binding the protocol enforces: an account id IS the hash of its
    // key, so a rename that does not satisfy it is not a rotation.
    const h = await harness()
    const before = generateIdentity()
    const after = generateIdentity()
    const oldId = accountIdOf(before.ikSig.publicKey)
    await h.contacts.recordFirstContact(oldId, before.ikSig.publicKey, 1000)

    const wrongId = accountIdOf(generateIdentity().ikSig.publicKey)
    expect(await h.contacts.renameAccount(oldId, wrongId, b64encode(after.ikSig.publicKey))).toBe(false)
    expect(await h.contacts.get(oldId)).not.toBeNull()
  })

  it('will not merge into an account that is already a contact', async () => {
    // Two conversations becoming one is the user's decision, not something to do
    // silently underneath them.
    const h = await harness()
    const before = generateIdentity()
    const other = generateIdentity()
    const oldId = accountIdOf(before.ikSig.publicKey)
    const otherId = accountIdOf(other.ikSig.publicKey)
    await h.contacts.recordFirstContact(oldId, before.ikSig.publicKey, 1000)
    await h.contacts.recordFirstContact(otherId, other.ikSig.publicKey, 1000)

    expect(await h.contacts.renameAccount(oldId, otherId, b64encode(other.ikSig.publicKey))).toBe(false)
    expect(await h.contacts.get(oldId)).not.toBeNull()
    expect(await h.contacts.get(otherId)).not.toBeNull()
  })

  it('finishes a rename that was interrupted', async () => {
    // The marker is written before any row moves and cleared after the last one,
    // so a resume can always finish. Re-running a completed step is a no-op,
    // because a row that already moved is not at the old key any more.
    const h = await harness()
    const before = generateIdentity()
    const after = generateIdentity()
    const oldId = accountIdOf(before.ikSig.publicKey)
    const newId = accountIdOf(after.ikSig.publicKey)
    await h.contacts.recordFirstContact(oldId, before.ikSig.publicKey, 1000)
    await save(h, oldId, 'in', 'm1', 'stranded')
    // A rename that got as far as the marker and then died.
    await h.contacts.setPendingRename(oldId, { newId, ikSig: b64encode(after.ikSig.publicKey) })
    expect(Object.keys(await h.contacts.pendingRenames())).toEqual([oldId])

    await h.client.resumePendingRenames()

    expect(await messagesFor(h, newId)).toEqual(['stranded'])
    expect(await h.contacts.get(newId)).not.toBeNull()
    expect(await h.contacts.pendingRenames()).toEqual({})
  })

  it('announces itself in bytes a receiver can check on their own', async () => {
    // The statement rides INSIDE the message, so the receiver verifies it under
    // the key they already hold rather than on the say-so of the session it
    // arrived over. Round-tripped through the real decoder here.
    const before = generateIdentity()
    const after = generateIdentity()
    const st = signRotation(accountIdOf(before.ikSig.publicKey), before.ikSig.privateKey, after.ikSig, 1000)
    const decoded = decodeMessage(encodeRotationMessage(newMsgId(), st))

    expect(decoded.kind).toBe('rotation')
    if (decoded.kind !== 'rotation') return
    expect(decoded.statement).toEqual(st)
    // And it verifies under the OLD key, which is the only key a contact has.
    expect(() => verifyRotation(decoded.statement, before.ikSig.publicKey, 2000)).not.toThrow()
  })

  it('is clean-ignored by a build that predates it', () => {
    // Forward compatibility, the same promise every other kind here relies on: an
    // older client classifies an unknown kind as malformed and drops it, rather
    // than rendering it as text or failing the whole message.
    const before = generateIdentity()
    const after = generateIdentity()
    const st = signRotation(accountIdOf(before.ikSig.publicKey), before.ikSig.privateKey, after.ikSig, 1000)
    const bytes = encodeRotationMessage(newMsgId(), st)
    const truncated = bytes.slice(0, bytes.length - 1)
    expect(decodeMessage(truncated).kind).toBe('malformed')
  })

  it('ignores a rotation announced on somebody else’s behalf', async () => {
    // A contact may only rotate THEIR account. Without this check, anyone you
    // talk to could re-file any other conversation you hold.
    const h = await harness()
    const victim = generateIdentity()
    const attacker = generateIdentity()
    const target = generateIdentity()
    const victimId = accountIdOf(victim.ikSig.publicKey)
    const attackerId = accountIdOf(attacker.ikSig.publicKey)
    await h.contacts.recordFirstContact(victimId, victim.ikSig.publicKey, 1000)
    await h.contacts.recordFirstContact(attackerId, attacker.ikSig.publicKey, 1000)
    await save(h, victimId, 'in', 'm1', 'still here')

    // A statement about the VICTIM, genuinely signed by the victim's key would be
    // needed; the attacker cannot make one, so they replay the shape with their
    // own. Either way it arrives on the ATTACKER's session.
    const st = signRotation(attackerId, attacker.ikSig.privateKey, target.ikSig, 1000)
    const asIfFromVictim = { ...st, oldAccountId: victimId }
    await (
      h.client as unknown as { handleRotation(from: string, s: RotationStatement): Promise<void> }
    ).handleRotation(victimId, asIfFromVictim)

    expect(await messagesFor(h, victimId)).toEqual(['still here'])
    expect(await h.contacts.get(victimId)).not.toBeNull()
  })

  it('ignores a rotation that does not verify under the key we already hold', async () => {
    const h = await harness()
    const contact = generateIdentity()
    const impostor = generateIdentity()
    const target = generateIdentity()
    const contactId = accountIdOf(contact.ikSig.publicKey)
    await h.contacts.recordFirstContact(contactId, contact.ikSig.publicKey, 1000)
    await save(h, contactId, 'in', 'm1', 'still here')

    // Signed by an impostor, then relabelled to claim the contact's account.
    const forged = signRotation(accountIdOf(impostor.ikSig.publicKey), impostor.ikSig.privateKey, target.ikSig, 1000)
    await (
      h.client as unknown as { handleRotation(from: string, s: RotationStatement): Promise<void> }
    ).handleRotation(contactId, { ...forged, oldAccountId: contactId })

    expect(await messagesFor(h, contactId)).toEqual(['still here'])
    expect(await h.contacts.get(contactId)).not.toBeNull()
  })

  it('follows a genuine rotation from the contact it names', async () => {
    const h = await harness()
    const contact = generateIdentity()
    const after = generateIdentity()
    const oldId = accountIdOf(contact.ikSig.publicKey)
    const newId = accountIdOf(after.ikSig.publicKey)
    await h.contacts.recordFirstContact(oldId, contact.ikSig.publicKey, 1000)
    await save(h, oldId, 'in', 'm1', 'carried across')

    const st = signRotation(oldId, contact.ikSig.privateKey, after.ikSig, Date.now())
    await (
      h.client as unknown as { handleRotation(from: string, s: RotationStatement): Promise<void> }
    ).handleRotation(oldId, st)

    expect(await messagesFor(h, newId)).toEqual(['carried across'])
    expect((await h.contacts.get(newId))?.trust).toBe('unverified')
  })

  it('is idempotent, so running it twice changes nothing', async () => {
    const h = await harness()
    const before = generateIdentity()
    const after = generateIdentity()
    const oldId = accountIdOf(before.ikSig.publicKey)
    const newId = accountIdOf(after.ikSig.publicKey)
    await h.contacts.recordFirstContact(oldId, before.ikSig.publicKey, 1000)
    await save(h, oldId, 'in', 'm1', 'once')

    await h.client.applyRotation(oldId, newId, b64encode(after.ikSig.publicKey))
    await h.client.applyRotation(oldId, newId, b64encode(after.ikSig.publicKey))

    expect(await messagesFor(h, newId)).toEqual(['once'])
    expect((await h.store.historyLoadAll()).length).toBe(1)
  })
})
