// Restore staging tests (P8, DESIGN 8.3): ordering, wipe completeness, the
// one-shot flag lifecycle, and the binding re-check on imported contacts.

import { describe, expect, it } from 'vitest'
import { generateIdentity } from '../crypto/identity'
import type { BackupPayload } from '../crypto/backup'
import { b64encode } from '../wire/codec'
import type { Contact } from '../trust/contactStore'
import { ContactStore } from '../trust/contactStore'
import { IDENTITY_KEY, bootstrapIdentity } from './identityStore'
import { MemoryKeyStore } from './keystore'
import { InMemoryLock } from './lock'
import { MemorySentinel } from './persist'
import { PREKEYS_KEY } from './prekeyStore'
import { MemorySessionStore, singleSessionBook } from './sessionStore'
import type { RatchetSnapshot } from '../crypto/ratchet'
import { RESTORE_PENDING_KEY, clearPendingRestore, pendingRestore, stageRestore } from './restore'

const NOW = 1_700_000_000_000

const emptySnap: RatchetSnapshot = {
  dhsPriv: null,
  dhsPub: null,
  dhr: null,
  rk: '00'.repeat(32),
  cks: null,
  ckr: null,
  ns: 0,
  nr: 0,
  pn: 0,
  skipped: [],
  ad: 'aa'.repeat(8),
}

function contactFor(trust: Contact['trust']): Contact {
  const peer = generateIdentity()
  return { peerId: peer.userId, ikSig: b64encode(peer.ikSig.publicKey), trust, firstSeen: NOW, verifiedAt: null }
}

function deps() {
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  return {
    keys,
    lock,
    sessions: new MemorySessionStore(),
    contacts: new ContactStore(keys, lock),
    sentinel: new MemorySentinel(),
  }
}

describe('stageRestore', () => {
  it('wipes prior state, stages identity + contacts + flag, and the next bootstrap loads the restored identity', async () => {
    const d = deps()
    // Prior life on this device: an old identity, a session, stale prekeys.
    const old = generateIdentity()
    await d.keys.put(IDENTITY_KEY, Uint8Array.from({ length: 192 }, () => 1)) // garbage; replaced wholesale
    await d.keys.put(PREKEYS_KEY, Uint8Array.from([1, 2, 3]))
    await d.sessions.saveBookWithSeenReplay('peer', singleSessionBook(emptySnap), 'msg', 'init')
    await d.sessions.saveBookWithOutbox('peer', singleSessionBook(emptySnap), { id: 'o1', to: 'peer', env: {}, createdAt: NOW })

    const restored = generateIdentity()
    const good = contactFor('verified')
    const payload: BackupPayload = { identity: restored, contacts: [good], createdAt: NOW }
    await stageRestore(d, payload)

    // Old session-layer state is gone (replay dedup included: dead identity).
    expect(await d.sessions.loadBook('peer')).toBeNull()
    expect(await d.sessions.hasSeen('msg')).toBe(false)
    expect(await d.sessions.hasReplayedInitial('init')).toBe(false)
    expect(await d.sessions.pendingOutbox()).toEqual([])
    expect(await d.keys.get(PREKEYS_KEY)).toBeNull()

    // Flag is set, contacts staged, and bootstrap loads the restored identity.
    expect(await pendingRestore(d.keys)).toBe(true)
    expect((await d.contacts.get(good.peerId))?.trust).toBe('verified')
    const boot = await bootstrapIdentity(d.keys, d.sentinel, d.lock)
    expect(boot.state).toBe('loaded')
    expect(boot.identity?.userId).toBe(restored.userId)
    expect(boot.identity?.userId).not.toBe(old.userId)
  })

  it('re-checks the contact binding on import and drops rows that fail it', async () => {
    const d = deps()
    const good = contactFor('invite')
    const forged = { ...contactFor('verified'), peerId: generateIdentity().userId }
    await stageRestore(d, { identity: generateIdentity(), contacts: [good, forged], createdAt: NOW })
    expect(await d.contacts.get(good.peerId)).not.toBeNull()
    expect(await d.contacts.get(forged.peerId)).toBeNull()
  })

  it('flag lifecycle: pending until cleared, and clearing is idempotent', async () => {
    const d = deps()
    expect(await pendingRestore(d.keys)).toBe(false)
    await stageRestore(d, { identity: generateIdentity(), contacts: [], createdAt: NOW })
    expect(await pendingRestore(d.keys)).toBe(true)
    await clearPendingRestore(d.keys)
    expect(await pendingRestore(d.keys)).toBe(false)
    await clearPendingRestore(d.keys)
    expect(await pendingRestore(d.keys)).toBe(false)
    expect(await d.keys.get(RESTORE_PENDING_KEY)).toBeNull()
  })

  it('a second concurrent stageRestore serializes behind the identity lock (last write wins, no interleave)', async () => {
    const d = deps()
    const a = generateIdentity()
    const b = generateIdentity()
    await Promise.all([
      stageRestore(d, { identity: a, contacts: [], createdAt: NOW }),
      stageRestore(d, { identity: b, contacts: [], createdAt: NOW }),
    ])
    const boot = await bootstrapIdentity(d.keys, d.sentinel, d.lock)
    expect(boot.state).toBe('loaded')
    // One of the two, atomically; the sentinel + flag are consistent either way.
    expect([a.userId, b.userId]).toContain(boot.identity?.userId)
    expect(await pendingRestore(d.keys)).toBe(true)
  })
})
