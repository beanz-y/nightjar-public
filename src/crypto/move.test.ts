// Move-package tests (Phase D, DESIGN 8.3). Same discipline as backup.test.ts:
// reduced Argon2id memory keeps the suite fast, one independently computed KAT
// pins the whole canonicalize -> argon2id -> HKDF chain, and the parse ORDER
// (bounds before KDF, authenticate before parse, discriminator before fields)
// is pinned by tests because each ordering is load-bearing.

import { afterEach, describe, expect, it, vi } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { MOVE_MAX_PAYLOAD_BYTES } from './constants'
import { generateIdentity, serializeIdentity } from './identity'
import { aeadSeal, concatBytes, u32be, utf8 } from './primitives'
import type { Contact } from '../trust/contactStore'
import { b64encode } from '../wire/codec'
import { sealBackup } from './backup'
import type { HistoryUnitMessage } from './historyUnit'
import {
  MoveAuthError,
  canonicalizeMovePassphrase,
  decodeMovePayload,
  deriveMoveKeyNonce,
  encodeMovePayload,
  openMove,
  parseMoveHeader,
  sealMove,
} from './move'

const NOW = 1_700_000_000_000
const FAST = { m: 8192, t: 1, p: 1 }
const PASS = 'abcd-efgh-2345-qrs7-tuv2'

function contactFor(trust: Contact['trust'] = 'verified'): Contact {
  const peer = generateIdentity()
  return {
    peerId: peer.userId,
    ikSig: b64encode(peer.ikSig.publicKey),
    trust,
    firstSeen: NOW - 1000,
    verifiedAt: trust === 'verified' ? NOW - 500 : null,
  }
}

function msgFor(peer: string, over: Partial<HistoryUnitMessage> = {}): HistoryUnitMessage {
  return { id: 'a1'.repeat(16), peer, dir: 'in', ts: NOW - 1000, text: 'hello', ...over }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('move package (Phase D)', () => {
  it('round-trips the full payload', async () => {
    const id = generateIdentity()
    const alice = contactFor('verified')
    const bob = contactFor('unverified')
    const aliases = { [alice.peerId]: 'mom' }
    const dismissals = { [bob.peerId]: { at: NOW - 9000, auto: false } }
    const messages = [
      msgFor(alice.peerId),
      msgFor(alice.peerId, { id: 'b2'.repeat(16), dir: 'out', ts: NOW - 500, text: 'back', status: 'sent' }),
    ]
    const blob = await sealMove(
      { identity: id, contacts: [alice, bob], aliases, dismissals, messages },
      PASS,
      { createdAt: NOW, params: FAST },
    )
    const opened = await openMove(blob, PASS, { now: NOW })
    expect(opened.payload.identity.userId).toBe(id.userId)
    expect(bytesToHex(opened.payload.identity.ikSig.privateKey)).toBe(bytesToHex(id.ikSig.privateKey))
    expect(opened.payload.contacts).toEqual([alice, bob])
    expect(opened.payload.aliases).toEqual(aliases)
    expect(opened.payload.dismissals).toEqual(dismissals)
    expect(opened.payload.messages).toEqual(messages)
    expect(opened.payload.createdAt).toBe(NOW)
    expect(opened.dropped).toEqual({ contacts: 0, aliases: 0, dismissals: 0, messages: 0, collapsed: 0 })
  }, 30_000)

  it('canonicalizes the typed passphrase (pinned mapping) and opens under any typing of it', async () => {
    expect(canonicalizeMovePassphrase(' ABCD-EFGH-2345-Q RS7 tuv2 ')).toBe('abcdefgh2345qrs7tuv2')
    const id = generateIdentity()
    const blob = await sealMove(
      { identity: id, contacts: [], aliases: {}, dismissals: {}, messages: [] },
      'abcdefgh2345qrs7tuv2',
      { createdAt: NOW, params: FAST },
    )
    const opened = await openMove(blob, 'ABCD EFGH 2345 QRS7 TUV2', { now: NOW })
    expect(opened.payload.identity.userId).toBe(id.userId)
  }, 30_000)

  it('pins the KDF chain against an independently computed known answer', async () => {
    // Computed by hand from the primitives (scratch script, not this module):
    // canonicalize(' ABCD-EFGH-2345-Q RS7 tuv2 ') -> abcdefgh2345qrs7tuv2,
    // argon2id(m=8192,t=1,p=1) with salt 16x0x0a, HKDF zeros / Nightjar_Move_v1.
    const { key, nonce } = await deriveMoveKeyNonce(' ABCD-EFGH-2345-Q RS7 tuv2 ', new Uint8Array(16).fill(0x0a), FAST)
    expect(bytesToHex(key)).toBe('8272bb28edb3bd496906386b78b0d7f3366547fc51ab8a2c8e49980c9c1674be')
    expect(bytesToHex(nonce)).toBe('11b5c244e31c1803f61b88c0303c2e0e4cec55fa2dc530ef')
  })

  it('refuses an empty-after-normalization passphrase before any KDF work', async () => {
    const kdf = vi.fn()
    await expect(deriveMoveKeyNonce('!!! 189 ---', new Uint8Array(16), FAST, kdf)).rejects.toThrow(
      'empty after normalization',
    )
    expect(kdf).not.toHaveBeenCalled()
  })

  it('rejects the wrong passphrase and any single-byte tamper', async () => {
    const id = generateIdentity()
    const blob = await sealMove({ identity: id, contacts: [], aliases: {}, dismissals: {}, messages: [] }, PASS, {
      createdAt: NOW,
      params: FAST,
    })
    await expect(openMove(blob, PASS + 'z', { now: NOW })).rejects.toBeInstanceOf(MoveAuthError)
    const tampered = blob.slice()
    tampered[tampered.length - 1] ^= 1
    await expect(openMove(tampered, PASS, { now: NOW })).rejects.toBeInstanceOf(MoveAuthError)
    const saltFlip = blob.slice()
    saltFlip[12] ^= 1
    await expect(openMove(saltFlip, PASS, { now: NOW })).rejects.toBeInstanceOf(MoveAuthError)
  }, 30_000)

  it('never parses a payload that did not authenticate', async () => {
    const id = generateIdentity()
    const blob = await sealMove({ identity: id, contacts: [], aliases: {}, dismissals: {}, messages: [] }, PASS, {
      createdAt: NOW,
      params: FAST,
    })
    const tampered = blob.slice()
    tampered[tampered.length - 1] ^= 1
    const parse = vi.spyOn(JSON, 'parse')
    await expect(openMove(tampered, PASS, { now: NOW })).rejects.toBeInstanceOf(MoveAuthError)
    expect(parse).not.toHaveBeenCalled()
  }, 30_000)

  it('survives an authenticated nesting bomb as a clean format error', async () => {
    // Seal hostile bytes under the real key: deep nesting must land in the
    // decoder's try/catch as MoveFormatError, never a crash.
    const salt = new Uint8Array(16).fill(3)
    const { key, nonce } = await deriveMoveKeyNonce(PASS, salt, FAST)
    const header = concatBytes(utf8('NJMV'), Uint8Array.from([0x01]), u32be(FAST.m), Uint8Array.from([FAST.t, FAST.p]), salt)
    const bomb = utf8('['.repeat(200_000))
    const blob = concatBytes(header, aeadSeal(key, nonce, bomb, header))
    await expect(openMove(blob, PASS, { now: NOW })).rejects.toThrow('not valid JSON')
  })

  it('bounds-checks hostile headers BEFORE any KDF work', () => {
    const good = concatBytes(utf8('NJMV'), Uint8Array.from([0x01]), u32be(FAST.m), Uint8Array.from([FAST.t, FAST.p]), new Uint8Array(16))
    const withBody = (h: Uint8Array) => concatBytes(h, new Uint8Array(16))
    expect(() => parseMoveHeader(new Uint8Array(10))).toThrow('too short')
    const badVersion = withBody(good.slice())
    badVersion[4] = 0x02
    expect(() => parseMoveHeader(badVersion)).toThrow('not supported')
    const hugeM = withBody(good.slice())
    hugeM[5] = 0xff // m far above BACKUP_MAX_M_KIB
    expect(() => parseMoveHeader(hugeM)).toThrow('memory parameter')
    const zeroT = withBody(good.slice())
    zeroT[9] = 0
    expect(() => parseMoveHeader(zeroT)).toThrow('pass count')
    const twoLanes = withBody(good.slice())
    twoLanes[10] = 2
    expect(() => parseMoveHeader(twoLanes)).toThrow('lane count')
    expect(() => parseMoveHeader(new Uint8Array(27 + MOVE_MAX_PAYLOAD_BYTES + 65))).toThrow('implausibly large')
  })

  it('names the cross-format mistake in both directions', async () => {
    const id = generateIdentity()
    const backupBlob = await sealBackup(id, [], PASS, { createdAt: NOW, params: FAST })
    await expect(openMove(backupBlob, PASS, { now: NOW })).rejects.toThrow('identity backup')
    const moveBlob = await sealMove({ identity: id, contacts: [], aliases: {}, dismissals: {}, messages: [] }, PASS, {
      createdAt: NOW,
      params: FAST,
    })
    const { openBackup } = await import('./backup')
    await expect(openBackup(moveBlob, PASS)).rejects.toThrow('move file')
  }, 30_000)

  it('requires the payload discriminator before reading any field', () => {
    // A backup-shaped payload (v:1, identity, contacts) with no t: must be
    // rejected as "not a move payload", not decoded as an empty move.
    const impostor = utf8(
      JSON.stringify({ v: 1, createdAt: NOW, identity: b64encode(new Uint8Array(192)), contacts: [] }),
    )
    expect(() => decodeMovePayload(impostor, NOW)).toThrow('not a move payload')
    const wrongV = utf8(JSON.stringify({ t: 'njmv', v: 2, identity: b64encode(new Uint8Array(192)) }))
    expect(() => decodeMovePayload(wrongV, NOW)).toThrow('version unsupported')
  })

  it('drops history rows naming a peer the file does not introduce as a contact', async () => {
    const id = generateIdentity()
    const known = contactFor()
    const stranger = generateIdentity().userId
    const blob = await sealMove(
      {
        identity: id,
        contacts: [known],
        aliases: {},
        dismissals: {},
        messages: [msgFor(known.peerId), msgFor(stranger, { id: 'c3'.repeat(16) })],
      },
      PASS,
      { createdAt: NOW, params: FAST },
    )
    const opened = await openMove(blob, PASS, { now: NOW })
    expect(opened.payload.messages).toHaveLength(1)
    expect(opened.payload.messages[0].peer).toBe(known.peerId)
    expect(opened.dropped.messages).toBe(1)
  }, 30_000)

  it('validates nicknames and deletion markers (junk keys dropped, future markers clamped, auto defaulted)', () => {
    const id = generateIdentity()
    const c = contactFor()
    const wire = {
      t: 'njmv',
      v: 1,
      createdAt: NOW,
      identity: b64encode(serializeIdentity(id)),
      contacts: [{ peerId: c.peerId, ikSig: c.ikSig, trust: c.trust, firstSeen: c.firstSeen, verifiedAt: c.verifiedAt }],
      aliases: { [c.peerId]: '  ' + 'n'.repeat(200), 'not-a-user-id': 'x' },
      dismissals: {
        [c.peerId]: { at: NOW + 999_999_999 },
        'also-bad-key': { at: NOW },
      },
      history: { t: 'njhist', hv: 1, messages: [] },
    }
    const opened = decodeMovePayload(utf8(JSON.stringify(wire)), NOW)
    expect(opened.payload.aliases[c.peerId]).toHaveLength(60)
    expect(Object.keys(opened.payload.aliases)).toEqual([c.peerId])
    expect(opened.dropped.aliases).toBe(1) // the junk key; __proto__ never survives JSON+guards
    expect(opened.payload.dismissals[c.peerId]).toEqual({ at: NOW, auto: true })
    expect(opened.dropped.dismissals).toBe(1)
  })

  it('refuses over-cap payloads rather than truncating', () => {
    const id = generateIdentity()
    const tooManyContacts = Array.from({ length: 1001 }, () => contactFor())
    expect(() => encodeMovePayload(id, tooManyContacts, {}, {}, [], NOW)).toThrow('too many contacts')
  })
})
