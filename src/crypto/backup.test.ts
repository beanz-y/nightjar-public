// Backup blob tests (P8, DESIGN 8.3). Tests run with REDUCED Argon2id memory
// (m = 1024 KiB) so the suite stays fast; the construction is identical and one
// pinned KAT locks the full chain (header layout, AAD scope, argon2id -> HKDF
// key/nonce split) against silent change. Production parameters are pinned in
// constants.ts and exercised once in the round-trip-with-defaults test below,
// which is why this file's slowest test runs a real 64 MiB derivation.

import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { PASSPHRASE_MIN_LENGTH } from './constants'
import { generateIdentity } from './identity'
import type { Contact } from '../trust/contactStore'
import { b64encode } from '../wire/codec'
import {
  BackupAuthError,
  deriveKeyNonce,
  generateBackupPassphrase,
  normalizePassphrase,
  openBackup,
  parseBackupHeader,
  passphraseIssue,
  sealBackup,
} from './backup'

const NOW = 1_700_000_000_000
// Fast test parameters: the SMALLEST values the decoder accepts (8 MiB, one
// pass), so open() exercises the same validation path as production blobs.
const FAST = { m: 8192, t: 1, p: 1 }
const PASS = 'correct-horse-battery-staple'

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

describe('backup blob (P8)', () => {
  it('round-trips identity + contacts under the production parameters', async () => {
    const id = generateIdentity()
    const contacts = [contactFor('verified'), contactFor('invite')]
    const blob = await sealBackup(id, contacts, PASS, { createdAt: NOW })
    const opened = await openBackup(blob, PASS)
    expect(opened.droppedContacts).toBe(0)
    expect(opened.payload.identity.userId).toBe(id.userId)
    expect(bytesToHex(opened.payload.identity.ikSig.privateKey)).toBe(bytesToHex(id.ikSig.privateKey))
    expect(bytesToHex(opened.payload.identity.ikDh.privateKey)).toBe(bytesToHex(id.ikDh.privateKey))
    expect(opened.payload.contacts).toEqual(contacts)
    expect(opened.payload.createdAt).toBe(NOW)
  }, 30_000)

  it('rejects the wrong passphrase and any single-byte tamper (header or body)', async () => {
    const id = generateIdentity()
    const salt = new Uint8Array(16).fill(7)
    const blob = await sealBackup(id, [], PASS, { createdAt: NOW, salt, params: FAST })

    await expect(openBackup(blob, PASS + 'x')).rejects.toBeInstanceOf(BackupAuthError)

    // Body tamper -> auth failure.
    const body = blob.slice()
    body[blob.length - 1] ^= 1
    await expect(openBackup(body, PASS)).rejects.toBeInstanceOf(BackupAuthError)

    // Salt tamper (inside the AAD) -> derives a different key -> auth failure.
    const saltFlip = blob.slice()
    saltFlip[12] ^= 1
    await expect(openBackup(saltFlip, PASS)).rejects.toBeInstanceOf(BackupAuthError)

    // Params tamper (m lowered a notch but still in range) -> the KDF output
    // changes AND the AAD changes; either way it must not authenticate.
    const mFlip = blob.slice()
    mFlip[8] ^= 1
    await expect(openBackup(mFlip, PASS)).rejects.toThrow()
  }, 30_000)

  it('bounds-checks hostile parameters BEFORE any KDF work', () => {
    const goodHeader = (m: number, t: number, p: number) => {
      const b = new Uint8Array(27 + 16)
      b.set([0x4e, 0x4a, 0x42, 0x4b, 0x01]) // "NJBK", v1
      b[5] = (m >>> 24) & 0xff
      b[6] = (m >>> 16) & 0xff
      b[7] = (m >>> 8) & 0xff
      b[8] = m & 0xff
      b[9] = t
      b[10] = p
      return b
    }
    // 4 GiB memory bomb, absurd pass count, multi-lane: all refused at parse.
    expect(() => parseBackupHeader(goodHeader(4 * 1024 * 1024, 3, 1))).toThrow(/memory parameter/)
    expect(() => parseBackupHeader(goodHeader(1024, 3, 1))).toThrow(/memory parameter/)
    expect(() => parseBackupHeader(goodHeader(65536, 200, 1))).toThrow(/pass count/)
    expect(() => parseBackupHeader(goodHeader(65536, 3, 4))).toThrow(/lane count/)
    expect(() => parseBackupHeader(new Uint8Array(10))).toThrow(/too short/)
    const wrongMagic = goodHeader(65536, 3, 1)
    wrongMagic[0] = 0x58
    expect(() => parseBackupHeader(wrongMagic)).toThrow(/not a Nightjar backup/)
    const futureVersion = goodHeader(65536, 3, 1)
    futureVersion[4] = 2
    expect(() => parseBackupHeader(futureVersion)).toThrow(/not supported/)
  })

  it('pinned KAT: header byte layout', async () => {
    const id = generateIdentity()
    const salt = Uint8Array.from({ length: 16 }, (_, i) => i + 1)
    const blob = await sealBackup(id, [], 'kat-passphrase-12', { createdAt: NOW, salt, params: FAST })
    expect(bytesToHex(blob.slice(0, 27))).toBe(
      '4e4a424b' + // NJBK
        '01' + // format v1
        '00002000' + // m = 8192 KiB
        '01' + // t = 1
        '01' + // p = 1
        '0102030405060708090a0b0c0d0e0f10', // salt
    )
    const opened = await openBackup(blob, 'kat-passphrase-12')
    expect(opened.payload.identity.userId).toBe(id.userId)
  })

  it('pinned KAT: locks the argon2id->HKDF->key||nonce derivation (golden value)', async () => {
    // A round-trip alone cannot catch a symmetric change (seal + open share
    // deriveKeyNonce); this pins the derived bytes against a golden value, so any
    // change to the key/nonce split, INFO_BACKUP, the HKDF salt, or removal of
    // the HKDF layer FAILS here. Fixed inputs, real argon2id at small params.
    const salt = Uint8Array.from({ length: 16 }, (_, i) => i + 1)
    const { key, nonce } = await deriveKeyNonce('kat-passphrase-12', salt, FAST)
    expect(bytesToHex(key) + bytesToHex(nonce)).toBe(
      '18983d58f7eab7097c36696fd2af00cd5ebc0a98ade7fef354f7543ed7a61cc5' + // key (32B)
        '5250a8e2f3f76ef3aba459cd86485aa43c508dfdee524332', // nonce (24B)
    )
  })

  it('accepts an NFD-typed passphrase for an NFC-sealed blob (normalization)', async () => {
    const id = generateIdentity()
    const nfc = 'café-passphrase-x' // e-acute composed
    const nfd = 'café-passphrase-x' // e + combining acute
    expect(nfd).not.toBe(nfc)
    expect(normalizePassphrase(nfd)).toBe(normalizePassphrase(nfc))
    const blob = await sealBackup(id, [], nfc, { params: FAST })
    const opened = await openBackup(blob, `  ${nfd} `) // plus paste-artifact whitespace
    expect(opened.payload.identity.userId).toBe(id.userId)
  })

  it('drops (and counts) a contact row whose key does not hash to its userId, keeping the rest', async () => {
    const id = generateIdentity()
    const good = contactFor('invite')
    const evil = { ...contactFor('verified'), peerId: generateIdentity().userId } // key/id mismatch
    const blob = await sealBackup(id, [good, evil], PASS, { params: FAST })
    const opened = await openBackup(blob, PASS)
    expect(opened.droppedContacts).toBe(1)
    expect(opened.payload.contacts).toEqual([good])
  })

  it('passphrase floor and generated passphrases', () => {
    expect(passphraseIssue('short')).toMatch(new RegExp(String(PASSPHRASE_MIN_LENGTH)))
    expect(passphraseIssue('   padded-but-short   '.slice(0, PASSPHRASE_MIN_LENGTH - 1) + '   ')).not.toBeNull()
    expect(passphraseIssue('a'.repeat(PASSPHRASE_MIN_LENGTH))).toBeNull()

    const p1 = generateBackupPassphrase()
    const p2 = generateBackupPassphrase()
    expect(p1).toMatch(/^[a-z2-7]{4}(-[a-z2-7]{4}){4}$/)
    expect(p1).not.toBe(p2) // 100 bits: a collision here means randomBytes broke
    expect(passphraseIssue(p1)).toBeNull()
  })
})
