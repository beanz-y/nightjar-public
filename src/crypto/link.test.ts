// Linking a device: the code and the transfer (Sesame).
//
// The secret in the code is the only thing standing between a new device and the
// relay, so these tests are mostly about what happens when the relay misbehaves:
// altering a chunk, replaying one, splicing two transfers, or handing over a
// payload that was never sealed for this device at all.

import { describe, expect, it } from 'vitest'
import { LINK_MAX_CHUNK_BYTES, LINK_SECRET_BYTES } from './constants'
import { accountIdOf, deviceIdOf, generateIdentity } from './identity'
import {
  LINK_HEADER_LEN,
  type LinkPayload,
  LinkAuthError,
  LinkFormatError,
  openLink,
  readLinkChunkHeader,
  sealLink,
} from './link'
import { LinkCodeError, newLinkCode, parseLinkCode } from '../trust/linkCode'
import { randomBytes } from './primitives'
import { b64encode } from '../wire/codec'

const account = generateIdentity()

function payloadWith(contacts: LinkPayload['contacts'] = [], aliases: Record<string, string> = {}): LinkPayload {
  return {
    accountId: account.userId,
    accountKeyPriv: account.ikSig.privateKey,
    contacts,
    aliases,
    createdAt: 1_700_000_000_000,
  }
}

function contactRow() {
  const peer = generateIdentity()
  return { peerId: peer.userId, ikSig: b64encode(peer.ikSig.publicKey) }
}

describe('the link code', () => {
  it('round-trips, and derives the device id from the key rather than carrying it', () => {
    const device = generateIdentity()
    const { code, parsed } = newLinkCode(device.ikSig.publicKey)
    const scanned = parseLinkCode(code)
    expect(scanned.deviceId).toBe(deviceIdOf(device.ikSig.publicKey))
    expect(scanned.dkSigPub).toEqual(device.ikSig.publicKey)
    expect(scanned.secret).toEqual(parsed.secret)
    expect(scanned.secret).toHaveLength(LINK_SECRET_BYTES)
  })

  it('gives every link its own secret', () => {
    const device = generateIdentity()
    const a = newLinkCode(device.ikSig.publicKey)
    const b = newLinkCode(device.ikSig.publicKey)
    expect(a.parsed.secret).not.toEqual(b.parsed.secret)
  })

  it('refuses anything that is not exactly one of ours', () => {
    const device = generateIdentity()
    const { code } = newLinkCode(device.ikSig.publicKey)
    // A truncated scan must be refused, not read as a shorter secret.
    expect(() => parseLinkCode(code.slice(0, code.length - 4))).toThrow(LinkCodeError)
    expect(() => parseLinkCode(`${code}AAAA`)).toThrow(LinkCodeError)
    expect(() => parseLinkCode('not a code at all')).toThrow(LinkCodeError)
    expect(() => parseLinkCode('')).toThrow(LinkCodeError)
  })
})

describe('the link transfer', () => {
  it('round-trips a payload through one chunk', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const rows = [contactRow(), contactRow()]
    const chunks = sealLink(payloadWith(rows, { [rows[0].peerId]: 'mum' }), secret)
    expect(chunks).toHaveLength(1)

    const opened = openLink(chunks, secret)
    expect(opened.accountId).toBe(account.userId)
    expect(opened.accountKeyPriv).toEqual(account.ikSig.privateKey)
    expect(opened.contacts.map((c) => c.peerId).sort()).toEqual(rows.map((r) => r.peerId).sort())
    expect(opened.aliases[rows[0].peerId]).toBe('mum')
  })

  it('splits a large payload and reassembles it in any order', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    // Enough contacts to cross the chunk boundary.
    const rows = Array.from({ length: 400 }, contactRow)
    const chunks = sealLink(payloadWith(rows), secret)
    expect(chunks.length).toBeGreaterThan(1)
    expect(chunks.every((c) => c.length <= LINK_HEADER_LEN + LINK_MAX_CHUNK_BYTES + 16)).toBe(true)

    const shuffled = [...chunks].reverse()
    expect(openLink(shuffled, secret).contacts).toHaveLength(rows.length)
    // Duplicates are harmless: a relay may redeliver.
    expect(openLink([...shuffled, ...chunks], secret).contacts).toHaveLength(rows.length)
  })

  it('will not open with the wrong secret', () => {
    const chunks = sealLink(payloadWith([contactRow()]), randomBytes(LINK_SECRET_BYTES))
    expect(() => openLink(chunks, randomBytes(LINK_SECRET_BYTES))).toThrow(LinkAuthError)
  })

  it('notices a chunk that was altered in flight', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const chunks = sealLink(payloadWith([contactRow()]), secret)
    const tampered = new Uint8Array(chunks[0])
    tampered[tampered.length - 1] ^= 1
    expect(() => openLink([tampered], secret)).toThrow(LinkAuthError)
    // And a header edit, which the AAD covers just as tightly.
    const reheaded = new Uint8Array(chunks[0])
    reheaded[5] ^= 1 // first byte of the transfer id
    expect(() => openLink([reheaded], secret)).toThrow(LinkAuthError)
  })

  it('refuses chunks spliced from two different transfers', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const rows = Array.from({ length: 400 }, contactRow)
    const first = sealLink(payloadWith(rows), secret)
    const second = sealLink(payloadWith(rows), secret)
    expect(first.length).toBeGreaterThan(1)
    // Same secret, same shape, different transfer: still refused, because the
    // transfer id is inside every chunk's authenticated header.
    expect(() => openLink([first[0], second[1]], secret)).toThrow(/different transfers/)
  })

  it('refuses an incomplete transfer rather than opening what it has', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const chunks = sealLink(payloadWith(Array.from({ length: 400 }, contactRow)), secret)
    expect(() => openLink(chunks.slice(1), secret)).toThrow(/incomplete/)
  })

  it('reads a chunk header without the secret, and bounds it', () => {
    // A receiver has to be able to group and bound a transfer before deciding to
    // open anything, so header parsing is deliberately keyless.
    const chunks = sealLink(payloadWith(), randomBytes(LINK_SECRET_BYTES))
    const h = readLinkChunkHeader(chunks[0])
    expect(h).toEqual({ transferId: expect.any(String), index: 0, count: 1 })
    expect(() => readLinkChunkHeader(new Uint8Array(10))).toThrow(LinkFormatError)
    const notOurs = new Uint8Array(chunks[0])
    notOurs[0] ^= 1
    expect(() => readLinkChunkHeader(notOurs)).toThrow(/not a link transfer/)
  })

  it('refuses a payload whose account key does not match the account it claims', () => {
    // Otherwise a device would join an account under a key that cannot sign for
    // it, and would silently be unable to change the device list ever after.
    const secret = randomBytes(LINK_SECRET_BYTES)
    const other = generateIdentity()
    const chunks = sealLink({ ...payloadWith(), accountId: other.userId }, secret)
    expect(() => openLink(chunks, secret)).toThrow(/does not match the account/)
  })

  it('drops a contact row whose key does not hash to its id, and keeps the rest', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const good = contactRow()
    const bad = { peerId: generateIdentity().userId, ikSig: b64encode(generateIdentity().ikSig.publicKey) }
    const opened = openLink(sealLink(payloadWith([good, bad]), secret), secret)
    expect(opened.contacts.map((c) => c.peerId)).toEqual([good.peerId])
  })

  it('carries no trust at all, because a device earns its own', () => {
    // Dan's decision, and the difference from a move file: a move keeps your
    // verifications because it replaces a device; a link does not, because it adds
    // one, and nothing remote may mark a contact verified here.
    const secret = randomBytes(LINK_SECRET_BYTES)
    const row = contactRow()
    const opened = openLink(sealLink(payloadWith([row]), secret), secret)
    expect(Object.keys(opened.contacts[0]).sort()).toEqual(['ikSig', 'peerId'])
    expect(JSON.stringify(opened)).not.toContain('verified')
  })

  it('keeps a nickname only for a contact that survived', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const row = contactRow()
    const stranger = generateIdentity().userId
    const opened = openLink(sealLink(payloadWith([row], { [row.peerId]: 'dad', [stranger]: 'ghost' }), secret), secret)
    expect(opened.aliases).toEqual({ [row.peerId]: 'dad' })
  })

  it('rejects a secret of the wrong width on both sides', () => {
    expect(() => sealLink(payloadWith(), randomBytes(16))).toThrow(LinkFormatError)
    const chunks = sealLink(payloadWith(), randomBytes(LINK_SECRET_BYTES))
    expect(() => openLink(chunks, randomBytes(16))).toThrow(LinkFormatError)
  })

  it('binds the account id to the key, which is what makes the link meaningful', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const opened = openLink(sealLink(payloadWith(), secret), secret)
    expect(accountIdOf(account.ikSig.publicKey)).toBe(opened.accountId)
  })
})
