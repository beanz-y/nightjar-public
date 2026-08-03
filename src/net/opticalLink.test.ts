// The optical link transfer, all the way through (Sesame B1).
//
// Every layer below has its own tests: the fountain code reassembles blocks, the
// QR encoder round-trips against an independent decoder, the link envelope opens
// only under its own secret. What nothing covered until now is the WHOLE path
// joined up, which is the only thing the user actually performs:
//
//   seal -> fountain frames -> QR symbols -> [a camera] -> QR decode ->
//   fountain reassembly -> open under the scanned secret
//
// The camera is the one link in that chain a test cannot stand in for. Everything
// on either side of it is exercised here against the REAL encoder and a
// DIFFERENT decoder (jsQR), so a frame that only this project can read would fail.

import { describe, expect, it } from 'vitest'
import jsQR from 'jsqr'
import { openLink, sealLink } from '../crypto/link'
import { LINK_MAX_PAYLOAD_BYTES, LINK_SECRET_BYTES } from '../crypto/constants'
import { ed25519Public, randomBytes } from '../crypto/primitives'
import { accountIdOf, generateIdentity } from '../crypto/identity'
import { FountainDecoder } from './fountain'
import { BLOCK_BYTES, frameCount, opticalFrame, parseOpticalFrame } from './opticalFrames'
import { qrMatrix } from '../ui/qr'

/** Render a frame the way the sending screen does, then read it back the way a
 *  camera-side decoder would. Deliberately jsQR rather than our own encoder in
 *  reverse: a symbol only we can read would pass a self-check and fail on a phone. */
function throughAScreen(text: string): string | null {
  const m = qrMatrix(text, 'L')
  const n = m.length
  const quiet = 4
  const dim = n + quiet * 2
  const data = new Uint8ClampedArray(dim * dim * 4)
  for (let y = 0; y < dim; y++) {
    for (let x = 0; x < dim; x++) {
      const inside = y >= quiet && y < quiet + n && x >= quiet && x < quiet + n
      const dark = inside && m[y - quiet][x - quiet]
      const v = dark ? 0 : 255
      const i = (y * dim + x) * 4
      data[i] = v
      data[i + 1] = v
      data[i + 2] = v
      data[i + 3] = 255
    }
  }
  return jsQR(data, dim, dim)?.data ?? null
}

function linkPayload(contacts: number) {
  const account = generateIdentity()
  const rows = Array.from({ length: contacts }, () => {
    const c = generateIdentity()
    return { peerId: c.userId, ikSig: Buffer.from(c.ikSig.publicKey).toString('base64url') }
  })
  return {
    accountId: accountIdOf(account.ikSig.publicKey),
    accountKeyPriv: account.ikSig.privateKey,
    contacts: rows,
    aliases: {} as Record<string, string>,
    createdAt: Date.now(),
  }
}

describe('handing an account to a new device over a screen', () => {
  it('survives seal, frames, real QR symbols and reassembly', async () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const payload = linkPayload(3)
    // ONE sealed unit, which is what makes the optical path need no reassembly
    // format of its own.
    const chunks = sealLink(payload, secret, LINK_MAX_PAYLOAD_BYTES)
    expect(chunks).toHaveLength(1)
    const blob = chunks[0]

    const transferId = randomBytes(8)
    const decoder = new FountainDecoder()
    let done: Uint8Array | null = null
    // A clean capture costs exactly the systematic pass, which is the case worth
    // being fast: frames 0..K-1 ARE the blocks.
    for (let seq = 0; seq < frameCount(blob.length) && !done; seq++) {
      const scanned = throughAScreen(opticalFrame(blob, transferId, seq))
      expect(scanned).not.toBeNull()
      const frame = parseOpticalFrame(scanned as string)
      expect(frame).not.toBeNull()
      done = decoder.push(frame as Uint8Array)
    }
    expect(done).not.toBeNull()

    const opened = openLink([done as Uint8Array], secret)
    expect(opened.accountId).toBe(payload.accountId)
    expect(opened.accountKeyPriv).toEqual(payload.accountKeyPriv)
    expect(accountIdOf(ed25519Public(opened.accountKeyPriv))).toBe(payload.accountId)
    expect(opened.contacts.map((c) => c.peerId)).toEqual(payload.contacts.map((c) => c.peerId))
  })

  it('recovers when the camera misses part of the first pass', async () => {
    // The realistic case: a hand moves, the screen glares, focus hunts. Frames
    // past the systematic pass are combinations, and the receiver repairs the gaps
    // from them without anything asking for a repeat, because there is no back
    // channel to ask on.
    const secret = randomBytes(LINK_SECRET_BYTES)
    // Enough contacts to need several blocks, or there is nothing to miss.
    const payload = linkPayload(90)
    const blob = sealLink(payload, secret, LINK_MAX_PAYLOAD_BYTES)[0]
    expect(blob.length).toBeGreaterThan(BLOCK_BYTES)

    const transferId = randomBytes(8)
    const decoder = new FountainDecoder()
    let done: Uint8Array | null = null
    let seq = 0
    // Drop every third frame, and keep going well past the systematic pass.
    while (!done && seq < 400) {
      if (seq % 3 !== 1) {
        const scanned = throughAScreen(opticalFrame(blob, transferId, seq))
        const frame = scanned ? parseOpticalFrame(scanned) : null
        if (frame) done = decoder.push(frame)
      }
      seq++
    }
    expect(done).not.toBeNull()
    expect(openLink([done as Uint8Array], secret).accountId).toBe(payload.accountId)
  })

  it('refuses a transfer read off somebody else screen', async () => {
    // The receiving device holds the only copy of the secret it generated, so a
    // perfectly readable stream from a different ceremony reassembles fine and
    // then fails to open, which is where it should fail.
    const mine = randomBytes(LINK_SECRET_BYTES)
    const theirs = randomBytes(LINK_SECRET_BYTES)
    const blob = sealLink(linkPayload(1), theirs, LINK_MAX_PAYLOAD_BYTES)[0]

    const transferId = randomBytes(8)
    const decoder = new FountainDecoder()
    let done: Uint8Array | null = null
    for (let seq = 0; seq < frameCount(blob.length) && !done; seq++) {
      const scanned = throughAScreen(opticalFrame(blob, transferId, seq))
      done = decoder.push(parseOpticalFrame(scanned as string) as Uint8Array)
    }
    expect(done).not.toBeNull() // reassembly is not where this is caught
    expect(() => openLink([done as Uint8Array], mine)).toThrow()
  })
})
