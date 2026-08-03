import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { utf8 } from './primitives'
import {
  MSG_MAGIC,
  decodeMessage,
  encodeDeleteMessage,
  encodeRefreshMessage,
  encodeRetryRequest,
  encodeTextMessage,
  newMsgId,
} from './message'

const ID = Uint8Array.from({ length: 16 }, (_, i) => i + 1)

describe('structured message payload (P10a)', () => {
  it('round-trips a text message (non-ephemeral and ephemeral)', () => {
    for (const eph of [false, true]) {
      const d = decodeMessage(encodeTextMessage(ID, 'hello world 😀', eph))
      expect(d.kind).toBe('text')
      if (d.kind !== 'text') return
      expect(bytesToHex(d.id)).toBe(bytesToHex(ID))
      expect(d.body).toBe('hello world 😀')
      expect(d.ephemeral).toBe(eph)
    }
  })

  it('round-trips a delete control message', () => {
    const d = decodeMessage(encodeDeleteMessage(ID))
    expect(d.kind).toBe('delete')
    if (d.kind !== 'delete') return
    expect(bytesToHex(d.id)).toBe(bytesToHex(ID))
  })

  it('round-trips a retry-request, which carries no target (8.10)', () => {
    const d = decodeMessage(encodeRetryRequest(ID))
    expect(d.kind).toBe('retry')
    if (d.kind !== 'retry') return
    // Its id identifies the record and addresses nothing: a device that could not
    // decrypt never learned a content id, so it CANNOT ask for a specific message.
    // That is the structural rate limit, and it lives in the wire format.
    expect(bytesToHex(d.id)).toBe(bytesToHex(ID))
    expect(encodeRetryRequest(ID)).toHaveLength(22)
  })

  it('a retry-request with anything appended is malformed, never a partial ask', () => {
    expect(decodeMessage(new Uint8Array([...encodeRetryRequest(ID), 0x00])).kind).toBe('malformed')
    expect(decodeMessage(encodeRetryRequest(ID).slice(0, 21)).kind).toBe('malformed')
  })

  it('the controls a 1.9.0 build cannot know read as malformed there, not as text', () => {
    // Forward compatibility is what lets a control be added at all: an older build
    // sees an unknown kind, renders and stores NOTHING, and still promotes the
    // session the record rode in on. Simulated by decoding with the kind byte an
    // older decoder would not recognise.
    for (const kind of [0x03, 0x04, 0x7f]) {
      const older = new Uint8Array([...MSG_MAGIC, 0x01, kind, ...ID])
      const decoded = decodeMessage(older)
      expect(decoded.kind === 'malformed' || decoded.kind === 'retry').toBe(true)
    }
    // The session-refresh kind is deliberately never taught to this decoder, so it
    // is malformed HERE too (its whole value is the initial it rides on).
    expect(decodeMessage(encodeRefreshMessage(ID)).kind).toBe('malformed')
  })

  it('treats a payload without the magic as legacy plain text', () => {
    const d = decodeMessage(utf8('just a normal old message'))
    expect(d).toEqual({ kind: 'legacy', body: 'just a normal old message' })
  })

  it('is a TOTAL function: malformed structured records never throw', () => {
    const bad = [
      MSG_MAGIC.slice(0, 3), // too short for magic -> legacy actually (no full magic)
      new Uint8Array([...MSG_MAGIC, 0x01]), // magic + version, truncated header
      new Uint8Array([...MSG_MAGIC, 0x99, 0x01, ...ID]), // unknown version -> malformed
      new Uint8Array([...MSG_MAGIC, 0x01, 0x09, ...ID]), // unknown kind -> malformed
      new Uint8Array([...MSG_MAGIC, 0x01, 0x01, ...ID]), // text kind, missing flags byte
      new Uint8Array([...MSG_MAGIC, 0x01, 0x02, ...ID, 0x00]), // delete with trailing byte
    ]
    for (const b of bad) {
      expect(() => decodeMessage(b)).not.toThrow()
    }
    // A 3-byte "magic" prefix is NOT the full magic, so it is legacy text.
    expect(decodeMessage(MSG_MAGIC.slice(0, 3)).kind).toBe('legacy')
    // The genuinely-structured-but-invalid ones are malformed.
    expect(decodeMessage(new Uint8Array([...MSG_MAGIC, 0x99, 0x01, ...ID])).kind).toBe('malformed')
    expect(decodeMessage(new Uint8Array([...MSG_MAGIC, 0x01, 0x09, ...ID])).kind).toBe('malformed')
    expect(decodeMessage(new Uint8Array([...MSG_MAGIC, 0x01, 0x01, ...ID])).kind).toBe('malformed')
    expect(decodeMessage(new Uint8Array([...MSG_MAGIC, 0x01, 0x02, ...ID, 0x00])).kind).toBe('malformed')
  })

  it('ignores reserved flag bits (forward-compat), reading only bit0', () => {
    // flags byte with bit0 set AND a reserved bit set -> still ephemeral, not malformed.
    const bytes = new Uint8Array([...MSG_MAGIC, 0x01, 0x01, ...ID, 0x03, ...utf8('hi')])
    const d = decodeMessage(bytes)
    expect(d.kind).toBe('text')
    if (d.kind === 'text') {
      expect(d.ephemeral).toBe(true)
      expect(d.body).toBe('hi')
    }
  })

  it('rejects an over-long body as malformed rather than allocating it as text', () => {
    const huge = new Uint8Array(65 * 1024).fill(0x41)
    const bytes = new Uint8Array([...MSG_MAGIC, 0x01, 0x01, ...ID, 0x00, ...huge])
    expect(decodeMessage(bytes).kind).toBe('malformed')
  })

  it('newMsgId returns 16 distinct random bytes', () => {
    const a = newMsgId()
    const b = newMsgId()
    expect(a.length).toBe(16)
    expect(bytesToHex(a)).not.toBe(bytesToHex(b))
  })

  it('encode rejects a wrong-width id', () => {
    expect(() => encodeTextMessage(new Uint8Array(15), 'x', false)).toThrow(/16 bytes/)
    expect(() => encodeDeleteMessage(new Uint8Array(17), )).toThrow(/16 bytes/)
  })
})
