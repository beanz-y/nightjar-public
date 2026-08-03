// The text layer between the fountain and the QR encoder.
//
// The reason this layer exists at all is worth pinning: a camera-side decoder
// hands back a STRING, and the native BarcodeDetector reads byte mode as UTF-8
// with no way to reach the underlying bytes. So a frame has to survive being
// decoded as text, and these tests are what stop that quietly regressing into a
// binary frame that works in the pure-JS fallback and breaks on real phones.

import { describe, expect, it } from 'vitest'
import { randomBytes } from '../crypto/primitives'
import { qrCapacityBytes } from '../ui/qr'
import { BLOCK_BYTES, FRAME_BYTES, frameCount, opticalFrame, parseOpticalFrame } from './opticalFrames'
import { FountainDecoder } from './fountain'

describe('optical frames', () => {
  it('fits inside a symbol even after base64 has taken its third', () => {
    const capacity = qrCapacityBytes('L', 40)
    const payload = randomBytes(BLOCK_BYTES * 3)
    const id = randomBytes(8)
    for (const seq of [0, 1, 2, 99]) {
      const text = opticalFrame(payload, id, seq)
      expect(text.length).toBeLessThanOrEqual(capacity)
    }
  })

  it('survives the round trip a decoder actually performs, through text', () => {
    // The trip that matters: bytes to a string, back to bytes, and the payload
    // still reassembles. Anything binary-only would pass a direct byte test and
    // fail here.
    const payload = randomBytes(BLOCK_BYTES * 4 + 11)
    const id = randomBytes(8)
    const d = new FountainDecoder()
    let out: Uint8Array | null = null
    for (let seq = 0; seq < 20 && !out; seq++) {
      const asText = opticalFrame(payload, id, seq)
      expect(typeof asText).toBe('string')
      const frame = parseOpticalFrame(asText)
      expect(frame).not.toBeNull()
      out = d.push(frame as Uint8Array)
    }
    expect(out).toEqual(payload)
  })

  it('carries far more per frame than the old encoder ceiling', () => {
    // The whole reason the encoder was extended: ~180 bytes was unusable for
    // anything but a short code.
    expect(BLOCK_BYTES).toBeGreaterThan(2000)
    expect(FRAME_BYTES).toBeGreaterThan(BLOCK_BYTES)
  })

  it('ignores anything that is not one of our frames, without complaining', () => {
    // A camera pointed at a room sees invite codes, wifi codes and posters. None
    // of them are errors.
    expect(parseOpticalFrame('not base64 at all !!')).toBeNull()
    expect(parseOpticalFrame('')).toBeNull()
    expect(parseOpticalFrame('aGVsbG8gd29ybGQ')).toBeNull() // valid base64, wrong shape
  })

  it('estimates the frame count from the payload', () => {
    expect(frameCount(1)).toBe(1)
    expect(frameCount(BLOCK_BYTES)).toBe(1)
    expect(frameCount(BLOCK_BYTES + 1)).toBe(2)
  })
})
