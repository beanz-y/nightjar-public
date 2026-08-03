// The geometry the camera decoder reads at.
//
// This is arithmetic that fails silently: an off-centre crop or a swapped axis
// does not throw, it just means the code is never in the part of the frame being
// examined and nothing ever decodes, which looks exactly like a camera that has
// not been aimed properly. So it is pinned here rather than trusted.

import { describe, expect, it } from 'vitest'
import { cropRect } from './qrDecode'

describe('the square the decoder reads', () => {
  it('takes the centre of a landscape frame, which is what the preview shows', () => {
    // Both previews are square elements with object-fit: cover, so the strips
    // left and right of this are not on screen and must not be searched.
    const r = cropRect(1920, 1080, 1024)
    expect(r.side).toBe(1080)
    expect(r.sx).toBe(420) // (1920 - 1080) / 2
    expect(r.sy).toBe(0)
    // Landscape means the horizontal offset is the one that moves.
    expect(r.sx * 2 + r.side).toBe(1920)
  })

  it('takes the centre of a portrait frame too', () => {
    const r = cropRect(1080, 1920, 1024)
    expect(r.side).toBe(1080)
    expect(r.sx).toBe(0)
    expect(r.sy).toBe(420)
    expect(r.sy * 2 + r.side).toBe(1920)
  })

  it('caps the size handed to the decoder, because that cost sets the scan rate', () => {
    // jsQR is O(pixels) on the main thread. A full 1080p frame drags the loop
    // down to a few attempts a second, and the code being read changes several
    // times a second, so a slow loop misses most of them however well it is aimed.
    expect(cropRect(1920, 1080, 1024).edge).toBe(1024)
    expect(cropRect(3840, 2160, 1024).edge).toBe(1024)
  })

  it('never scales a small frame UP, which would add no detail and cost time', () => {
    const r = cropRect(640, 480, 1024)
    expect(r.side).toBe(480)
    expect(r.edge).toBe(480)
  })

  it('handles a frame that is already square', () => {
    const r = cropRect(720, 720, 1024)
    expect(r).toMatchObject({ sx: 0, sy: 0, side: 720, edge: 720 })
  })

  it('keeps the crop inside the frame at odd sizes', () => {
    // An odd difference must not produce a fractional origin: getImageData on a
    // fractional rect samples between pixels and softens exactly the edges a
    // finder pattern is recognised by.
    const r = cropRect(1281, 721, 1024)
    expect(Number.isInteger(r.sx)).toBe(true)
    expect(Number.isInteger(r.sy)).toBe(true)
    expect(r.sx + r.side).toBeLessThanOrEqual(1281)
    expect(r.sy + r.side).toBeLessThanOrEqual(721)
  })
})
