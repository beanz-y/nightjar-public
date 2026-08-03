// Optical transfer, the reassembly layer.
//
// A camera watching a screen misses frames, and there is no back channel to ask
// for a repeat, so every test here is a way of losing frames: dropping them,
// seeing them out of order, joining a stream that is already running, or being
// shown someone else's transfer at the same time.

import { describe, expect, it } from 'vitest'
import { randomBytes } from '../crypto/primitives'
import { FRAME_HEADER_LEN, FountainDecoder, FountainError, coveredBlocks, encodeFrame, readFrameHeader } from './fountain'

const BLOCK = 256

function transfer(payload: Uint8Array, blockSize = BLOCK, id = randomBytes(8)) {
  return {
    id,
    frame: (seq: number) => encodeFrame(payload, id, blockSize, seq),
    blocks: Math.max(1, Math.ceil(payload.length / blockSize)),
  }
}

/** Feed frames from `seq = 0` upward, skipping any the filter rejects, until the
 *  decoder completes or we give up. Returns the payload and how many it took. */
function run(t: ReturnType<typeof transfer>, keep: (seq: number) => boolean, limit = 4000) {
  const d = new FountainDecoder()
  for (let seq = 0; seq < limit; seq++) {
    if (!keep(seq)) continue
    const out = d.push(t.frame(seq))
    if (out) return { out, frames: seq + 1 }
  }
  return { out: null, frames: limit }
}

describe('optical frames', () => {
  it('round-trips a payload with nothing lost, using exactly one frame per block', () => {
    // The common case: good light, steady hands. The systematic first pass means
    // a clean capture wastes nothing at all.
    const payload = randomBytes(BLOCK * 10)
    const t = transfer(payload)
    const { out, frames } = run(t, () => true)
    expect(out).toEqual(payload)
    expect(frames).toBe(10)
  })

  it('recovers from dropped frames without anyone asking for a repeat', () => {
    const payload = randomBytes(BLOCK * 12)
    const t = transfer(payload)
    // A third of the first pass missed, which no ordered scheme could survive
    // without a back channel.
    const { out } = run(t, (seq) => seq % 3 !== 0)
    expect(out).toEqual(payload)
  })

  it('decodes a stream joined late, having missed the whole systematic pass', () => {
    // Pointing a camera at a code already running is the normal way this is used.
    const payload = randomBytes(BLOCK * 8)
    const t = transfer(payload)
    const { out } = run(t, (seq) => seq >= t.blocks)
    expect(out).toEqual(payload)
  })

  it('does not care what order frames arrive in', () => {
    const payload = randomBytes(BLOCK * 6)
    const t = transfer(payload)
    const d = new FountainDecoder()
    let out: Uint8Array | null = null
    for (const seq of [5, 0, 3, 1, 4, 2]) out = d.push(t.frame(seq)) ?? out
    expect(out).toEqual(payload)
  })

  it('treats a repeated frame as free, not as progress', () => {
    const payload = randomBytes(BLOCK * 4)
    const t = transfer(payload)
    const d = new FountainDecoder()
    for (let i = 0; i < 10; i++) expect(d.push(t.frame(0))).toBeNull()
    expect(d.progress).toEqual({ have: 1, need: 4 })
  })

  it('handles a payload that does not divide evenly, trimming the padding', () => {
    const payload = randomBytes(BLOCK * 3 + 17)
    const t = transfer(payload)
    const { out } = run(t, () => true)
    expect(out).toEqual(payload)
    expect(out).toHaveLength(BLOCK * 3 + 17)
  })

  it('handles a payload smaller than one block', () => {
    const payload = randomBytes(9)
    const { out } = run(transfer(payload), () => true)
    expect(out).toEqual(payload)
  })

  it('reports progress while it is still going', () => {
    const payload = randomBytes(BLOCK * 5)
    const t = transfer(payload)
    const d = new FountainDecoder()
    expect(d.progress).toEqual({ have: 0, need: 0 })
    d.push(t.frame(0))
    expect(d.progress).toEqual({ have: 1, need: 5 })
    expect(d.done).toBe(false)
  })

  it('ignores a transfer other than the one it locked onto', () => {
    // Two people linking devices side by side must not feed each other halves.
    const mine = randomBytes(BLOCK * 4)
    const theirs = randomBytes(BLOCK * 4)
    const a = transfer(mine)
    const b = transfer(theirs)
    const d = new FountainDecoder()
    let out: Uint8Array | null = null
    for (let seq = 0; seq < 4; seq++) {
      out = d.push(a.frame(seq)) ?? out
      d.push(b.frame(seq)) // interleaved noise from the next table over
    }
    expect(out).toEqual(mine)
    // It locks onto whichever it sees FIRST and ignores the rest, so a camera
    // that catches the other stream first simply decodes that one instead. Either
    // way it never mixes the two.
    const reversed = new FountainDecoder()
    let other: Uint8Array | null = null
    for (let seq = 0; seq < 4; seq++) {
      other = reversed.push(b.frame(seq)) ?? other
      reversed.push(a.frame(seq))
    }
    expect(other).toEqual(theirs)
  })

  it('refuses frames that claim the same transfer with a different shape', () => {
    const d = new FountainDecoder()
    const id = randomBytes(8)
    d.push(encodeFrame(randomBytes(BLOCK * 4), id, BLOCK, 0))
    expect(() => d.push(encodeFrame(randomBytes(BLOCK * 9), id, BLOCK, 1))).toThrow(FountainError)
  })

  it('rejects a structurally impossible frame rather than guessing', () => {
    const t = transfer(randomBytes(BLOCK * 2))
    const good = t.frame(0)
    expect(() => readFrameHeader(good.slice(0, FRAME_HEADER_LEN))).toThrow(FountainError)
    const wrongMagic = new Uint8Array(good)
    wrongMagic[0] ^= 1
    expect(() => readFrameHeader(wrongMagic)).toThrow(/not one of our frames/)
    const truncated = good.slice(0, good.length - 1)
    expect(() => readFrameHeader(truncated)).toThrow(/disagrees with its header/)
  })

  it('covers exactly one block per frame during the systematic pass', () => {
    // What makes a clean capture cost exactly K frames instead of ~1.15K.
    const id = randomBytes(8)
    for (let seq = 0; seq < 10; seq++) expect(coveredBlocks(seq, 10, id)).toEqual([seq])
    // After it, frames mix blocks, and crucially SOME cover just one: belief
    // propagation has nothing to start from otherwise, which is exactly how a
    // receiver that joined late gets stuck.
    const after = Array.from({ length: 200 }, (_, i) => coveredBlocks(10 + i, 10, id))
    expect(after.some((c) => c.length > 1)).toBe(true)
    expect(after.some((c) => c.length === 1)).toBe(true)
  })

  it('derives the same covered set on both sides from the sequence number alone', () => {
    // There is no shared state beyond the header, which is what lets a receiver
    // join a stream that is already running.
    const id = randomBytes(8)
    for (const seq of [12, 99, 5000]) {
      expect(coveredBlocks(seq, 40, id)).toEqual(coveredBlocks(seq, 40, id))
    }
    const other = randomBytes(8)
    expect(coveredBlocks(50, 40, id)).not.toEqual(coveredBlocks(50, 40, other))
  })

  it('finishes a badly lossy capture with a tolerable amount of overhead', () => {
    // Half the frames missed, which is a pessimistic reading of a shaky hand.
    const payload = randomBytes(BLOCK * 40)
    const t = transfer(payload)
    const { out, frames } = run(t, (seq) => seq % 2 === 0)
    expect(out).toEqual(payload)
    // It saw 40 blocks' worth of data spread over the frames it kept; the point
    // is that it converges at all, and does so without a wild multiple.
    expect(frames).toBeLessThan(t.blocks * 6)
  })
})
