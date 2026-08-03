// Optical transfer: turning a blob into an endless stream of frames that a
// camera can reassemble (Sesame linking, and later history transfer).
//
// The problem this solves is that a camera watching a screen MISSES frames. It
// misses them for focus, for glare, for a hand moving, for the two devices
// running at different refresh rates. Any scheme that needs frame N before frame
// N+1 turns every miss into a stall and needs a back channel to ask again; there
// is no back channel here, because the whole point is that nothing crosses the
// network.
//
// So the sender loops forever and the receiver takes whatever it catches:
//
//   - Frames 0..K-1 are the raw blocks, in order. A clean capture in good light
//     decodes at exactly K frames with no waste at all, which is the common case
//     and worth optimizing for.
//   - Frames K onward are XORs of a pseudorandom subset of blocks, chosen only
//     from the frame's own sequence number. A receiver that missed some of the
//     first pass recovers them from these without anyone asking for a repeat.
//
// Decoding is the usual belief propagation: a frame covering exactly one unknown
// block reveals it, revealing it shrinks every other frame that covers it, and
// that often reveals another. It terminates when every block is known.
//
// NO CRYPTOGRAPHY LIVES HERE, deliberately. What this carries is already sealed
// and authenticated by whoever produced it (crypto/link.ts, and later the history
// unit), so this layer only has to reassemble bytes. If it ever reassembles the
// wrong bytes, the AEAD above it fails and the transfer is rejected there. That
// is why the frame header is not authenticated and does not need to be: a hostile
// display can waste the receiver's time, which it could do anyway by showing
// nothing, but it cannot produce a payload that opens.

import { hash256 } from '../crypto/primitives'
import { concatBytes, u32be } from '../crypto/primitives'

const MAGIC = 'NJQR'
const VERSION = 0x01
/** magic(4) version(1) transferId(8) totalBytes(4) blockSize(2) seq(4) */
export const FRAME_HEADER_LEN = 4 + 1 + 8 + 4 + 2 + 4

/** Bound on blocks per transfer. At 2 KB blocks this is 128 MB, far above any
 *  payload here, and it stops a malformed header making a receiver allocate. */
export const MAX_BLOCKS = 65535
/** Bound on a frame's data part, so one frame cannot demand unbounded memory. */
export const MAX_BLOCK_SIZE = 8192

export class FountainError extends Error {
  constructor(message: string) {
    super(`optical: ${message}`)
    this.name = 'FountainError'
  }
}

export interface FrameHeader {
  transferId: string
  totalBytes: number
  blockSize: number
  seq: number
  /** Blocks in this transfer, derived rather than carried so it cannot disagree. */
  blocks: number
}

const magicBytes = new TextEncoder().encode(MAGIC)

function blockCount(totalBytes: number, blockSize: number): number {
  return Math.max(1, Math.ceil(totalBytes / blockSize))
}

/**
 * Which blocks frame `seq` covers, derived from the sequence number alone.
 *
 * Both sides compute this the same way with nothing shared but the header, which
 * is what lets a receiver join a stream that is already running. Degrees are
 * kept small and skewed toward 1 and 2: those are the frames that actually make
 * belief propagation progress, and a degree far above that mostly produces a
 * frame nothing can use yet.
 */
export function coveredBlocks(seq: number, blocks: number, transferId: Uint8Array): number[] {
  if (seq < blocks) return [seq] // the systematic pass: frame i IS block i
  if (blocks === 1) return [0]
  const rand = hash256(concatBytes(transferId, u32be(seq)))
  // Degree from the first byte. Roughly one frame in eight covers a SINGLE block,
  // and that fraction is load-bearing rather than a tuning detail: belief
  // propagation can only start from a frame with one unknown in it, so a stream
  // of nothing but combinations is undecodable to a receiver that joined late and
  // missed the systematic pass. The rest are small combinations, which is what
  // repairs the gaps once there is something to propagate from.
  const spread = Math.min(blocks, 8)
  const degree = rand[0] < 32 ? 1 : 2 + (rand[0] % Math.max(1, spread - 1))
  const picked = new Set<number>()
  // Rejection sampling from the remaining digest, re-hashing if it runs out, so
  // the subset is well spread without needing a specified PRNG on both sides.
  let pool = rand
  let at = 1
  while (picked.size < degree) {
    if (at + 4 > pool.length) {
      pool = hash256(pool)
      at = 0
    }
    const v = ((pool[at] << 24) | (pool[at + 1] << 16) | (pool[at + 2] << 8) | pool[at + 3]) >>> 0
    at += 4
    picked.add(v % blocks)
  }
  return [...picked].sort((a, b) => a - b)
}

/** Build frame `seq` of a transfer. Callers loop this forever while the code is
 *  on screen; there is no end and no acknowledgement. */
export function encodeFrame(
  payload: Uint8Array,
  transferId: Uint8Array,
  blockSize: number,
  seq: number,
): Uint8Array {
  if (transferId.length !== 8) throw new FountainError('transfer id must be 8 bytes')
  if (blockSize < 1 || blockSize > MAX_BLOCK_SIZE) throw new FountainError('bad block size')
  const blocks = blockCount(payload.length, blockSize)
  if (blocks > MAX_BLOCKS) throw new FountainError('payload needs too many blocks')
  const data = new Uint8Array(blockSize)
  for (const b of coveredBlocks(seq, blocks, transferId)) {
    const start = b * blockSize
    const slice = payload.subarray(start, Math.min(start + blockSize, payload.length))
    for (let i = 0; i < slice.length; i++) data[i] ^= slice[i]
  }
  const header = concatBytes(
    magicBytes,
    Uint8Array.from([VERSION]),
    transferId,
    u32be(payload.length),
    Uint8Array.from([(blockSize >> 8) & 0xff, blockSize & 0xff]),
    u32be(seq),
  )
  return concatBytes(header, data)
}

/** Read and bounds-check a frame header without touching its data. */
export function readFrameHeader(frame: Uint8Array): FrameHeader {
  if (frame.length <= FRAME_HEADER_LEN) throw new FountainError('frame is too short')
  for (let i = 0; i < 4; i++) if (frame[i] !== magicBytes[i]) throw new FountainError('not one of our frames')
  if (frame[4] !== VERSION) throw new FountainError('unsupported frame version')
  const totalBytes = ((frame[13] << 24) | (frame[14] << 16) | (frame[15] << 8) | frame[16]) >>> 0
  const blockSize = (frame[17] << 8) | frame[18]
  const seq = ((frame[19] << 24) | (frame[20] << 16) | (frame[21] << 8) | frame[22]) >>> 0
  if (blockSize < 1 || blockSize > MAX_BLOCK_SIZE) throw new FountainError('bad block size')
  if (frame.length !== FRAME_HEADER_LEN + blockSize) throw new FountainError('frame length disagrees with its header')
  if (totalBytes < 1) throw new FountainError('empty transfer')
  const blocks = blockCount(totalBytes, blockSize)
  if (blocks > MAX_BLOCKS) throw new FountainError('transfer claims too many blocks')
  let transferId = ''
  for (let i = 5; i < 13; i++) transferId += frame[i].toString(16).padStart(2, '0')
  return { transferId, totalBytes, blockSize, seq, blocks }
}

/**
 * Reassembles one transfer from frames as they arrive.
 *
 * Locks onto the first transfer it sees and ignores every other, so two people
 * linking devices beside each other cannot feed each other halves of a payload.
 * Feeding it the same frame twice is free, and feeding it frames forever after
 * it completes is free too.
 */
export class FountainDecoder {
  private transferId: string | null = null
  private totalBytes = 0
  private blockSize = 0
  private blocks = 0
  private readonly known = new Map<number, Uint8Array>()
  /** Frames not yet reduced to a single unknown block, by their covered set. */
  private pending: Array<{ cover: Set<number>; data: Uint8Array }> = []
  private seenSeq = new Set<number>()

  /** Blocks recovered so far, for a progress indicator. */
  get progress(): { have: number; need: number } {
    return { have: this.known.size, need: this.blocks }
  }

  get done(): boolean {
    return this.blocks > 0 && this.known.size === this.blocks
  }

  /** Take one frame. Returns the payload once complete, else null. Throws only
   *  on a frame that is structurally impossible; a frame from another transfer
   *  is ignored rather than treated as an error, because a camera pointed at a
   *  busy room may well see one. */
  push(frame: Uint8Array): Uint8Array | null {
    const h = readFrameHeader(frame)
    if (this.transferId === null) {
      this.transferId = h.transferId
      this.totalBytes = h.totalBytes
      this.blockSize = h.blockSize
      this.blocks = h.blocks
    } else if (h.transferId !== this.transferId) {
      return this.done ? this.assemble() : null
    } else if (h.totalBytes !== this.totalBytes || h.blockSize !== this.blockSize) {
      // Same id, different shape: something is wrong with the stream, and mixing
      // the two would produce bytes that cannot open.
      throw new FountainError('frames disagree about the transfer shape')
    }
    if (this.done) return this.assemble()
    if (this.seenSeq.has(h.seq)) return null // a repeat adds nothing
    this.seenSeq.add(h.seq)

    const idBytes = new Uint8Array(8)
    for (let i = 0; i < 8; i++) idBytes[i] = frame[5 + i]
    const cover = new Set(coveredBlocks(h.seq, this.blocks, idBytes))
    this.absorb(cover, frame.slice(FRAME_HEADER_LEN))
    return this.done ? this.assemble() : null
  }

  /** Reduce a frame by everything already known, then propagate. */
  private absorb(cover: Set<number>, data: Uint8Array): void {
    const reduced = new Uint8Array(data)
    for (const b of [...cover]) {
      const have = this.known.get(b)
      if (!have) continue
      for (let i = 0; i < reduced.length; i++) reduced[i] ^= have[i]
      cover.delete(b)
    }
    if (cover.size === 0) return // nothing new
    if (cover.size > 1) {
      this.pending.push({ cover, data: reduced })
      return
    }
    // Exactly one unknown: it is revealed, which may reveal others in turn.
    const [index] = [...cover]
    this.known.set(index, reduced)
    const carry = this.pending
    this.pending = []
    for (const p of carry) {
      if (this.known.size === this.blocks) {
        this.pending.push(p)
        continue
      }
      this.absorb(p.cover, p.data)
    }
  }

  private assemble(): Uint8Array {
    const out = new Uint8Array(this.blocks * this.blockSize)
    for (let i = 0; i < this.blocks; i++) out.set(this.known.get(i) as Uint8Array, i * this.blockSize)
    return out.slice(0, this.totalBytes) // trim the padding of the final block
  }
}
