// Self-contained, dependency-free QR Code generator (BYTE mode, EC level M).
//
// This file implements the QR encoding pipeline from scratch using only
// standard JavaScript built-ins (no npm imports), so it is safe to run under a
// strict Content-Security-Policy. It supports symbol versions 1..10, which at
// error-correction level M comfortably covers any payload below ~180 bytes
// (the intended use is short safety-number / invite URLs, always < 200 chars).
//
// Reference: ISO/IEC 18004 (QR Code). The structure mirrors the well-known
// reference decomposition: bit stream assembly, Reed-Solomon error correction
// over GF(256), block interleaving, function-pattern placement, zig-zag data
// placement, the eight data masks, and standard penalty-based mask selection.

/** Error-correction characteristics for one symbol version at EC level M. */
interface VersionEcInfo {
  /** Error-correction codewords per block. */
  ecPerBlock: number
  /** Number of blocks in group 1. */
  g1Blocks: number
  /** Data codewords per block in group 1. */
  g1DataPerBlock: number
  /** Number of blocks in group 2 (0 if the version has a single group). */
  g2Blocks: number
  /** Data codewords per block in group 2. */
  g2DataPerBlock: number
}

// EC level M, versions 1..10. Values are taken directly from the ISO/IEC 18004
// error-correction characteristics table. Index 0 is unused (versions are
// 1-based); we start the array at version 1.
const VERSION_EC_M: Record<number, VersionEcInfo> = {
  1: { ecPerBlock: 10, g1Blocks: 1, g1DataPerBlock: 16, g2Blocks: 0, g2DataPerBlock: 0 },
  2: { ecPerBlock: 16, g1Blocks: 1, g1DataPerBlock: 28, g2Blocks: 0, g2DataPerBlock: 0 },
  3: { ecPerBlock: 26, g1Blocks: 1, g1DataPerBlock: 44, g2Blocks: 0, g2DataPerBlock: 0 },
  4: { ecPerBlock: 18, g1Blocks: 2, g1DataPerBlock: 32, g2Blocks: 0, g2DataPerBlock: 0 },
  5: { ecPerBlock: 24, g1Blocks: 2, g1DataPerBlock: 43, g2Blocks: 0, g2DataPerBlock: 0 },
  6: { ecPerBlock: 16, g1Blocks: 4, g1DataPerBlock: 27, g2Blocks: 0, g2DataPerBlock: 0 },
  7: { ecPerBlock: 18, g1Blocks: 4, g1DataPerBlock: 31, g2Blocks: 0, g2DataPerBlock: 0 },
  8: { ecPerBlock: 22, g1Blocks: 2, g1DataPerBlock: 38, g2Blocks: 2, g2DataPerBlock: 39 },
  9: { ecPerBlock: 22, g1Blocks: 3, g1DataPerBlock: 36, g2Blocks: 2, g2DataPerBlock: 37 },
  10: { ecPerBlock: 26, g1Blocks: 4, g1DataPerBlock: 43, g2Blocks: 1, g2DataPerBlock: 44 },
}

const MIN_VERSION = 1
const MAX_VERSION = 10

/** Total number of data codewords available for a version at EC level M. */
function dataCodewordCount(info: VersionEcInfo): number {
  return info.g1Blocks * info.g1DataPerBlock + info.g2Blocks * info.g2DataPerBlock
}

/** Byte-mode character-count indicator width in bits for a given version. */
function charCountBits(version: number): number {
  // Byte mode: 8 bits for versions 1..9, 16 bits for versions 10..26.
  return version <= 9 ? 8 : 16
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic for Reed-Solomon, using primitive polynomial 0x11D.
// ---------------------------------------------------------------------------

const GF_EXP = new Uint8Array(255)
const GF_LOG = new Uint8Array(256)
;(function initGaloisTables(): void {
  let x = 1
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x
    GF_LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11d
  }
})()

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0
  return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]
}

/**
 * Compute the Reed-Solomon generator polynomial (divisor) of the given degree.
 * Returned as an array of `degree` coefficients; the constant term is last.
 */
function rsGeneratorPoly(degree: number): number[] {
  const result: number[] = new Array(degree).fill(0)
  result[degree - 1] = 1 // start with the polynomial "1"
  let root = 1
  for (let i = 0; i < degree; i++) {
    // Multiply the current polynomial by (x - root), where root = 2^i.
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j], root)
      if (j + 1 < degree) result[j] ^= result[j + 1]
    }
    root = gfMul(root, 2)
  }
  return result
}

/** Compute the `degree` Reed-Solomon EC codewords for a block of data bytes. */
function rsRemainder(data: number[], divisor: number[]): number[] {
  const result: number[] = new Array(divisor.length).fill(0)
  for (const b of data) {
    const factor = b ^ result[0]
    result.shift()
    result.push(0)
    for (let i = 0; i < result.length; i++) {
      result[i] ^= gfMul(divisor[i], factor)
    }
  }
  return result
}

// ---------------------------------------------------------------------------
// Bit buffer helper.
// ---------------------------------------------------------------------------

class BitBuffer {
  private bits: number[] = []

  append(value: number, length: number): void {
    for (let i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1)
    }
  }

  get length(): number {
    return this.bits.length
  }

  /** Pack the bit stream into bytes (MSB first). Length must be a multiple of 8. */
  toBytes(): number[] {
    const out: number[] = []
    for (let i = 0; i < this.bits.length; i += 8) {
      let byte = 0
      for (let j = 0; j < 8; j++) {
        byte = (byte << 1) | (this.bits[i + j] ?? 0)
      }
      out.push(byte)
    }
    return out
  }
}

// ---------------------------------------------------------------------------
// Data encoding: mode + count indicators, terminator, padding, then RS EC and
// block interleaving. Returns the final interleaved codeword stream (bytes).
// ---------------------------------------------------------------------------

function encodeData(bytes: number[], version: number, info: VersionEcInfo): number[] {
  const totalDataCodewords = dataCodewordCount(info)
  const capacityBits = totalDataCodewords * 8

  const bb = new BitBuffer()
  bb.append(0b0100, 4) // mode indicator: byte mode
  bb.append(bytes.length, charCountBits(version)) // character count
  for (const b of bytes) bb.append(b, 8) // payload bytes

  // Terminator: up to four 0 bits, but no more than the remaining capacity.
  const terminator = Math.min(4, capacityBits - bb.length)
  bb.append(0, terminator)

  // Pad with 0 bits to the next byte boundary.
  if (bb.length % 8 !== 0) {
    bb.append(0, 8 - (bb.length % 8))
  }

  const dataBytes = bb.toBytes()

  // Pad bytes alternate 0xEC / 0x11 until the data capacity is filled.
  const padBytes = [0xec, 0x11]
  for (let i = 0; dataBytes.length < totalDataCodewords; i++) {
    dataBytes.push(padBytes[i % 2])
  }

  // Split the data codewords into blocks.
  const dataBlocks: number[][] = []
  const ecBlocks: number[][] = []
  const divisor = rsGeneratorPoly(info.ecPerBlock)
  let offset = 0
  const totalBlocks = info.g1Blocks + info.g2Blocks
  for (let b = 0; b < totalBlocks; b++) {
    const count = b < info.g1Blocks ? info.g1DataPerBlock : info.g2DataPerBlock
    const block = dataBytes.slice(offset, offset + count)
    offset += count
    dataBlocks.push(block)
    ecBlocks.push(rsRemainder(block, divisor))
  }

  // Interleave data codewords across blocks (column by column).
  const result: number[] = []
  const maxData = Math.max(...dataBlocks.map((blk) => blk.length))
  for (let i = 0; i < maxData; i++) {
    for (const block of dataBlocks) {
      if (i < block.length) result.push(block[i])
    }
  }
  // Interleave EC codewords across blocks (every block has the same EC count).
  for (let i = 0; i < info.ecPerBlock; i++) {
    for (const block of ecBlocks) {
      result.push(block[i])
    }
  }
  return result
}

// ---------------------------------------------------------------------------
// Matrix construction.
// ---------------------------------------------------------------------------

/** Working symbol: the module matrix plus a function-module mask. */
class QrSymbol {
  readonly size: number
  readonly modules: boolean[][]
  private readonly isFunction: boolean[][]

  constructor(
    readonly version: number,
    private readonly codewords: number[],
  ) {
    this.size = version * 4 + 17
    this.modules = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false))
    this.isFunction = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false))

    this.drawFunctionPatterns()
    this.drawCodewords()
    this.selectAndApplyMask()
  }

  private set(row: number, col: number, dark: boolean): void {
    this.modules[row][col] = dark
    this.isFunction[row][col] = true
  }

  // --- Function patterns ---------------------------------------------------

  private drawFunctionPatterns(): void {
    // Timing patterns along row 6 and column 6.
    for (let i = 0; i < this.size; i++) {
      this.set(6, i, i % 2 === 0)
      this.set(i, 6, i % 2 === 0)
    }

    // Three finder patterns (with separators), centered near the corners.
    this.drawFinder(3, 3)
    this.drawFinder(3, this.size - 4)
    this.drawFinder(this.size - 4, 3)

    // Alignment patterns.
    const positions = alignmentPatternPositions(this.version)
    const last = positions.length - 1
    for (let i = 0; i <= last; i++) {
      for (let j = 0; j <= last; j++) {
        // Skip the three positions that collide with finder patterns.
        if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue
        this.drawAlignment(positions[i], positions[j])
      }
    }

    // Reserve the format- and version-information regions; the actual bits are
    // written after masking. The dark module is a fixed dark cell.
    this.reserveFormatAndVersion()
    this.set(this.size - 8, 8, true) // dark module
  }

  private drawFinder(centerRow: number, centerCol: number): void {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const r = centerRow + dy
        const c = centerCol + dx
        if (r < 0 || r >= this.size || c < 0 || c >= this.size) continue
        const dist = Math.max(Math.abs(dx), Math.abs(dy)) // Chebyshev distance
        // Dark for the outer ring (3) and the 3x3 center (0,1); light for the
        // inner ring (2) and the separator (4).
        this.set(r, c, dist !== 2 && dist !== 4)
      }
    }
  }

  private drawAlignment(centerRow: number, centerCol: number): void {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy))
        this.set(centerRow + dy, centerCol + dx, dist !== 1)
      }
    }
  }

  private reserveFormatAndVersion(): void {
    // Format information (two copies) around the finder patterns.
    for (let i = 0; i <= 8; i++) {
      this.reserve(8, i)
      this.reserve(i, 8)
    }
    for (let i = 0; i < 8; i++) {
      this.reserve(this.size - 1 - i, 8)
      this.reserve(8, this.size - 1 - i)
    }
    // Version information (two 6x3 blocks) for versions >= 7.
    if (this.version >= 7) {
      for (let i = 0; i < 6; i++) {
        for (let j = 0; j < 3; j++) {
          this.reserve(i, this.size - 11 + j)
          this.reserve(this.size - 11 + j, i)
        }
      }
    }
  }

  private reserve(row: number, col: number): void {
    // Mark as a function module without changing its (currently light) value;
    // the real bits are written later.
    this.isFunction[row][col] = true
  }

  // --- Data placement ------------------------------------------------------

  private drawCodewords(): void {
    const totalBits = this.codewords.length * 8
    let bitIndex = 0
    const getBit = (): boolean => {
      if (bitIndex >= totalBits) return false // remainder bits are light
      const byte = this.codewords[bitIndex >>> 3]
      const bit = (byte >>> (7 - (bitIndex & 7))) & 1
      bitIndex++
      return bit === 1
    }

    let upward = true
    for (let col = this.size - 1; col > 0; col -= 2) {
      // The vertical timing pattern occupies column 6; shift left past it.
      if (col === 6) col = 5
      for (let i = 0; i < this.size; i++) {
        const row = upward ? this.size - 1 - i : i
        for (let dc = 0; dc < 2; dc++) {
          const c = col - dc
          if (!this.isFunction[row][c]) {
            this.modules[row][c] = getBit()
          }
        }
      }
      upward = !upward
    }
  }

  // --- Masking -------------------------------------------------------------

  private applyMask(mask: number): void {
    for (let row = 0; row < this.size; row++) {
      for (let col = 0; col < this.size; col++) {
        if (this.isFunction[row][col]) continue
        if (maskCondition(mask, row, col)) {
          this.modules[row][col] = !this.modules[row][col]
        }
      }
    }
  }

  private selectAndApplyMask(): void {
    let bestMask = 0
    let bestPenalty = Infinity
    for (let mask = 0; mask < 8; mask++) {
      this.applyMask(mask)
      this.drawFormatBits(mask)
      const penalty = this.penaltyScore()
      if (penalty < bestPenalty) {
        bestPenalty = penalty
        bestMask = mask
      }
      this.applyMask(mask) // XOR again to revert
    }
    this.applyMask(bestMask)
    this.drawFormatBits(bestMask)
    this.drawVersionBits()
  }

  // --- Format & version information ---------------------------------------

  private drawFormatBits(mask: number): void {
    // EC level M is 0b00; combine with the 3-bit mask, then BCH(15,5).
    const data = (0b00 << 3) | mask
    let rem = data
    for (let i = 0; i < 10; i++) {
      rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
    }
    const bits = ((data << 10) | rem) ^ 0x5412 // 15-bit format value
    const bit = (i: number): boolean => ((bits >>> i) & 1) === 1
    const n = this.size

    // First copy, wrapping the top-left finder: bits 0-7 run down column 8
    // (rows 0-5, 7, 8), then bits 8-14 run left along row 8 (cols 7, 5..0),
    // skipping the timing modules at (6, 8) and (8, 6).
    for (let i = 0; i <= 5; i++) this.modules[i][8] = bit(i)
    this.modules[7][8] = bit(6)
    this.modules[8][8] = bit(7)
    this.modules[8][7] = bit(8)
    for (let i = 9; i < 15; i++) this.modules[8][14 - i] = bit(i)

    // Second copy: bits 0-7 run left along row 8 from the right edge, then
    // bits 8-14 run down column 8 to the bottom edge.
    for (let i = 0; i < 8; i++) this.modules[8][n - 1 - i] = bit(i)
    for (let i = 8; i < 15; i++) this.modules[n - 15 + i][8] = bit(i)
    this.modules[n - 8][8] = true // dark module (kept dark)
  }

  private drawVersionBits(): void {
    if (this.version < 7) return
    let rem = this.version
    for (let i = 0; i < 12; i++) {
      rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
    }
    const bits = (this.version << 12) | rem // 18-bit version value
    for (let i = 0; i < 18; i++) {
      const b = ((bits >>> i) & 1) === 1
      const a = this.size - 11 + (i % 3)
      const c = Math.floor(i / 3)
      this.modules[a][c] = b
      this.modules[c][a] = b
    }
  }

  // --- Penalty scoring (rules 1-4) ----------------------------------------

  private penaltyScore(): number {
    const n = this.size
    const m = this.modules
    let penalty = 0

    // Rule 1: runs of >= 5 same-colored modules in each row and column.
    for (let row = 0; row < n; row++) {
      let runColor = m[row][0]
      let runLen = 1
      for (let col = 1; col < n; col++) {
        if (m[row][col] === runColor) {
          runLen++
        } else {
          if (runLen >= 5) penalty += 3 + (runLen - 5)
          runColor = m[row][col]
          runLen = 1
        }
      }
      if (runLen >= 5) penalty += 3 + (runLen - 5)
    }
    for (let col = 0; col < n; col++) {
      let runColor = m[0][col]
      let runLen = 1
      for (let row = 1; row < n; row++) {
        if (m[row][col] === runColor) {
          runLen++
        } else {
          if (runLen >= 5) penalty += 3 + (runLen - 5)
          runColor = m[row][col]
          runLen = 1
        }
      }
      if (runLen >= 5) penalty += 3 + (runLen - 5)
    }

    // Rule 2: 2x2 blocks of a single color.
    for (let row = 0; row < n - 1; row++) {
      for (let col = 0; col < n - 1; col++) {
        const c = m[row][col]
        if (c === m[row][col + 1] && c === m[row + 1][col] && c === m[row + 1][col + 1]) {
          penalty += 3
        }
      }
    }

    // Rule 3: the 1:1:3:1:1 finder-like pattern with four light modules on one
    // side, i.e. 1011101 0000 or 0000 1011101, in any row or column.
    const p1 = [true, false, true, true, true, false, true, false, false, false, false]
    const p2 = [false, false, false, false, true, false, true, true, true, false, true]
    for (let row = 0; row < n; row++) {
      for (let col = 0; col <= n - 11; col++) {
        if (matchWindow(m, row, col, true, p1) || matchWindow(m, row, col, true, p2)) penalty += 40
      }
    }
    for (let col = 0; col < n; col++) {
      for (let row = 0; row <= n - 11; row++) {
        if (matchWindow(m, row, col, false, p1) || matchWindow(m, row, col, false, p2)) penalty += 40
      }
    }

    // Rule 4: deviation of the dark-module proportion from 50%.
    let dark = 0
    for (let row = 0; row < n; row++) {
      for (let col = 0; col < n; col++) {
        if (m[row][col]) dark++
      }
    }
    const total = n * n
    const percent = (dark * 100) / total
    const prev = Math.floor(percent / 5) * 5
    const next = prev + 5
    penalty += (Math.min(Math.abs(prev - 50), Math.abs(next - 50)) / 5) * 10

    return penalty
  }
}

/** Check whether an 11-module window (horizontal or vertical) matches a pattern. */
function matchWindow(
  m: boolean[][],
  row: number,
  col: number,
  horizontal: boolean,
  pattern: boolean[],
): boolean {
  for (let k = 0; k < 11; k++) {
    const value = horizontal ? m[row][col + k] : m[row + k][col]
    if (value !== pattern[k]) return false
  }
  return true
}

/** Data-mask condition for mask `k` at (row, col). */
function maskCondition(k: number, row: number, col: number): boolean {
  switch (k) {
    case 0:
      return (row + col) % 2 === 0
    case 1:
      return row % 2 === 0
    case 2:
      return col % 3 === 0
    case 3:
      return (row + col) % 3 === 0
    case 4:
      return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0
    case 5:
      return ((row * col) % 2) + ((row * col) % 3) === 0
    case 6:
      return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0
    case 7:
      return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0
    default:
      throw new Error(`invalid mask ${k}`)
  }
}

/** Center coordinates of alignment patterns for the given version. */
function alignmentPatternPositions(version: number): number[] {
  if (version === 1) return []
  const size = version * 4 + 17
  const numAlign = Math.floor(version / 7) + 2
  const step = Math.ceil((version * 4 + 4) / (numAlign * 2 - 2)) * 2
  const result = [6]
  for (let pos = size - 7; result.length < numAlign; pos -= step) {
    result.splice(1, 0, pos)
  }
  return result
}

/** Pick the smallest supported version whose EC-level-M capacity fits `byteLen`. */
function chooseVersion(byteLen: number): { version: number; info: VersionEcInfo } {
  for (let version = MIN_VERSION; version <= MAX_VERSION; version++) {
    const info = VERSION_EC_M[version]
    const capacityBits = dataCodewordCount(info) * 8
    const neededBits = 4 + charCountBits(version) + byteLen * 8
    if (neededBits <= capacityBits) return { version, info }
  }
  throw new Error(
    `text too long for QR versions ${MIN_VERSION}-${MAX_VERSION} at EC level M (${byteLen} bytes)`,
  )
}

/**
 * Encode `text` (ASCII/UTF-8, treated as bytes) as a QR matrix. Returns a
 * square, row-major boolean matrix where true = a dark module. No quiet zone
 * (the caller adds margin). Throws if the text is too long for the supported
 * versions.
 */
export function qrMatrix(text: string): boolean[][] {
  const bytes = Array.from(new TextEncoder().encode(text))
  const { version, info } = chooseVersion(bytes.length)
  const codewords = encodeData(bytes, version, info)
  const symbol = new QrSymbol(version, codewords)
  return symbol.modules
}
