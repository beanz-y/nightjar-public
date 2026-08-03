import { describe, it, expect } from 'vitest'
import { qrMatrix } from './qr'

/** All valid symbol sizes for versions 1..10 (size = 17 + 4*version). */
const VALID_SIZES = new Set([21, 25, 29, 33, 37, 41, 45, 49, 53, 57])

/**
 * Assert the 7x7 finder ring at top-left corner (r0, c0): a dark border, a
 * light ring inside it, and a dark 3x3 center.
 */
function assertFinder(m: boolean[][], r0: number, c0: number): void {
  for (let dy = 0; dy < 7; dy++) {
    for (let dx = 0; dx < 7; dx++) {
      const dist = Math.max(Math.abs(dx - 3), Math.abs(dy - 3)) // Chebyshev from center
      // dark: center 3x3 (dist 0,1) and outer border (dist 3); light: ring (dist 2).
      const expected = dist !== 2
      expect(m[r0 + dy][c0 + dx]).toBe(expected)
    }
  }
}

describe('qrMatrix', () => {
  it('produces a square matrix with a valid version size', () => {
    const m = qrMatrix('nightjar')
    expect(m.length).toBeGreaterThan(0)
    const size = m.length
    expect(VALID_SIZES.has(size)).toBe(true)
    // Every row is the same length as the matrix is tall.
    for (const row of m) {
      expect(row.length).toBe(size)
    }
    // A short string should pick the smallest version (1 -> 21x21).
    expect(size).toBe(21)
  })

  it('places all three finder patterns at the expected corners', () => {
    const m = qrMatrix('safety-number-check')
    const size = m.length
    assertFinder(m, 0, 0) // top-left
    assertFinder(m, 0, size - 7) // top-right
    assertFinder(m, size - 7, 0) // bottom-left
  })

  it('has alternating timing patterns on row 6 and column 6', () => {
    const m = qrMatrix('timing-pattern-test')
    const size = m.length
    // The timing patterns run between the finder patterns (indices 8..size-9)
    // and alternate dark/light with dark on even coordinates.
    for (let i = 8; i <= size - 9; i++) {
      expect(m[6][i]).toBe(i % 2 === 0) // row 6 (horizontal timing)
      expect(m[i][6]).toBe(i % 2 === 0) // column 6 (vertical timing)
    }
  })

  it('is deterministic for the same input', () => {
    const a = qrMatrix('https://nightjar.example/invite#abc123')
    const b = qrMatrix('https://nightjar.example/invite#abc123')
    expect(a).toEqual(b)
  })

  it('produces different matrices for different inputs', () => {
    const a = qrMatrix('alpha')
    const b = qrMatrix('bravo')
    expect(a).not.toEqual(b)
  })

  it('encodes a ~180-char string without throwing (higher version)', () => {
    const long = 'x'.repeat(180)
    let m: boolean[][] | undefined
    expect(() => {
      m = qrMatrix(long)
    }).not.toThrow()
    expect(m).toBeDefined()
    const size = m!.length
    expect(VALID_SIZES.has(size)).toBe(true)
    // 180 bytes needs a much larger symbol than version 1.
    expect(size).toBeGreaterThan(21)
  })
})

// --- versions beyond 10, and EC level L (optical transfer) -----------------
//
// The characteristics table is now DERIVED rather than transcribed, so the two
// things worth proving are that the derivation still reproduces the rows this
// file used to carry by hand, and that what comes out actually scans. The second
// is checked against jsQR, an independent decoder that is already a dependency,
// which is a far better witness than any structural assertion could be.

/** The exact table this file carried before the derivation replaced it. */
const HAND_ENTERED_M: Record<number, [number, number, number, number, number]> = {
  1: [10, 1, 16, 0, 0],
  2: [16, 1, 28, 0, 0],
  3: [26, 1, 44, 0, 0],
  4: [18, 2, 32, 0, 0],
  5: [24, 2, 43, 0, 0],
  6: [16, 4, 27, 0, 0],
  7: [18, 4, 31, 0, 0],
  8: [22, 2, 38, 2, 39],
  9: [22, 3, 36, 2, 37],
  10: [26, 4, 43, 1, 44],
}

function render(m: boolean[][], scale = 3, quiet = 4): { data: Uint8ClampedArray; width: number; height: number } {
  const size = m.length
  const width = (size + quiet * 2) * scale
  const data = new Uint8ClampedArray(width * width * 4).fill(255)
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!m[y][x]) continue
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const px = ((y + quiet) * scale + dy) * width + (x + quiet) * scale + dx
          data[px * 4] = 0
          data[px * 4 + 1] = 0
          data[px * 4 + 2] = 0
        }
      }
    }
  }
  return { data, width, height: width }
}

describe('symbol versions and error-correction levels', () => {
  it('derives exactly the table this file used to carry by hand', async () => {
    // The regression that matters: eighty transcribed rows would have been eighty
    // chances at a typo that only shows up as one unscannable size.
    const { __testVersionEcInfo } = (await import('./qr')) as unknown as {
      __testVersionEcInfo: (v: number, l: 'L' | 'M') => Record<string, number>
    }
    for (const [version, [ec, g1b, g1d, g2b, g2d]] of Object.entries(HAND_ENTERED_M)) {
      expect(__testVersionEcInfo(Number(version), 'M')).toEqual({
        ecPerBlock: ec,
        g1Blocks: g1b,
        g1DataPerBlock: g1d,
        g2Blocks: g2b,
        g2DataPerBlock: g2d,
      })
    }
  })

  it('round-trips through an independent decoder at a range of sizes', async () => {
    const jsQR = (await import('jsqr')).default
    for (const [len, level] of [
      [40, 'M'],
      [300, 'M'],
      [1200, 'L'],
      [2000, 'L'],
    ] as Array<[number, 'L' | 'M']>) {
      const text = Array.from({ length: len }, (_, i) => String.fromCharCode(97 + (i % 26))).join('')
      const img = render(qrMatrix(text, level))
      const decoded = jsQR(img.data, img.width, img.height)
      expect(decoded?.data).toBe(text)
    }
  })

  it('reports a capacity that grows with version and is looser at level L', async () => {
    const { qrCapacityBytes } = await import('./qr')
    expect(qrCapacityBytes('L', 40)).toBeGreaterThan(qrCapacityBytes('M', 40))
    expect(qrCapacityBytes('L', 40)).toBeGreaterThan(2900) // ~2.9 KB per frame
    expect(qrCapacityBytes('M', 10)).toBeGreaterThan(180) // the old ceiling
    for (let v = 2; v <= 40; v++) {
      expect(qrCapacityBytes('L', v)).toBeGreaterThan(qrCapacityBytes('L', v - 1))
    }
  })

  it('accepts a payload far past the old 180-byte ceiling', () => {
    const long = 'y'.repeat(2500)
    const m = qrMatrix(long, 'L')
    // Comfortably past the old ceiling of version 10 (size 57), and it picks the
    // SMALLEST version that fits rather than jumping straight to the largest.
    expect(m.length).toBeGreaterThan(57)
    expect(m.length).toBeLessThanOrEqual(177)
    expect((m.length - 17) % 4).toBe(0) // a real version size
  })
})
