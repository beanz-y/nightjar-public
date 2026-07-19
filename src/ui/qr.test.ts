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
