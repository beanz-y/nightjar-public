import { describe, expect, it } from 'vitest'
import {
  INVITE_CODE_LEN,
  formatInviteCode,
  isWellFormedInviteCode,
  newInviteCode,
  normalizeInviteCode,
} from './invites'

const AMBIGUOUS = /[01OIL]/

describe('newInviteCode', () => {
  it('has the pinned length and only in-alphabet, unambiguous symbols', () => {
    for (let i = 0; i < 200; i++) {
      const code = newInviteCode()
      expect(code).toHaveLength(INVITE_CODE_LEN)
      expect(isWellFormedInviteCode(code)).toBe(true)
      expect(AMBIGUOUS.test(code)).toBe(false)
    }
  })

  it('is overwhelmingly unique across a large batch (CSPRNG, not counter)', () => {
    const seen = new Set<string>()
    for (let i = 0; i < 5000; i++) seen.add(newInviteCode())
    expect(seen.size).toBe(5000)
  })

  it('distributes symbols without gross modulo bias (rejection sampling)', () => {
    // Sample many symbols; every one of the 31 should appear and none should
    // dominate. A biased `% 31` over 256 would over-weight the first 8 symbols.
    const counts = new Map<string, number>()
    const N = 31 * 400
    for (let i = 0; i < N; i++) {
      for (const ch of newInviteCode()) counts.set(ch, (counts.get(ch) ?? 0) + 1)
    }
    expect(counts.size).toBe(31)
    const expected = (N * INVITE_CODE_LEN) / 31
    for (const c of counts.values()) {
      expect(c).toBeGreaterThan(expected * 0.8)
      expect(c).toBeLessThan(expected * 1.2)
    }
  })
})

describe('format + normalize', () => {
  it('formats into 4-char groups and normalizes back to canonical', () => {
    const code = newInviteCode()
    const display = formatInviteCode(code)
    expect(display).toMatch(/^.{4}-.{4}-.{4}$/)
    expect(normalizeInviteCode(display)).toBe(code)
  })

  it('normalizes messy user input (spaces, lowercase, stray dashes)', () => {
    const code = newInviteCode()
    const messy = `  ${formatInviteCode(code).toLowerCase()} `
    expect(normalizeInviteCode(messy)).toBe(code)
  })
})

describe('isWellFormedInviteCode', () => {
  it('rejects wrong length, out-of-alphabet, and ambiguous symbols', () => {
    expect(isWellFormedInviteCode('ABCD')).toBe(false) // too short
    expect(isWellFormedInviteCode('ABCDEFGHJKMNP')).toBe(false) // too long
    expect(isWellFormedInviteCode('ABCDEFGH0KMN')).toBe(false) // contains 0
    expect(isWellFormedInviteCode('ABCDEFGHIKMN')).toBe(false) // contains I
    expect(isWellFormedInviteCode('abcdefghjkmn')).toBe(false) // lowercase not canonical
    expect(isWellFormedInviteCode('')).toBe(false)
  })
})
