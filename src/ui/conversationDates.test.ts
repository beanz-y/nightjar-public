// Day-separator label branches (Today / Yesterday / weekday / date / date+year).
// Uses local-time day boundaries via the same helpers the component renders with.

import { describe, expect, it } from 'vitest'
import { formatDaySeparator, sameDay } from './Conversation'

// A fixed reference "now": 2026-07-20 (a Monday) at local noon.
const NOW = new Date(2026, 6, 20, 12, 0, 0).getTime()
const atNoon = (y: number, m: number, d: number) => new Date(y, m, d, 12, 0, 0).getTime()

describe('formatDaySeparator', () => {
  it('labels the same day as Today (even at a different time)', () => {
    expect(formatDaySeparator(new Date(2026, 6, 20, 1, 15).getTime(), NOW)).toBe('Today')
    expect(formatDaySeparator(new Date(2026, 6, 20, 23, 45).getTime(), NOW)).toBe('Today')
  })

  it('labels the prior day as Yesterday', () => {
    expect(formatDaySeparator(atNoon(2026, 6, 19), NOW)).toBe('Yesterday')
  })

  it('labels 2-6 days ago by weekday name', () => {
    // 2026-07-17 is a Friday, three days before Monday the 20th.
    expect(formatDaySeparator(atNoon(2026, 6, 17), NOW)).toBe(
      new Date(2026, 6, 17).toLocaleDateString(undefined, { weekday: 'long' }),
    )
  })

  it('labels a week+ ago (same year) by month and day, no year', () => {
    const out = formatDaySeparator(atNoon(2026, 5, 1), NOW) // 2026-06-01
    expect(out).toBe(new Date(2026, 5, 1).toLocaleDateString(undefined, { month: 'long', day: 'numeric' }))
    expect(out).not.toMatch(/2026/)
  })

  it('includes the year for a different-year date', () => {
    const out = formatDaySeparator(atNoon(2025, 11, 25), NOW) // 2025-12-25
    expect(out).toMatch(/2025/)
  })

  it('sameDay is true within a day and false across the boundary', () => {
    expect(sameDay(new Date(2026, 6, 20, 0, 1).getTime(), new Date(2026, 6, 20, 23, 59).getTime())).toBe(true)
    expect(sameDay(new Date(2026, 6, 20, 23, 59).getTime(), new Date(2026, 6, 21, 0, 1).getTime())).toBe(false)
  })
})
