import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { getTimeFormat, hour12For, setTimeFormat } from './timePref'

// The unit suite runs under node (no DOM), so provide a minimal localStorage for
// the round-trip. setTimeFormat also fires a window CustomEvent, which is guarded
// and simply no-ops here; the live cross-component re-render is browser-verified.
beforeAll(() => {
  if (typeof globalThis.localStorage === 'undefined') {
    const store = new Map<string, string>()
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      value: {
        getItem: (k: string) => (store.has(k) ? (store.get(k) as string) : null),
        setItem: (k: string, v: string) => {
          store.set(k, String(v))
        },
        removeItem: (k: string) => {
          store.delete(k)
        },
        clear: () => {
          store.clear()
        },
      },
    })
  }
})

afterEach(() => {
  try {
    localStorage.clear()
  } catch {
    /* ignore */
  }
})

describe('timePref', () => {
  it('defaults to auto, then persists a chosen format', () => {
    expect(getTimeFormat()).toBe('auto')
    setTimeFormat('24')
    expect(getTimeFormat()).toBe('24')
    setTimeFormat('12')
    expect(getTimeFormat()).toBe('12')
  })

  it('falls back to auto on a garbage stored value', () => {
    localStorage.setItem('nightjar.timeFormat', 'nonsense')
    expect(getTimeFormat()).toBe('auto')
  })

  it('maps the format to the Intl hour12 flag', () => {
    expect(hour12For('12')).toBe(true)
    expect(hour12For('24')).toBe(false)
    expect(hour12For('auto')).toBeUndefined()
  })
})
