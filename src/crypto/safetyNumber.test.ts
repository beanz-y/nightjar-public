import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { safetyNumber, safetyNumberDigest } from './safetyNumber'
import { generateIdentity } from './identity'
import { bytesEqual } from './primitives'

describe('safety number', () => {
  const a = generateIdentity().ikSig.publicKey
  const b = generateIdentity().ikSig.publicKey

  it('is order-independent', () => {
    expect(safetyNumber(a, b)).toBe(safetyNumber(b, a))
    expect(bytesEqual(safetyNumberDigest(a, b), safetyNumberDigest(b, a))).toBe(true)
  })

  it('is deterministic', () => {
    expect(safetyNumber(a, b)).toBe(safetyNumber(a, b))
  })

  it('differs for different key pairs', () => {
    const c = generateIdentity().ikSig.publicKey
    expect(safetyNumber(a, b)).not.toBe(safetyNumber(a, c))
  })

  it('renders 8 groups of 5 digits', () => {
    expect(safetyNumber(a, b)).toMatch(/^(\d{5} ){7}\d{5}$/)
  })

  it('matches a pinned known-answer vector', () => {
    // Locks SN_ITERATIONS, SN_TAG, the lo/hi sort, the 5-byte big-endian ->
    // mod-100000 grouping, and endianness. A silent change to any of these
    // would still pass the property tests above, but not this.
    const fa = Uint8Array.from({ length: 32 }, (_, i) => i)
    const fb = Uint8Array.from({ length: 32 }, (_, i) => i + 32)
    expect(safetyNumber(fa, fb)).toBe('29726 30836 35298 15262 27637 23376 13062 33571')
    expect(bytesToHex(safetyNumberDigest(fa, fb))).toBe(
      '39c5b241fe37e758639489b5dc54e2eba22a991ed13b7412f5aae0cdca500f70' +
        '9f898673ec443b030180c85546531c7670d3a1c8f17bffb8892de79656cd827b',
    )
  })
})
