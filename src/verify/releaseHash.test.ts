import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
// The canonical release-hash recipe is a plain .mjs so CI/auditors run it with bare
// node; import it here to lock its format with an independently-built KAT.
import { manifestFromEntries, releaseHash, sha256hex } from '../../scripts/release-hash.mjs'

// Independently constructed fixture: bytes hashed via node:crypto (not the module),
// and the expected order written out by hand in byte-wise order, so a locale sort or
// a line-format change fails the test.
const files = [
  { path: 'index.html', bytes: 'html' },
  { path: 'Index.html', bytes: 'HTML' }, // uppercase 'I' (0x49) sorts before 'i' (0x69)
  { path: 'assets/a.js', bytes: 'a' },
  { path: 'assets/é.js', bytes: 'e-acute' }, // 'é' is 0xC3 0xA9, sorts after ASCII
  { path: 'sw.js', bytes: 'sw' },
]
const bySha = new Map(files.map((f) => [f.path, createHash('sha256').update(Buffer.from(f.bytes)).digest('hex')]))
const sha = (p: string): string => bySha.get(p) ?? ''
const entries = files.map((f) => ({ path: f.path, sha256: sha(f.path) }))

// Byte-wise order of the paths: I(0x49) < a(0x61)... < i(0x69) < s(0x73).
const ORDER = ['Index.html', 'assets/a.js', 'assets/é.js', 'index.html', 'sw.js']
const EXPECTED_MANIFEST = ORDER.map((p) => `${sha(p)}  ${p}\n`).join('')

describe('release-hash canonical recipe (KAT)', () => {
  it('sorts byte-wise and uses the exact `<hex>  <path>\\n` line format', () => {
    expect(manifestFromEntries(entries)).toBe(EXPECTED_MANIFEST)
  })

  it('is a locale-independent sort (uppercase before lowercase)', () => {
    const m = manifestFromEntries(entries)
    expect(m.indexOf('Index.html')).toBeLessThan(m.indexOf('index.html'))
  })

  it('releaseHash = sha256 of the manifest bytes', () => {
    const expected = createHash('sha256').update(Buffer.from(EXPECTED_MANIFEST, 'utf8')).digest('hex')
    expect(releaseHash(EXPECTED_MANIFEST)).toBe(expected)
  })

  it('sha256hex matches node crypto', () => {
    expect(sha256hex(Buffer.from('nightjar'))).toBe(
      createHash('sha256').update(Buffer.from('nightjar')).digest('hex'),
    )
  })

  it('input order does not affect the manifest (stable canonical sort)', () => {
    const shuffled = [...entries].reverse()
    expect(manifestFromEntries(shuffled)).toBe(manifestFromEntries(entries))
  })
})
