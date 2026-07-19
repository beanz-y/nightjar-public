#!/usr/bin/env node
// The ONE canonical release-hash recipe (DESIGN 10, MF5). Referenced by the
// CI release workflow, build-reproducible.sh, the runbook, and the warrant canary,
// so an auditor rebuilding from public source computes the SAME number that is
// signed into Rekor and attested by the canary. Node built-ins only, run under the
// pinned Node (.nvmrc) with `node scripts/release-hash.mjs [distDir]`.
//
// Recipe over the built dist/ tree:
//   1. every regular file, path relative to dist/, forward slashes; exclusion
//      list is EMPTY (nothing built into dist/ is excluded).
//   2. sort by byte-wise UTF-8 order of the path (Buffer.compare; never a locale
//      sort -- that is the exact cross-OS nondeterminism this guards against).
//   3. each file -> one line `<sha256-hex>  <relpath>\n` (two spaces, LF).
//   4. manifest = those lines joined; releaseHash = sha256(manifest bytes), hex.
//
// The manifest hashes the BUILD OUTPUT (including _headers, which Cloudflare
// consumes to set headers rather than serving as content), so the honest claim is
// "rebuild the release and diff the build output", never "diff the served bytes".

import { createHash } from 'node:crypto'
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

export function sha256hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

/** entries: Array<{ path: string, sha256: string }>. Sort is byte-wise over the
 *  UTF-8 path bytes; the line format is exactly `<hex>  <path>\n`. */
export function manifestFromEntries(entries) {
  const sorted = [...entries].sort((a, b) =>
    Buffer.compare(Buffer.from(a.path, 'utf8'), Buffer.from(b.path, 'utf8')),
  )
  return sorted.map((e) => `${e.sha256}  ${e.path}\n`).join('')
}

export function releaseHash(manifest) {
  return sha256hex(Buffer.from(manifest, 'utf8'))
}

/** Walk a dist dir into canonical {path, sha256} entries. */
export function hashDir(dir) {
  const out = []
  const walk = (d) => {
    for (const name of readdirSync(d).sort()) {
      const full = join(d, name)
      const st = statSync(full)
      if (st.isDirectory()) walk(full)
      else if (st.isFile()) {
        out.push({ path: relative(dir, full).split(sep).join('/'), sha256: sha256hex(readFileSync(full)) })
      }
    }
  }
  walk(dir)
  return out
}

function main() {
  const dir = process.argv[2] || 'dist'
  const version = process.env.NIGHTJAR_VERSION || 'dev'
  const entries = hashDir(dir)
  const manifest = manifestFromEntries(entries)
  const hash = releaseHash(manifest)
  // Explicit LF/UTF-8: writeFileSync writes the string bytes verbatim, so the '\n'
  // above is preserved even on Windows (never CRLF).
  writeFileSync('manifest.txt', manifest)
  writeFileSync(
    'release.json',
    `${JSON.stringify({ version, releaseHash: hash, files: entries.length, generator: 'nightjar-release-hash/1' }, null, 2)}\n`,
  )
  process.stdout.write(`releaseHash ${hash}\nfiles ${entries.length}\nversion ${version}\n`)
}

// Run main only when executed directly (not when imported by the KAT test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main()
