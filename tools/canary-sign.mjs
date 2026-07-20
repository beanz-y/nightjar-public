#!/usr/bin/env node
// Sign a warrant-canary document (P7, DESIGN 10.3; DESIGN 10). Run OFFLINE
// with the canary private key; paste the printed JSON into the CANARY_JSON
// dashboard var. Uses the SAME @noble Ed25519 + domain-separated message as the
// in-app verifier (src/verify/canary.ts), which a round-trip test locks.
//
//   CANARY_PRIVATE_KEY=<base64url-32B> node tools/canary-sign.mjs \
//       --version v1.0.0 --hash <64-hex releaseHash> [--statement "..."]
//
// MF3 (do not weaken): signedAt defaults to NOW and the tool REFUSES a date more
// than a few minutes in the future. The whole warrant-canary guarantee is that the
// operator cannot forge a future fresh date without this key, so future-dating or
// batch pre-signing ANY canary voids it. The --backdate-for-testing escape hatch
// exists only for tests and prints a loud warning; never use it for a real canary.

import { fileURLToPath } from 'node:url'
import { ed25519 } from '@noble/curves/ed25519'
import { base64urlnopad } from '@scure/base'

const TAG_CANARY = 'Nightjar-canary-v1'
const FUTURE_SKEW_MS = 5 * 60 * 1000
const DEFAULT_STATEMENT =
  'As of the signed date, I (the operator) am not aware of any compromise or compulsion affecting this release, and this is the honest published build.'

const enc = new TextEncoder()

function u32be(n) {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}
function concat(...arrs) {
  let total = 0
  for (const a of arrs) total += a.length
  const out = new Uint8Array(total)
  let at = 0
  for (const a of arrs) {
    out.set(a, at)
    at += a.length
  }
  return out
}
function domainSeparate(tag, ...parts) {
  const tagB = enc.encode(tag)
  const chunks = [u32be(tagB.length), tagB]
  for (const p of parts) chunks.push(u32be(p.length), p)
  return concat(...chunks)
}

/** Build a signed canary doc. Pure + exported so a test can round-trip it through
 *  the in-app verifier. Throws on a future signedAt unless allowBackdate. */
export function buildCanary({ version, releaseHash, statement, signedAt, privateKeyB64, now = Date.now(), allowBackdate = false }) {
  if (!/^v?[\w.\-+]{1,63}$/.test(version || '')) throw new Error('bad --version')
  if (!/^[0-9a-f]{64}$/.test(releaseHash || '')) throw new Error('--hash must be 64 lowercase hex chars (a sha-256)')
  const stmt = statement && statement.length ? statement : DEFAULT_STATEMENT
  const when = signedAt || new Date(now).toISOString()
  const t = Date.parse(when)
  if (Number.isNaN(t)) throw new Error('bad --date (must be ISO 8601)')
  if (!allowBackdate && t > now + FUTURE_SKEW_MS) {
    throw new Error('refusing to sign a canary dated in the future (this voids the warrant-canary guarantee; see DESIGN 10)')
  }
  const priv = base64urlnopad.decode(privateKeyB64)
  if (priv.length !== 32) throw new Error('CANARY_PRIVATE_KEY must be base64url of a 32-byte Ed25519 seed')
  const msg = domainSeparate(TAG_CANARY, enc.encode(version), enc.encode(releaseHash), enc.encode(when), enc.encode(stmt))
  const sig = ed25519.sign(msg, priv)
  return { v: 1, version, releaseHash, statement: stmt, signedAt: when, sig: base64urlnopad.encode(sig) }
}

function arg(name) {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 ? process.argv[i + 1] : undefined
}

function main() {
  const privateKeyB64 = process.env.CANARY_PRIVATE_KEY
  if (!privateKeyB64) {
    console.error('set CANARY_PRIVATE_KEY (base64url of the 32-byte Ed25519 seed from canary-keygen.mjs)')
    process.exit(1)
  }
  const allowBackdate = process.argv.includes('--backdate-for-testing')
  if (allowBackdate) console.error('\x1b[31m!! --backdate-for-testing: NEVER use this for a real canary; it voids the guarantee !!\x1b[0m')
  try {
    const doc = buildCanary({
      version: arg('version'),
      releaseHash: arg('hash'),
      statement: arg('statement'),
      signedAt: arg('date'),
      privateKeyB64,
      allowBackdate,
    })
    // Compact single line: this is what goes into the CANARY_JSON dashboard var.
    process.stdout.write(`${JSON.stringify(doc)}\n`)
  } catch (e) {
    console.error(`canary-sign: ${e instanceof Error ? e.message : e}`)
    process.exit(1)
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main()
