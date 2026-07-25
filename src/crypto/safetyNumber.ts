// Safety numbers (DESIGN 6.2). An order-independent, human-comparable function
// of two identity signing keys, for the out-of-band verification that is the
// single highest-value security control in Nightjar (DESIGN 6.1).
//
// SN = render( iterated-SHA512^N_iter( SN_TAG || sort(IK_sig_a, IK_sig_b) ) )
//
// The display carries ~132 bits (8 groups x 5 decimal digits), comfortably over
// the >= 120-bit floor that keeps it non-grindable (DESIGN 14).

import { SN_DIGITS_PER_GROUP, SN_GROUPS, SN_ITERATIONS, SN_TAG } from './constants'
import { compareBytes, concatBytes, hash512, utf8 } from './primitives'

const GROUP_MODULUS = 10 ** SN_DIGITS_PER_GROUP

/** The raw 64-byte iterated digest, before rendering. Exposed for testing. */
export function safetyNumberDigest(ikSigPubA: Uint8Array, ikSigPubB: Uint8Array): Uint8Array {
  const [lo, hi] = compareBytes(ikSigPubA, ikSigPubB) <= 0
    ? [ikSigPubA, ikSigPubB]
    : [ikSigPubB, ikSigPubA]
  let digest = hash512(concatBytes(utf8(SN_TAG), lo, hi))
  for (let i = 1; i < SN_ITERATIONS; i++) digest = hash512(digest)
  return digest
}

/** Render an already-computed digest as the human-facing digit groups. Split out so
 *  a caller that needs BOTH the digest and the digits (the verify screen, which
 *  needs the digest for the QR direction tag) pays for the 5200 iterated hashes
 *  once instead of twice. */
export function renderSafetyNumber(digest: Uint8Array): string {
  const groups: string[] = []
  for (let g = 0; g < SN_GROUPS; g++) {
    // 5 big-endian bytes -> a value mod 100000, zero-padded to 5 digits.
    let value = 0
    for (let j = 0; j < 5; j++) value = (value * 256 + digest[g * 5 + j]) % GROUP_MODULUS
    groups.push(String(value).padStart(SN_DIGITS_PER_GROUP, '0'))
  }
  return groups.join(' ')
}

/** The human-facing safety number, e.g. "01234 56789 ...". */
export function safetyNumber(ikSigPubA: Uint8Array, ikSigPubB: Uint8Array): string {
  return renderSafetyNumber(safetyNumberDigest(ikSigPubA, ikSigPubB))
}
