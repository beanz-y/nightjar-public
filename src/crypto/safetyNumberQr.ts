// The safety-number QR payload, and the comparison a scan performs (DESIGN 6.2).
//
// Verification is the highest-value control in the whole project (DESIGN 6.1), so
// a scanner that makes a WRONG verification easier would be a security regression
// even though it is a usability win. One property of the safety number forces the
// shape of this file:
//
//   the safety number is SYMMETRIC. Both parties compute the identical value
//   (safetyNumber sorts the two keys before hashing), so a payload carrying only
//   the digits is byte-identical on both devices.
//
// A scanner reading bare digits therefore cannot tell a genuine scan of the peer's
// screen from the victim being handed back a picture of their OWN verify screen.
// That makes the cheapest false verification indistinguishable from a real one.
//
// So the payload also carries a DIRECTION TAG: a short hash over the pair digest
// and the IK_sig of the device DISPLAYING it. The scanner knows both keys, so it
// can compute what the tag should be for its peer and what it would be for itself,
// and refuse anything that is not unambiguously the peer's. The tag is public,
// non-secret, and derived from the same values already on screen: it grants no new
// capability and adds no identifier a photograph of the code did not already imply.
//
// Payload:  NJSN1:<digits>:<tag>
//   NJSN1   4-char namespace + envelope version, matching the NJM1 / NJBK house
//           style. The namespace is what stops an invite code or a user id being
//           mistaken for a safety number, and vice versa: all three are QR codes in
//           this same app.
//   digits  the safety number with spaces stripped, BYTE-IDENTICAL to what the eye
//           compares, so the machine check is exactly the human check.
//   tag     base32(hash(domain-separated(pair digest, displayer IK_sig))[0..8])
//
// Everything here is pure and total: no throws, no I/O, no key material.

import { SN_DIGITS_PER_GROUP, SN_GROUPS } from './constants'
import { base32lower, domainSeparate, hash256 } from './primitives'

/** Namespace + envelope version. A future safety-number algorithm change bumps
 *  this, so an old peer's code is refused with "update your app" rather than
 *  compared and reported as a scary mismatch. */
export const SN_QR_MAGIC = 'NJSN1'
/** Domain-separation tag: this hash use must never collide with another. */
export const SN_QR_TAG = 'Nightjar-SNQR-v1'
/** Truncation of the direction tag. Nothing adversarial rests on its collision
 *  resistance (an attacker who could forge it would still have to match all
 *  digits, which requires the real key), so 64 bits is ample. */
const SN_QR_TAG_BYTES = 8

const SN_DIGIT_COUNT = SN_GROUPS * SN_DIGITS_PER_GROUP
/** base32 of 8 bytes, unpadded. */
const SN_QR_TAG_CHARS = Math.ceil((SN_QR_TAG_BYTES * 8) / 5)
const PAYLOAD_RE = new RegExp(`^${SN_QR_MAGIC}:(\\d{${SN_DIGIT_COUNT}}):([a-z2-7]{${SN_QR_TAG_CHARS}})$`)
/** Refused before parsing. A native BarcodeDetector will happily return kilobytes
 *  from a QR, and nothing legitimate here is longer than ~60 characters. */
const MAX_SCAN_CHARS = 256

/** The direction tag for the device DISPLAYING this code. `digest` is the raw
 *  safetyNumberDigest of the pair; `displayerIkSigPub` is the identity key of
 *  whichever device is showing the code. */
export function directionTag(digest: Uint8Array, displayerIkSigPub: Uint8Array): string {
  const h = hash256(domainSeparate(SN_QR_TAG, digest, displayerIkSigPub))
  return base32lower(h.slice(0, SN_QR_TAG_BYTES))
}

/** Build the payload this device shows for a contact. `digits` is the rendered
 *  safety number (spaces are stripped here), `myIkSigPub` is OUR key, because we
 *  are the one displaying it. */
export function encodeSafetyNumberQr(digits: string, digest: Uint8Array, myIkSigPub: Uint8Array): string {
  return `${SN_QR_MAGIC}:${digits.replace(/ /g, '')}:${directionTag(digest, myIkSigPub)}`
}

/** Why a scanned string could not be compared. Each maps to a distinct, honest
 *  message: telling someone "that did not match" when they actually scanned an
 *  invite code would send them hunting for an attack that is not there. */
export type ScanRejection =
  | 'unsupported-version' // a Nightjar safety-number code this build cannot read
  | 'legacy-digits' // bare digits: a peer on an older build
  | 'other-nightjar-code' // an invite code or a user id, both also QRs in this app
  | 'unreadable' // not a Nightjar code at all

/** The outcome of scanning a code while viewing one contact's verify screen. */
export type ScanVerdict =
  /** Same safety number AND displayed by this contact's device. The only outcome
   *  that may lead to marking verified, and even then only after the human says
   *  how they scanned it. */
  | { kind: 'match' }
  /** Same safety number, but the code is the one THIS device shows. Someone
   *  scanned their own screen, a mirror, or a picture of their own code. */
  | { kind: 'self' }
  /** Same safety number, tag belongs to neither party. Should not happen between
   *  two honest current builds, so it is refused rather than guessed at. */
  | { kind: 'indeterminate' }
  /** Different safety number. This is the loud one: it means the key one side
   *  holds is not the key the other side holds. */
  | { kind: 'mismatch' }
  | { kind: 'rejected'; reason: ScanRejection }

/** Classify a scanned string without comparing it yet. Total: never throws. */
export function parseSafetyNumberQr(text: string): { digits: string; tag: string } | { rejected: ScanRejection } {
  const raw = typeof text === 'string' ? text.trim() : ''
  if (raw.length === 0 || raw.length > MAX_SCAN_CHARS) return { rejected: 'unreadable' }
  const m = PAYLOAD_RE.exec(raw)
  if (m) return { digits: m[1], tag: m[2] }
  // A Nightjar safety-number code from a build we cannot read. Checked before the
  // generic cases so it never degrades to "that is not a Nightjar code".
  if (/^NJSN\d*:/.test(raw)) return { rejected: 'unsupported-version' }
  // The payload this app itself generated before scanning existed.
  if (new RegExp(`^\\d{${SN_DIGIT_COUNT}}$`).test(raw)) return { rejected: 'legacy-digits' }
  // The two other QR codes in this app, so the user gets "that is your invite
  // code" instead of a mismatch scare.
  if (/^[a-z2-7]{52}$/.test(raw.toLowerCase())) return { rejected: 'other-nightjar-code' }
  if (/[#?&]i=/.test(raw) || /^[A-Za-z0-9]{12}(\.[a-z2-7]{52})?$/.test(raw)) return { rejected: 'other-nightjar-code' }
  return { rejected: 'unreadable' }
}

/**
 * Compare a scanned string against the contact whose verify screen is open.
 *
 * Fails closed: every outcome that is not an unambiguous, correctly-directed match
 * refuses, and only 'match' may lead to a trust change. Nothing here writes
 * anything: a mismatch deliberately mutates no durable state, so a hostile code
 * held up to someone's camera cannot damage a real contact record.
 */
export function compareScannedSafetyNumber(
  scanned: string,
  expected: { digits: string; digest: Uint8Array; myIkSigPub: Uint8Array; peerIkSigPub: Uint8Array },
): ScanVerdict {
  const parsed = parseSafetyNumberQr(scanned)
  if ('rejected' in parsed) return { kind: 'rejected', reason: parsed.rejected }

  // Digits first: a different safety number is the finding, whoever displayed it.
  if (parsed.digits !== expected.digits.replace(/ /g, '')) return { kind: 'mismatch' }

  if (parsed.tag === directionTag(expected.digest, expected.peerIkSigPub)) return { kind: 'match' }
  if (parsed.tag === directionTag(expected.digest, expected.myIkSigPub)) return { kind: 'self' }
  return { kind: 'indeterminate' }
}
