// The code a device shows to start an optical ceremony (Sesame).
//
// Two ceremonies use this shape. A device that wants to be LINKED shows one, and
// an existing device scans it. A device that wants the account's SAVED MESSAGES
// shows one, and the device holding them scans it. Both are displayed as a QR and
// read by a camera, so they travel screen to camera and never over the network,
// and that is what the whole thing rests on: a value the relay has never seen can
// both encrypt what follows and prove who sent it.
//
// Layout, base64url encoded:
//   0   4   magic ("NJLC" to be linked, "NJHC" to be sent saved messages)
//   4   1   version (0x01)
//   5   32  the device's Ed25519 signing key
//   37  32  a fresh secret, used once, for this ceremony only
//
// The magic differs between the two DELIBERATELY. To a camera the codes are
// indistinguishable, so sharing one format would mean a code shown to ask for
// messages could be scanned on the linking screen and quietly add a device
// instead. Each parser accepts only its own.
//
// The device id is deliberately NOT carried. A device id IS the hash of that
// signing key, so deriving it here means a code cannot name one device while
// carrying another's key. That whole class of mismatch is removed by
// construction rather than checked for.

import {
  HISTORY_CODE_MAGIC,
  HISTORY_CODE_VERSION,
  LINK_CODE_MAGIC,
  LINK_CODE_VERSION,
  LINK_SECRET_BYTES,
} from '../crypto/constants'
import { deviceIdOf } from '../crypto/identity'
import { concatBytes, randomBytes, utf8 } from '../crypto/primitives'
import { b64decode, b64encode } from '../wire/codec'

const CODE_LEN = 4 + 1 + 32 + LINK_SECRET_BYTES

export interface LinkCode {
  /** Derived from the key below, never carried separately. */
  deviceId: string
  dkSigPub: Uint8Array
  secret: Uint8Array
}

export class LinkCodeError extends Error {
  constructor(message: string) {
    super(`link code: ${message}`)
    this.name = 'LinkCodeError'
  }
}

function buildCode(magic: string, version: number, dkSigPub: Uint8Array): { code: string; parsed: LinkCode } {
  if (dkSigPub.length !== 32) throw new LinkCodeError('device key must be 32 bytes')
  const secret = randomBytes(LINK_SECRET_BYTES)
  const bytes = concatBytes(utf8(magic), Uint8Array.from([version]), dkSigPub, secret)
  return {
    code: b64encode(bytes),
    parsed: { deviceId: deviceIdOf(dkSigPub), dkSigPub, secret },
  }
}

/** Read a scanned code, fail-closed. Rejects anything that is not exactly one of
 *  ours at exactly the expected width, so a truncated or padded scan is refused
 *  rather than silently producing a short secret. `noun` names what the caller was
 *  expecting, so scanning the wrong one of the two says which. */
function parseCode(magic: string, version: number, noun: string, code: string): LinkCode {
  let bytes: Uint8Array
  try {
    bytes = b64decode(code.trim())
  } catch {
    throw new LinkCodeError(`that does not look like a ${noun}`)
  }
  if (bytes.length !== CODE_LEN) throw new LinkCodeError(`that ${noun} is the wrong length`)
  const expected = utf8(magic)
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== expected[i]) throw new LinkCodeError(`that is not a ${noun}`)
  }
  if (bytes[4] !== version) throw new LinkCodeError(`that ${noun} is from a newer version`)
  const dkSigPub = bytes.slice(5, 37)
  return { deviceId: deviceIdOf(dkSigPub), dkSigPub, secret: bytes.slice(37) }
}

/** Build the code a device shows to be linked, with a fresh single-use secret. */
export function newLinkCode(dkSigPub: Uint8Array): { code: string; parsed: LinkCode } {
  return buildCode(LINK_CODE_MAGIC, LINK_CODE_VERSION, dkSigPub)
}

export function parseLinkCode(code: string): LinkCode {
  return parseCode(LINK_CODE_MAGIC, LINK_CODE_VERSION, 'device code', code)
}

/** Build the code a device shows to ask another for the account's saved messages. */
export function newHistoryCode(dkSigPub: Uint8Array): { code: string; parsed: LinkCode } {
  return buildCode(HISTORY_CODE_MAGIC, HISTORY_CODE_VERSION, dkSigPub)
}

export function parseHistoryCode(code: string): LinkCode {
  return parseCode(HISTORY_CODE_MAGIC, HISTORY_CODE_VERSION, 'saved-messages code', code)
}
