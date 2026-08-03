// The code a device shows when it wants to be linked (Sesame).
//
// It is displayed as a QR on the NEW device and scanned by an existing one, so
// it travels screen to camera and never over the network. That is what the whole
// ceremony rests on, and it is why the code carries a secret at all: a value the
// relay has never seen can both encrypt the transfer and prove who sent it.
//
// Layout, base64url encoded:
//   0   4   magic "NJLC"
//   4   1   version (0x01)
//   5   32  the device's Ed25519 signing key
//   37  32  a fresh secret, used once, for this link only
//
// The device id is deliberately NOT carried. A device id IS the hash of that
// signing key, so deriving it here means a code cannot name one device while
// carrying another's key. That whole class of mismatch is removed by
// construction rather than checked for.

import { LINK_CODE_MAGIC, LINK_CODE_VERSION, LINK_SECRET_BYTES } from '../crypto/constants'
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

/** Build the code a device shows to be linked, with a fresh single-use secret. */
export function newLinkCode(dkSigPub: Uint8Array): { code: string; parsed: LinkCode } {
  if (dkSigPub.length !== 32) throw new LinkCodeError('device key must be 32 bytes')
  const secret = randomBytes(LINK_SECRET_BYTES)
  const bytes = concatBytes(utf8(LINK_CODE_MAGIC), Uint8Array.from([LINK_CODE_VERSION]), dkSigPub, secret)
  return {
    code: b64encode(bytes),
    parsed: { deviceId: deviceIdOf(dkSigPub), dkSigPub, secret },
  }
}

/** Read a scanned code, fail-closed. Rejects anything that is not exactly one of
 *  ours at exactly the expected width, so a truncated or padded scan is refused
 *  rather than silently producing a short secret. */
export function parseLinkCode(code: string): LinkCode {
  let bytes: Uint8Array
  try {
    bytes = b64decode(code.trim())
  } catch {
    throw new LinkCodeError('that does not look like a device code')
  }
  if (bytes.length !== CODE_LEN) throw new LinkCodeError('that device code is the wrong length')
  const magic = utf8(LINK_CODE_MAGIC)
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== magic[i]) throw new LinkCodeError('that is not a device code')
  }
  if (bytes[4] !== LINK_CODE_VERSION) throw new LinkCodeError('that device code is from a newer version')
  const dkSigPub = bytes.slice(5, 37)
  return { deviceId: deviceIdOf(dkSigPub), dkSigPub, secret: bytes.slice(37) }
}
