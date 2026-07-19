// Passwordless connection authentication (DESIGN 7.3). On connect the server
// issues a STRUCTURED challenge (never opaque bytes); the client verifies the
// challenge's origin matches where it actually connected BEFORE signing, then
// signs it with IK_sig. The server verifies the signature and that
// SHA-256(IK_sig_pub) == the claimed user id, proving key possession with no
// password and no signing oracle (auth signatures are domain-separated from
// prekey signatures via TAG_AUTH).
//
// Shared by client (src/net) and server (worker/): both derive the SAME signing
// bytes from the SAME challenge, so a signature made by one verifies at the other.

import { AUTH_CHALLENGE_TTL_MS, AUTH_NONCE_BYTES, CLOCK_SKEW_MS, TAG_AUTH } from '../crypto/constants'
import { deriveUserId } from '../crypto/identity'
import { domainSeparate, ed25519Sign, ed25519Verify, randomBytes, u64be, utf8 } from '../crypto/primitives'
import { b64decode, b64encode } from './codec'

/** The structured challenge the server issues and the client signs. `origin` is
 *  the server's own origin; the client MUST refuse to sign if it does not match
 *  the origin it connected to. `serverNonce` and `ts` make each challenge unique
 *  and time-bound. */
export interface AuthChallenge {
  tag: string
  serverNonce: string // base64url of AUTH_NONCE_BYTES random bytes
  connectionId: string
  origin: string
  ts: number
}

/** Server: build a fresh challenge for a connection. `nonce` is a test seam;
 *  production draws AUTH_NONCE_BYTES at random. */
export function buildChallenge(
  origin: string,
  connectionId: string,
  now: number,
  nonce?: Uint8Array,
): AuthChallenge {
  return {
    tag: TAG_AUTH,
    serverNonce: b64encode(nonce ?? randomBytes(AUTH_NONCE_BYTES)),
    connectionId,
    origin,
    ts: now,
  }
}

/** The exact bytes both sides sign/verify. Domain-separated under TAG_AUTH and
 *  length-framed field by field, so it is structurally injective and can never
 *  be reinterpreted as a prekey signature or vice versa. */
export function challengeSigningInput(c: AuthChallenge): Uint8Array {
  if (c.tag !== TAG_AUTH) throw new Error('auth: wrong challenge tag')
  return domainSeparate(
    TAG_AUTH,
    b64decode(c.serverNonce, AUTH_NONCE_BYTES),
    utf8(c.connectionId),
    utf8(c.origin),
    u64be(c.ts),
  )
}

/**
 * Client: verify a received challenge is well-formed, fresh, and bound to the
 * origin we actually connected to, THEN sign it. Throwing before signing is the
 * point: we never sign a challenge whose origin does not match, so a malicious
 * or wrong-origin relay cannot obtain an auth signature usable against the real
 * origin.
 */
export function verifyAndSignChallenge(
  c: AuthChallenge,
  connectedOrigin: string,
  ikSigPriv: Uint8Array,
  now: number,
): Uint8Array {
  if (c.tag !== TAG_AUTH) throw new Error('auth: challenge missing auth tag')
  if (typeof c.origin !== 'string' || c.origin !== connectedOrigin) {
    throw new Error('auth: challenge origin does not match the connected origin')
  }
  if (typeof c.connectionId !== 'string' || c.connectionId.length === 0) {
    throw new Error('auth: challenge missing connection id')
  }
  if (typeof c.ts !== 'number' || !Number.isFinite(c.ts)) throw new Error('auth: challenge missing timestamp')
  if (c.ts > now + CLOCK_SKEW_MS) throw new Error('auth: challenge timestamp is in the future')
  if (now - c.ts > AUTH_CHALLENGE_TTL_MS) throw new Error('auth: challenge is stale')
  // challengeSigningInput re-validates the nonce width and tag.
  return ed25519Sign(challengeSigningInput(c), ikSigPriv)
}

export interface AuthResult {
  userId: string
}

/**
 * Server: verify the client's signature over the challenge WE issued and stored
 * for this connection (never a client-supplied challenge), and derive the
 * authenticated user id from the presented IK_sig public key. Also re-checks the
 * challenge is still fresh, bounding replay. Throws on any failure.
 */
export function verifyAuthResponse(
  storedChallenge: AuthChallenge,
  ikSigPub: Uint8Array,
  sig: Uint8Array,
  now: number,
): AuthResult {
  if (now - storedChallenge.ts > AUTH_CHALLENGE_TTL_MS) throw new Error('auth: challenge expired')
  if (ikSigPub.length !== 32) throw new Error('auth: bad IK_sig public key length')
  if (!ed25519Verify(sig, challengeSigningInput(storedChallenge), ikSigPub)) {
    throw new Error('auth: signature does not verify')
  }
  return { userId: deriveUserId(ikSigPub) }
}
