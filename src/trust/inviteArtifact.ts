// The invite artifact (DESIGN 6.3): what an inviter hands a joiner out of band.
// It is NOT just the invite code: it also carries the inviter's full-width
// userId (= base32(SHA-256(IK_sig)), so an untruncated 256-bit fingerprint), so
// the joiner can PIN the inviter's real identity key on join. The joiner's client
// fetches the inviter's bundle and checks deriveUserId(key) == this userId (the
// binding check in NightjarClient.addInviteContact), which authenticates the
// inviter -> joiner direction.
//
// Encoded as a compact `CODE.inviterUserId` token (or just `CODE` for a bootstrap
// admin invite, which has no real inviter to pin). The invite code is uppercase
// Crockford and the userId lowercase base32 (a-z,2-7), so `.` never collides with
// either alphabet. A nightjar invite URL wraps the same token for a QR / link.

import { isWellFormedInviteCode, normalizeInviteCode } from '../server/invites'

/** userId shape: lowercase, unpadded base32 of a 32-byte hash = 52 chars. */
const USER_ID_RE = /^[a-z2-7]{52}$/

export interface InviteArtifact {
  /** Canonical 12-char invite code. */
  code: string
  /** Inviter userId to pin, or null for a bootstrap/admin invite. */
  inviter: string | null
}

/** The compact token an inviter shares. */
export function encodeInviteArtifact(a: InviteArtifact): string {
  return a.inviter ? `${a.code}.${a.inviter}` : a.code
}

/** Parse a token, or a nightjar invite URL (`…#i=TOKEN` / `…?i=TOKEN`). Throws on
 *  a malformed code. The inviter, if present, is shape-checked here but only
 *  authenticated for real by the binding check in addInviteContact. */
export function decodeInviteArtifact(input: string): InviteArtifact {
  let token = input.trim()
  const m = token.match(/[#?&]i=([^#?&\s]+)/)
  if (m) token = decodeURIComponent(m[1])
  token = token.trim()

  const dot = token.indexOf('.')
  if (dot === -1) {
    const code = normalizeInviteCode(token)
    if (!isWellFormedInviteCode(code)) throw new Error('not a valid invite code')
    return { code, inviter: null }
  }
  const code = normalizeInviteCode(token.slice(0, dot))
  const inviter = token.slice(dot + 1).trim().toLowerCase()
  if (!isWellFormedInviteCode(code)) throw new Error('not a valid invite code')
  if (!USER_ID_RE.test(inviter)) throw new Error('invite has a malformed inviter id')
  return { code, inviter }
}

/** A deep-link URL wrapping the artifact, for a QR code or a shared link. */
export function inviteUrl(origin: string, a: InviteArtifact): string {
  return `${origin}/#i=${encodeInviteArtifact(a)}`
}
