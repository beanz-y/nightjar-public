// Invite codes (DESIGN 6.3, 7.1). A single-use, unguessable code gates
// registration. Redemption itself is a guarded read-modify-write inside the
// single-threaded Directory DO (worker/directory.ts): the DO's turn IS the
// atomic batch, so the one-way `used` transition and self-stamped `usedBy` are
// plain code invariants there. This module is only the code MINTING (pure,
// CSPRNG) and format validation, so it lives here and is node-tested.

// Crockford-style alphabet: 31 symbols, no 0/O/1/I/L to avoid transcription
// errors when a code is read aloud or copied by hand.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
/** 12 symbols over a 31-char alphabet ~= 59.4 bits: unguessable online on its
 *  own. The Directory additionally caps outstanding invites per inviter and
 *  expires unredeemed ones (worker/directory.ts). */
export const INVITE_CODE_LEN = 12

// Rejection-sampling bound: the largest multiple of the alphabet size that fits
// in a byte. Drawing only below it makes every symbol equiprobable (no modulo
// bias, unlike a plain `byte % 31`).
const REJECT_LIMIT = Math.floor(256 / ALPHABET.length) * ALPHABET.length

function pickSymbol(): string {
  const buf = new Uint8Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    if (buf[0] < REJECT_LIMIT) return ALPHABET[buf[0] % ALPHABET.length]
  }
}

/** Mint a fresh invite code (canonical form: uppercase, no separators). */
export function newInviteCode(): string {
  let out = ''
  for (let i = 0; i < INVITE_CODE_LEN; i++) out += pickSymbol()
  return out
}

/** Group the canonical code into 4-char blocks for display: ABCD-EFGH-JKMN.
 *  Purely cosmetic; normalizeInviteCode reverses it. */
export function formatInviteCode(code: string): string {
  return code.replace(/(.{4})(?=.)/g, '$1-')
}

/** Canonicalize user input: strip separators/whitespace and uppercase. Does not
 *  validate; pair with isWellFormedInviteCode. */
export function normalizeInviteCode(input: string): string {
  return input.replace(/[^A-Za-z0-9]/g, '').toUpperCase()
}

const CODE_RE = new RegExp(`^[${ALPHABET}]{${INVITE_CODE_LEN}}$`)

/** True only for a canonical code: exact length, every symbol in-alphabet. The
 *  Directory rejects anything else before touching storage. */
export function isWellFormedInviteCode(code: string): boolean {
  return CODE_RE.test(code)
}
