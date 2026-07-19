// P7 verifiability constants (DESIGN 10, §6; DESIGN 10.3). The in-app warrant
// canary is a signed, dated operator statement whose staleness or absence is the
// signal. Thresholds are deliberately generous: a canary that cries wolf on
// routine operator lateness just trains click-through (the 10.6 lesson), so the
// cadence is ~monthly and the alarming states are reserved for a reachable server
// that actively returns a bad or missing answer.

/** Domain-separation tag for the canary signature. Framed by domainSeparate() like
 *  every other Nightjar signature, so a canary signature can never be reinterpreted
 *  as an idkbind/spk/auth signature or vice versa. */
export const TAG_CANARY = 'Nightjar-canary-v1'

/** A canary at most this old reads as fresh (quiet, About-only). */
export const CANARY_FRESH_DAYS = 30
/** Older than this reads as stale: a dismissible warning. Between the two it is
 *  "aging" (a subtle About note, no banner). */
export const CANARY_STALE_DAYS = 45

/** A signedAt more than this far in the FUTURE is treated as invalid, never fresh.
 *  The warrant-canary guarantee rests on the operator being unable to forge a
 *  future fresh date without the offline key (DESIGN 10), so a future-dated
 *  blob must never be silently trusted (MF3). Also absorbs benign client skew. */
export const CANARY_FUTURE_SKEW_MS = 5 * 60 * 1000

/** Expected byte widths of the pinned key and the canary signature (Ed25519). */
export const CANARY_PUBKEY_BYTES = 32
export const CANARY_SIG_BYTES = 64
/** A release hash is SHA-256 hex. */
export const RELEASE_HASH_HEX_LEN = 64
/** Defensive upper bounds on the free-text canary fields (bounded before crypto). */
export const CANARY_MAX_VERSION_LEN = 64
export const CANARY_MAX_STATEMENT_LEN = 1024
