// Pinned protocol constants (DESIGN.md section 14). Changing any value here is a
// wire-format or security change: keep it in lockstep with the design doc and
// the known-answer tests.

/** Protocol/ciphersuite version octet. v1 is classical X25519 (DESIGN 4.4). */
export const VERSION = 0x01

// Domain-separation context tags. Every IK_sig signature is over a distinct,
// length-framed tag so one signing use can never be an oracle for another
// (DESIGN 2, 4.1, 7.3; the v0.1 signing-oracle bug). See domainSeparate().
export const TAG_IDKBIND = 'Nightjar-idkbind-v1'
export const TAG_SPK = 'Nightjar-spk-v1'
export const TAG_AUTH = 'Nightjar-auth-v1'

// KDF info strings, one per derivation, all versioned (DESIGN 4.2, 5.1).
export const INFO_X3DH = 'Nightjar_X3DH_v1'
export const INFO_DR_ROOT = 'Nightjar_DRRoot_v1'
export const INFO_MSG_KEY = 'Nightjar_MsgKey_v1'

// Safety number (DESIGN 6.2, 14). Iterated SHA-512; the display must carry at
// least 120 bits so it cannot be ground to a collision.
export const SN_TAG = 'Nightjar-SN-v1'
export const SN_ITERATIONS = 5200
/** 8 groups x 5 decimal digits = 40 digits ~= 132 bits displayed (>= 120). */
export const SN_GROUPS = 8
export const SN_DIGITS_PER_GROUP = 5

// Double Ratchet bound (DESIGN 5.3, 14). Checked BEFORE any key derivation, so
// it is a compute bound as well as a storage bound. (Consumed at P2.)
export const MAX_SKIP = 1000

/** Skipped message keys older than this are pruned (DESIGN 5.3, 14). Completes
 *  the retry invariant chain: outbox retry horizon (7d) < seen-id TTL (8d) <
 *  skipped-key expiry (14d), so a sender's late retry always lands on either a
 *  live skipped key or the receiver's dedup, never a silently-aged-out key. */
export const SKIPPED_KEY_EXPIRY_MS = 14 * 24 * 60 * 60 * 1000

// Session management (DESIGN 6.4, 8.3; the P5 glare fix). A peer slot holds a
// small SET of ratchet sessions (a "session book"), not one: simultaneous
// first-contact ("glare") leaves each side with two live sessions, and a
// re-established session (restore, 8.3) must be able to replace a stale one
// without silently clobbering an in-flight one. Sends use the current session;
// receives try current then the others and keep whichever authenticates. The book
// is bounded so a peer cannot grow it without limit (each accepted initial from
// them promotes a new current); the least-recently-used non-current session is
// evicted past the cap.
export const MAX_SESSIONS_PER_PEER = 5

// Receiver-side poison drop (DESIGN 5.3: "an unknown id that fails to decrypt" is
// the one corruption case). An envelope that never decrypts is normally NOT acked
// so a legitimately-reordered message (a normal arriving before its initial) gets
// re-tried on redelivery. But a permanently-undecryptable envelope would then be
// redelivered forever. After this many failed attempts it is acked-and-dropped.
// Kept generous so a delayed initial has many redeliveries to arrive first.
export const POISON_MAX_ATTEMPTS = 10

// Authentication (DESIGN 7.3). The connection challenge is signed under TAG_AUTH
// (domain-separated from prekey signatures) and is short-lived: a response older
// than this is refused, bounding any replay window.
export const AUTH_CHALLENGE_TTL_MS = 2 * 60 * 1000
/** Server nonce width in the auth challenge. */
export const AUTH_NONCE_BYTES = 16

// X3DH / prekeys (DESIGN 4, 14).
/** Reject a peer advertising a version below this (downgrade protection, 4.4). */
export const VERSION_FLOOR = 0x01
/** The client rotates its signed prekey once the current one is older than this
 *  (checked on every authenticated connect; P8). */
export const SPK_ROTATION_MS = 7 * 24 * 60 * 60 * 1000
/** Initiator rejects a signed prekey older than this (2x rotation). */
export const SPK_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000
/** Tolerance for clock skew when validating signed-prekey timestamps. */
export const CLOCK_SKEW_MS = 5 * 60 * 1000
/** How long a RETIRED signed prekey's private half is kept after its expiry: an
 *  initial message may be built any time the sender's fetched bundle still
 *  verifies (up to expiry + skew) and then sit queued for the full envelope TTL,
 *  so the responder must be able to open it that long (P8 rotation). */
export const SPK_RETIRE_GRACE_MS = 30 * 24 * 60 * 60 * 1000 + 5 * 60 * 1000
/** One-time prekey batch size, and the low-water mark to replenish at (P4). */
export const OPK_BATCH = 100
export const OPK_REPLENISH_THRESHOLD = 20

// Relay / delivery timing (DESIGN 7.1, 7.2, 14). The invariant chain is:
//   outbox retry horizon  <  seen-id TTL  <  skipped-key expiry
// so a duplicate can never slip past the receiver's dedup while the sender may
// still retry, and a late retry never lands on an aged-out skipped key.
/** Undelivered ciphertext is alarm-purged from an Inbox after this. */
export const ENVELOPE_TTL_MS = 30 * 24 * 60 * 60 * 1000
/** The client stops retrying an unacked outbox entry after this (DESIGN 7.2). */
export const OUTBOX_RETRY_HORIZON_MS = 7 * 24 * 60 * 60 * 1000
/** Inbox keeps a delivered id long enough to ack-and-drop a duplicate: must be
 *  >= the outbox retry horizon (DESIGN 7.1). */
export const SEEN_ID_TTL_MS = 8 * 24 * 60 * 60 * 1000
/** A repeat bundle fetch by the same (fetcher,target) within this window returns
 *  the SAME one-time prekey instead of depleting another (DESIGN 4.3). */
export const OPK_VEND_TTL_MS = 7 * 24 * 60 * 60 * 1000

// Server-side abuse ceilings. The Directory and Inbox are shared,
// single-instance-ish Durable Objects, so an unbounded write from one registered
// account is a shared-fate DoS. These bound each write path.
/** Max one-time prekeys accepted in a single register/publish call. */
export const MAX_OPKS_PER_REQUEST = 2 * OPK_BATCH
/** Max available (un-vended) one-time prekeys a user may accumulate. */
export const MAX_AVAILABLE_OPKS = 3 * OPK_BATCH
/** Max outstanding (unused, unexpired) invites a single inviter may hold. */
export const MAX_OUTSTANDING_INVITES = 50
/** Max joiner ids returned by a single inviteRedemptions lookup (mutual invite):
 *  bounds the wire response AND the inviter's per-connect bundle-fetch fan-out, since
 *  the redeemed-invite set is capped only by the 30-day retention, not MAX_OUTSTANDING_INVITES. */
export const MAX_INVITE_REDEMPTIONS = 200
/** An unredeemed invite expires after this and is purged. */
export const INVITE_TTL_MS = 30 * 24 * 60 * 60 * 1000
/** Max queued (undelivered) envelopes an Inbox will hold. */
export const MAX_QUEUED_ENVELOPES = 5000
/** Max total queued ciphertext bytes an Inbox will hold. */
export const MAX_QUEUED_BYTES = 32 * 1024 * 1024

// Web Push (P6, DESIGN 7.4). Subscriptions live in the per-user Inbox DO,
// registered only over the authenticated socket. Push is off entirely until a
// VAPID_JWK secret is set (off-until-secret, like ADMIN_TOKEN).
/** Max push subscriptions (devices) a single user's Inbox will hold. */
export const MAX_PUSH_SUBS = 20
/** A push subscription the client stops refreshing (device gone quiet) is
 *  alarm-purged after this. The client re-sends pushSubscribe on every connect
 *  while opted in, so an active device's row stays fresh well within it. */
export const PUSH_SUB_TTL_MS = 60 * 24 * 60 * 60 * 1000
/** How long the push service keeps retrying delivery to an offline device. A
 *  message nudge is still useful hours later, but not past the envelope TTL. */
export const PUSH_TTL_SEC = 24 * 60 * 60
/** Max endpoint-URL length accepted in pushSubscribe (a real push endpoint is a
 *  few hundred bytes; this bounds storage + outbound fetch size). */
export const MAX_PUSH_ENDPOINT_LEN = 2048

// Presence (P6). A push is sent for a new envelope only when the
// user has no socket that is "fresh-watching" (foreground). The client re-affirms
// watching while its page is visible; a slept/backgrounded/zombie socket stops
// affirming and goes stale within the freshness window, so its stale watching bit
// can only suppress a push for at most that long (it never suppresses forever).
/** The client re-affirms `watching` this often while its page is visible. */
export const PRESENCE_HEARTBEAT_MS = 45 * 1000
/** A `watching` affirmation older than this no longer counts as foreground, so a
 *  new envelope is pushed. Must exceed the heartbeat by >1 interval so a single
 *  dropped heartbeat does not spuriously push to an active foreground app. */
export const PRESENCE_FRESH_MS = 110 * 1000

// Identity backup (P8, DESIGN 8.3, 14). The blob is a fixed header (magic,
// format version, Argon2id parameters, salt) followed by an XChaCha20-Poly1305
// body whose key and nonce both derive from the passphrase; the header is the
// AAD, so no field of it can be altered without failing the tag.
export const BACKUP_MAGIC = 'NJBK'
export const BACKUP_FORMAT_VERSION = 0x01
/** Argon2id parameters pinned for exports: 64 MiB, 3 passes, 1 lane. Measured
 *  (@noble/hashes, desktop): ~2.3 s; the earlier provisional 256 MiB measured
 *  9.1 s and risks OOM in an iOS Safari worker. 64 MiB / t=3 is RFC 9106's
 *  constrained-environment recommendation; p=1 because a browser runs one lane
 *  and extra lanes in one thread only slow the defender. */
export const BACKUP_ARGON2_M_KIB = 65536
export const BACKUP_ARGON2_T = 3
export const BACKUP_ARGON2_P = 1
/** Restore-side bounds, enforced BEFORE the KDF runs so a hostile blob cannot
 *  make the client allocate gigabytes or spin for minutes. */
export const BACKUP_MIN_M_KIB = 8192
export const BACKUP_MAX_M_KIB = 262144
export const BACKUP_MAX_T = 6
export const BACKUP_SALT_BYTES = 16
/** KDF expansion info for the backup key+nonce (one derivation, versioned). */
export const INFO_BACKUP = 'Nightjar_Backup_v1'
/** Decrypted payload cap, enforced before JSON.parse (identity is 192 bytes and
 *  contacts are small; anything near this is not one of our blobs). */
export const BACKUP_MAX_PAYLOAD_BYTES = 256 * 1024
export const BACKUP_MAX_CONTACTS = 1000
/** Minimum typed-passphrase length (after trim + NFC). The offered generated
 *  passphrase is 20 base32 characters (~100 bits) and always passes. */
export const PASSPHRASE_MIN_LENGTH = 12

// Persistent local message history (P10b, DESIGN 8.1/8.3, 14). Each history
// row's body is sealed with a per-record key+nonce derived from a random 32-byte
// History Master Key (HMK) and a FRESH per-record salt. The fresh salt is
// load-bearing: a constant key with a constant salt would reuse the XChaCha
// keystream across rows (the trap in backup.ts's zero-salt deriveKeyNonce, which
// is safe there only because its key is single-use). The AEAD AAD binds the
// peerId + content msgId + version so a row cannot be moved between conversations
// or ids. P10b stores the HMK UNWRAPPED (history is therefore plaintext-at-rest,
// disclosed); P10c wraps it under an app-lock without changing this row format.
export const HISTORY_HMK_BYTES = 32
export const HISTORY_SALT_BYTES = 16
export const INFO_HISTORY = 'Nightjar_History_v1'
/** History-ROW format version bound into each row's AEAD AAD. Deliberately
 *  SEPARATE from the wire ciphersuite `VERSION`: history is an at-rest artifact
 *  and must not be invalidated by a wire-protocol bump (a v2 PQXDH upgrade bumps
 *  VERSION, and binding VERSION here would make every existing row fail to open).
 *  Bump this only on a deliberate history-row format change, with a migration. */
export const HISTORY_FORMAT_VERSION = 0x01

// Delete-for-everyone (P10d). A received delete may arrive BEFORE the message it
// targets (the two ride different envelopes and the relay can reorder / redeliver
// within its TTL). A `tombstone` records "this content id was deleted" so a later-
// arriving target is suppressed instead of persisted+shown. A tombstone need only
// outlive the redelivery window of its target, so it ages out on the SAME bound as
// an undelivered envelope: past `ENVELOPE_TTL_MS` the target can no longer be in
// flight, so the tombstone is dead weight. Keyed by the same opaque HMAC storage
// key as the history row it suppresses (so it too reveals no peer/id at rest).
export const TOMBSTONE_TTL_MS = ENVELOPE_TTL_MS

// App-lock (P10c, mandatory). All at-rest local data (message history bodies AND
// metadata, and the contact list) is encrypted under a random 32-byte Local Data
// Key (LDK, `HISTORY_HMK_BYTES` long). The LDK is NEVER stored unwrapped: it is
// generated in RAM at enrollment and wrapped under a KEK derived from each enabled
// unlock method (passphrase / PIN via Argon2id, biometric via WebAuthn PRF). A
// PWA has no OS keychain, so at-rest confidentiality reduces to the strength of
// the unlock secret; a short PIN is offline-brute-forceable from a device image
// (disclosed), so passphrase/biometric are the strong options.
export const LOCK_WRAP_FORMAT_VERSION = 0x01
/** KDF info expanding a KEK+nonce from the Argon2id output or the PRF secret. */
export const INFO_LOCK_WRAP = 'Nightjar_LockWrap_v1'
/** Sub-key derivation infos off the LDK (one independent key per at-rest use). */
export const INFO_HISTORY_BODY = 'Nightjar_HistBody_v1'
export const INFO_HISTORY_INDEX = 'Nightjar_HistIndex_v1'
export const INFO_CONTACTS = 'Nightjar_Contacts_v1'
/** Argon2id params for a knowledge-factor KEK: same as the backup blob (64 MiB,
 *  t=3, p=1; ~2.3 s desktop). Reused deliberately so there is one tuned cost. */
export const LOCK_ARGON2_M_KIB = BACKUP_ARGON2_M_KIB
export const LOCK_ARGON2_T = BACKUP_ARGON2_T
export const LOCK_ARGON2_P = BACKUP_ARGON2_P
/** Fresh CSPRNG salt widths per wrap (Argon2id salt + HKDF salt). */
export const LOCK_SALT_BYTES = 16
/** Minimum passphrase length (after NFC+trim), shared with the backup floor. */
export const LOCK_PASSPHRASE_MIN_LENGTH = PASSPHRASE_MIN_LENGTH
/** Minimum PIN digits. A numeric PIN is convenience-grade: even this floor is
 *  weak against an extracted device image (no PWA hardware rate-limiting), so the
 *  UI must label it as such and steer at-rest-sensitive users to a passphrase. */
export const PIN_MIN_DIGITS = 6
/** Fixed WebAuthn PRF evaluation input, pinned so the derived PRF secret is
 *  stable for a credential across unlocks. */
export const LOCK_PRF_INPUT = 'Nightjar-applock-prf-v1'
