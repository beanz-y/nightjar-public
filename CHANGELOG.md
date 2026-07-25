# Changelog

All notable changes to Nightjar are recorded here. This project cares about honest
disclosure, so each entry says what a change does and, where it matters, what it
does not do.

Entries cite the short commit hash so you can read the full diff (`git show <hash>`,
or the commit page on the repository host). The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/); version headings correspond to the
release tags cut by the deploy pipeline. Dates are the tag dates.

## [Unreleased]

## [1.6.0] - 2026-07-24

### Added
- **Scan a contact's code to compare safety numbers.** The verify screen can now
  use the camera instead of asking you to read 40 digits, which is the step people
  actually get wrong. The QR payload changed to carry, alongside the same digits,
  a short tag identifying the device displaying it. That matters more than it
  sounds: a safety number is the same on both devices, so a code carrying only the
  digits cannot tell a real scan of your contact's screen from someone handing you
  back a picture of your own. Scanning is fail-closed, and it names what happened
  rather than just passing or failing: a self-scan, a code from a different
  contact, an invite code, or an app version mismatch each get their own message.
  Both devices need this version to scan each other; comparing by eye is unchanged
  and always available.
- **A scan never verifies on its own, and never un-verifies either.** A match
  unlocks the confirmation, and you still confirm that you scanned their actual
  device, in person or on a live call. The camera can prove two codes agree; it
  cannot prove where the image came from, and a forwarded photo of a genuine code
  looks identical. A mismatch is shown loudly and changes nothing that is stored,
  so nobody can strip your verifications by putting a QR code in front of a camera.
- **Remove a verification.** If you learn you confirmed the wrong person you can
  now withdraw it, from the verify screen, behind a confirmation. It keeps the
  contact, their key, and your messages, and puts them back to unverified. Until
  now "verified" was a one-way door, which is not a good place to add a faster
  route into.
- **Sent and delivered indicators.** Your own messages show whether they are still
  on your device, stored for the other person, or picked up by their device. Both
  positive states are the relay's word, not a signed statement from your contact,
  and the tooltips say exactly that. "Delivered" means a device accepted the bytes:
  it does not mean anyone read it. There are no read receipts, deliberately, and
  the reasoning is in DESIGN 1.2 and 8.8. Nothing is stored on the relay for this,
  and the status is sealed inside your message history like the message itself, so
  a device image learns nothing new from it.

### Fixed
- **The "back up identity" icon rendered as an empty box on Android.** It, and two
  others, were Unicode symbols from blocks the default Android fonts do not cover.
  All the menu icons are now drawn by the app, so they no longer depend on which
  fonts a device happens to ship.
- **Queued messages could pile up in the wrong order.** The outbox was flushed in
  storage-key order, which is effectively random, rather than in the order you
  actually did things. It now flushes oldest first.
- **A full recipient inbox failed silently.** If someone's inbox was full, messages
  to them kept retrying with nothing shown, for up to a week. It now says so once.
- **"Erase saved messages" left the delete records behind.** The forgot-your-secret
  reset cleared your messages but not the markers recording which messages had been
  deleted for everyone. It now clears both, as that screen always said it would.
- **A future storage upgrade would have hung a second open tab.** The database open
  path had no handler for the case where another tab still holds an older version,
  so it would have waited forever with no error rather than telling you to reload.

## [1.5.3] - 2026-07-22

### Fixed
- **Portrait lock now holds on installed Android PWAs, including de-Googled ones.**
  The manifest `orientation` field (1.5.2) only binds when the install creates a
  WebAPK, which needs Google Play Services; on de-Googled Android (for example
  GrapheneOS with Vanadium) an install is a home-screen shortcut with no WebAPK, so
  the OS never applied it. The app now also locks portrait at runtime via the Screen
  Orientation API in standalone mode, which does not depend on a WebAPK. Honest scope:
  this affects only the installed home-screen app, never a browser tab, and iOS is not
  covered because Apple exposes no web orientation lock at all.

## [1.5.2] - 2026-07-22
- **Orientation locked on PWA mobile**

## [1.5.0] - 2026-07-22

### Added
- **Choose your time format.** A per-device Auto / 12-hour / 24-hour setting for
  message timestamps, in Settings. Auto follows the device locale (the previous
  behavior); the choice applies live and is local to each device.
- **Add biometric unlock after setup.** Fingerprint or face unlock can now be turned
  on, or off, any time from Settings, not only during initial enrollment. It never
  becomes your only lock; your passphrase or PIN always stays as a fallback. This also
  gives a fast unlock on devices where the passphrase hashing is slow (for example a
  browser running with its JavaScript optimizer disabled).

### Changed
- **The message composer grows with your text.** It expands from one line up to a few
  lines as you type a longer message, then scrolls inside, instead of a single fixed
  line. On a physical keyboard, Enter sends and Shift+Enter starts a new line; on a
  touch keyboard, Enter starts a new line and you send with the button.

### Fixed
- **The on-screen keyboard no longer hides your latest messages.** The conversation
  keeps the newest messages in view when the mobile keyboard opens and as the composer
  grows.

### Added
- **Cross-tab live message sync across open, unlocked tabs of the same account.** A
  same-origin BroadcastChannel fans a render-only append/delete/failed event to
  sibling tabs, so every open unlocked tab updates its in-memory view live. This
  closes the session-only (ephemeral) multi-tab gap and also gives normal messages
  live multi-tab sync (previously they only appeared after a reload). Receivers
  never re-decrypt, re-persist, or re-ack, so the message ratchet stays
  single-writer; the channel is closed while a tab is locked; and nothing leaves the
  browser, so relay-visible metadata is unchanged. (2b98a36)

## [1.3.0] - 2026-07-22

### Security
- **Keep the userId out of the /connect URL, and disable Worker invocation
  logging.** The WebSocket userId now rides the `Sec-WebSocket-Protocol` subprotocol
  instead of a `?u=` query param (a legacy fallback remains during rollout), so it
  cannot land in edge request logs alongside IP, geolocation, and TLS fingerprint. It
  is still only a routing hint, gated by the existing challenge-response. Workers
  observability is also turned off in the Worker config, since a dashboard toggle
  would not survive a deploy. This reduces log retention, not what the edge can see:
  as the TLS terminator, Cloudflare still transiently observes IP and timing. (9c3e0ac)

### Added
- **Mutual invite: the inviter auto-learns joiners as unverified contacts.** A new
  directory operation lets an inviter's client learn, on reconnect (throttled) and
  while an invite panel is open, which ids redeemed its invites, and record each as
  an unverified (trust-on-first-use) contact so safety numbers can be compared
  without waiting for a first message. The joiner id is a relay assertion with no
  cryptographic binding, so these contacts stay unverified and must still be
  confirmed out of band. (2971e47)

## [1.2.0] - 2026-07-21

### Build
- **Cut idempotent GitHub Releases on version bumps.** After a successful deploy the
  workflow now creates a version tag and GitHub Release (skipping when VERSION is
  unchanged), attaching the reproducible-build manifest and cosign bundle as a
  human-readable pointer to the existing Rekor transparency record. (ce398db)

## [1.1.2] - 2026-07-21

### Added
- **On-device message history that persists across reloads.** Each message row is
  sealed with XChaCha20-Poly1305 under a key derived from a random history key and a
  fresh per-record salt, written in the same database transaction as the ratchet
  advance so an acked message is always durably saved. In this release the history
  key is stored unwrapped, so history is readable at rest (disclosed plainly in
  DESIGN); the at-rest encryption lands in the app-lock change below. (e465ee0)
- **Delete-for-everyone.** Deleting a still-queued message cancels the send outright;
  a delivered one sends an encrypted delete control (with its own fresh transport id)
  that removes the matching row and records a tombstone, so a copy arriving after its
  delete is suppressed. It is best-effort and depends on the peer running an honest
  client, so the UI says "delete sent", never "deleted for everyone". (d2e1667)
- **Session-only (ephemeral) messages.** A sticky per-conversation compose toggle
  flags a message so both the send and receive paths skip writing it to history (the
  persist gate fails closed), leaving it in RAM only until reload or lock. It is
  delivered identically to any other message and hides no metadata: it is
  off-the-record courtesy, not a security guarantee. (ae56dca)
- **Localized message timestamps and day separators.** A small localized time under
  each message and a centered Today/Yesterday/weekday/date separator when the day
  rolls over (display-only, in the viewer's locale). This also landed the structured
  in-ratchet message format that later enabled delete and ephemeral. (e949150)

### Security
- **Encrypt local history and the contact list at rest behind a mandatory
  app-lock.** A Local Data Key is generated in RAM and never stored unwrapped; it is
  wrapped under a passphrase, PIN (Argon2id), and/or biometric (WebAuthn PRF), gating
  an unlock screen before the app. History records seal their whole content under
  opaque storage keys, so the database reveals no peer, timestamp, or count at rest.
  Identity and ratchet session keys stay unencrypted so the app can still receive
  once unlocked, which means a device image can still decrypt future traffic and read
  the contact graph; this is disclosed in DESIGN. (9f9c527)

### Fixed
- **Fix long-message bubbles and group timestamps within a burst.** Message rows now
  span the full chat width with proper overflow wrapping, replacing a shrink-wrapped
  layout that collapsed long text to one word per line. Rapid same-sender messages
  within two minutes now show a single timestamp on the last line. (bde7d5e)
- **Verify works immediately after adding a contact, and deletes no longer notify the
  recipient.** Adding someone by code or QR now fetches their key and records a
  trust-on-first-use contact up front, so the safety number can be checked without
  first exchanging a message. Delete controls are sent with a silent flag so the relay
  still stores and delivers them but skips the push nudge (the operator can still see
  which sends are marked do-not-notify). (bae5edd)
- **Migrate pre-lock plaintext contact blobs to sealed storage on first
  enrollment.** A device that predated the app-lock stored contacts as plaintext,
  which the sealed-blob reader could not open. On first enrollment the store now
  detects a legacy plaintext blob, adopts it instead of crashing, and re-seals it (a
  genuinely corrupt or wrong-key blob still fails closed). (f3cd159)
- **Clear sealed contacts and aliases on a forgot-secret reset so the app restarts.**
  The reset previously cleared only history, leaving contact and alias blobs sealed
  under the discarded Local Data Key, so a re-enrolled lock could not open them and
  the app failed to start. The reset now erases those blobs too, and the screen copy
  says so (they are recoverable from a backup). (600621e)

### Build
- **Harden the CI VERSION step to strip a byte-order mark and validate the version.**
  The workflow now strips a leading UTF-8 BOM (which a Windows editor can bake into
  VERSION) and fails the build if the result is not a valid version, so the compiled
  app version matches the value the canary signs. (c3c32b7)

### Docs
- **License the project under Apache-2.0.** Adds the LICENSE file, sets the
  package.json license field, and documents the choice in the README. (b7537f0)

## [1.0.1] - 2026-07-20

### Added
- **Passphrase-encrypted identity backup and restore, and signed-prekey rotation.**
  Download-only backup of both private keys plus the contact-trust map, wrapped with
  Argon2id and XChaCha20-Poly1305 (the relay never sees the blob or the passphrase),
  with a crash-safe restore that forces fresh prekey publication, plus on-cadence
  signed-prekey rotation. Message history stays per-device and is never in a backup.
  This commit also gated the deploy pipeline behind the full test suites and pinned
  its actions by SHA. (2c96001)
- **Local per-device chat nicknames, and a compose bar that stays above the mobile
  keyboard.** Aliases are cosmetic and local-only: a chat can be named instead of
  shown by its 52-character id, while the real id and trust badge stay visible so
  verification is always by identity. The compose bar now tracks the on-screen
  keyboard instead of being hidden by it. (c11ed0b)

### Changed
- **Rework the app into a chat-first messenger, and add an in-app QR scanner.**
  Replaces the old control-panel layout with a conversation-list shell (with new-chat
  and settings sheets), and adds a camera QR scanner (native detector with a bundled
  fallback) for scanning non-secret invite and id data. (f2dc9b5)

### Build
- **Deploy on push to main, sourcing the version from a committed VERSION file.**
  Replaces the tag trigger with push-to-main plus manual dispatch, and derives the
  version from the VERSION file rather than the ref name so an unchanged redeploy
  stays byte-identical and the canary's attested hash holds without a re-sign.
  (e51aa0d)

## [1.0.0] - 2026-07-19

### Added
- **Initial public release: a browser E2EE messenger with Signal-style crypto and a
  reproducible-build transparency pipeline.** Keypair identity, an invite flow, X3DH
  key agreement and a Double Ratchet (over the audited @noble and @scure primitives)
  with known-answer crypto tests, safety numbers, a Cloudflare Worker relay, a
  Sigstore/Rekor release pipeline, and an in-app warrant canary. The README and DESIGN
  doc are candid that the operator serves the code and can see who talks to whom and
  when. (0962978)

### Build
- **Pin wrangler and run npm ci before deploy so the Worker bundle resolves.** The
  deploy action's default version predated the JSON-with-comments config format and
  failed to find the entry point; pinning it and adding an install step fixed the
  bundle resolution at deploy time. (a573313)
