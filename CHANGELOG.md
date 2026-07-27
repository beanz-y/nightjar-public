# Changelog

All notable changes to Nightjar are recorded here. This project cares about honest
disclosure, so each entry says what a change does and, where it matters, what it
does not do.

Entries cite the short commit hash so you can read the full diff (`git show <hash>`,
or the commit page on the repository host). The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/); version headings correspond to the
release tags cut by the deploy pipeline. Dates are the tag dates.

## [Unreleased]

## [1.8.0] - 2026-07-26

### Changed
- **Your conversations are now encrypted on this device, not just your messages.**
  Until now the app-lock covered your saved messages and your contacts, but not the
  encryption sessions themselves. Those sat in the clear, filed under each person's
  user id, which meant someone who took your phone while it was locked could read a
  list of everyone you talk to and when you last did, and could decrypt everything
  those conversations went on to say. Both are now sealed with the same key as
  everything else, and filed under a name that is derived from your secret, so the
  database identifies nobody. Your queued messages and your one-time keys are sealed
  too; the one-time keys were what let someone read a brand new conversation
  arriving for you.
- **What that does not fix, said plainly.** Your identity key is still stored in the
  clear, because the app has to work out what screen to show you before you have
  unlocked anything, and because encrypting it would turn a forgotten passphrase
  into losing your identity for good. So someone with your locked device can still
  pretend to be you to the relay: collect messages waiting for you, send messages
  your contacts' safety numbers will accept, and read new first contacts. Fixing
  that needs a recovery story first, and it is not in this release.
- **And it applies going forward, not backward.** Browsers give no way to erase what
  has already been written to disk, so on a device that ran an earlier version the
  old unencrypted copies may still be recoverable. Starting clean (export a backup,
  clear the site's data or reinstall, then restore) is the only way to be rid of
  them, and it costs every conversation you currently have open.
- **Resetting a forgotten passphrase now costs more, and says so.** It used to erase
  your saved messages and contacts and leave your conversations working. Everything
  is encrypted with that secret now, so a reset ends every conversation as well. You
  keep your identity, so you are still the same person to everyone who knows you,
  but you have to message each contact again before they can reach you. The
  confirmation says this before you type ERASE.

### Fixed
- **The lock screen could show a contact's id.** A security warning is deliberately
  sticky, and it was being drawn above the unlock screen, so a device someone had
  just picked up could display part of a contact's identifier without their ever
  entering the secret. Those warnings now wait until you are in.
- **Changing your passphrase while the app locked could have destroyed the key.**
  The change takes a few seconds, and the automatic lock could land in the middle of
  it. It now completes correctly regardless.
- **Corrected the retention figure in the design notes**, which said the local
  duplicate-message list was cleared after 8 days. It is 30, matching how long the
  relay will keep retrying an undelivered message, and it has to be.

## [1.7.0] - 2026-07-26

### Added
- **Delete a conversation.** Two options on any chat. "Clear messages" removes the
  saved messages and keeps everything else. "Delete from this device" also removes
  the contact, any verification, the name you gave them, and anything still queued
  to send.
- **A deleted contact can still reach you, on purpose.** Deleting keeps the
  encryption session, and that is a deliberate choice rather than something we
  forgot. If it were removed, their app would carry on sending on the session it
  still holds, those messages would arrive here unreadable and be discarded, and
  their app would still show them as delivered. That lies to both people at once:
  someone who deleted a chat to tidy up would stop receiving that person for good
  with nothing on screen to say so, while the sender watched every message turn to a
  delivered tick. Deleting is a filing decision and must not quietly become a
  one-way mute. It is also not a block, and Nightjar does not have one; that gap is
  real and we would rather name it than have a delete pretend to fill it. So their
  messages still arrive and reopen the chat, with no name and no verification. The
  honest cost, which the confirmation states: the kept session still names them on
  this device.
- The confirmation says the rest before you act too: it is local, it does not touch
  their copy, they are not told, and it discards any in-person verification.
- **A deleted contact stays deleted, until they actually reach you.** The mutual
  invite re-learns anyone who redeemed one of your invites on every connection, so
  without this a deleted contact reappeared within about a minute, for up to a
  month. Deleted peers now go in a short-lived local list that only the automatic
  paths consult. A message that genuinely arrives from that person, or adding them
  back yourself, records them again as a plain unverified contact and clears the
  list entry. That last part matters more than it sounds: without a stored key there
  is no safety number, so a conversation you were actively having would have had the
  most important check in the app quietly unavailable.

### Fixed
- **The list of deleted contacts could erase itself.** Its housekeeping pass treated
  "could not read the list" the same as "the list is empty" and deleted it, which
  would have let every deleted contact reappear through the mutual invite. Only a
  successful read can now clear it.
- **A re-established conversation no longer gives up a one-time prekey it did not
  need to.** The safeguard that avoids reusing a prekey the other side has already
  consumed now applies only where that is actually true, rather than to anyone
  deleted in the past month.

## [1.6.1] - 2026-07-25

### Fixed
- **Corrected two claims the app was making that it could not support.** An
  adversarial review of the 1.6.0 release found them, and both were on the parts
  that matter most. First, a message with no delivery information was showing a dot
  reading "still on this device, waiting to be sent". That was false for every
  message sent before the feature existed and for every session-only message, both
  of which had in fact gone out. An unknown state now shows nothing, which is what
  the design said all along. Second, a successful code scan on the verify screen
  said the code "was displayed by their device". It cannot know that: the code is
  built from public keys, so a forwarded photo, or anyone holding both public keys,
  produces the same result. It now says what the check actually shows, and the
  documentation says the same.
- **The delivery tooltips now name the relay** as the source of both states, and no
  longer claim "their device has not picked it up yet" when the truth is only that
  the relay has not said so.
- **The scan option is offered for already-verified contacts**, which the screen was
  telling people to do while hiding the button. After a scan that did not check out,
  the confirmation no longer asks you to agree that "every digit matched".
- **Restored the "Metadata" heading in DESIGN.md**, which the 1.6.0 edit removed by
  accident, leaving the whole leak list buried inside the delivery-indicator section
  and five cross-references pointing at nothing. Also fixed the non-goals list,
  where a "5a." entry silently collapsed four items into one paragraph.
- **The delivery catch-up no longer rescans all history on every reconnect**, and
  picks the most recent messages to ask about rather than an arbitrary hash-ordered
  subset, so past the first 64 a message could previously never be confirmed.
- **A delivery update can no longer erase a "not sent" marker** written concurrently.
- **The verify screen no longer recomputes the safety number on every keystroke**
  (it is thousands of hash rounds, and it was running twice per render).

### Changed
- **The app now reaches the edges of your screen.** Everything sat inside a fixed
  inset, so on a phone the compose bar, the header rules and the message list all
  stopped short of the edge and the app read as a page floating in a box. The shell
  is full width now, and each bar places its own content; the centred column
  remains only on a wide desktop window, where it is actually wanted.
- **The message field got its width back.** The session-only control was a wide
  text chip taking about a third of the compose row. It is now a compact toggle,
  and when it is armed a labelled strip appears above the bar saying, in words,
  that the message will not be saved and can still be screenshotted. That is a
  stronger warning than the chip it replaced, not a quieter one.
- **A conversation gets the whole screen on a phone.** The app title bar is list
  chrome, so it steps aside when you open a chat. The connection state it carried
  is not lost: a conversation now says "offline" in its header when the relay
  connection is down, which is the part worth interrupting for.
- **The conversation header reads as a person, not a key.** The full user id used
  to wrap onto two monospace lines and dominate the header. It is now one quiet
  line that expands in place when tapped, with the name, trust badge and verify
  button on one aligned row. The id stays visible and one tap from full, because
  verification is always by identity and never by the nickname you set.
- **Messages sit at the bottom** of the conversation like every other messenger,
  instead of floating at the top, and a bubble now stops at about three quarters of
  the row so who said what reads instantly from shape alone.
- **Smaller things**: the canary warning is a compact row instead of three lines
  (it stays visible, it is a security notice), and the message box no longer shows
  a permanent scrollbar when it holds a single line.

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
