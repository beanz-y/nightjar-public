# Changelog

All notable changes to Nightjar are recorded here. This project cares about honest
disclosure, so each entry says what a change does and, where it matters, what it
does not do.

Entries cite the short commit hash so you can read the full diff (`git show <hash>`,
or the commit page on the repository host). The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/); version headings correspond to the
release tags cut by the deploy pipeline. Dates are the tag dates.

## [1.13.1] - 2026-08-03

### Fixed
- **Reading a code no longer freezes the thread that is trying to read it.** On browsers
  with no camera decoder of their own, which is every Firefox and Chrome on Windows, the
  bundled decoder ran on the same thread as the app and the camera. It is a lot of
  straight-line work per look, so the scanner managed only a handful of looks a second,
  which is survivable for a printed code sitting still and hopeless for one that changes
  several times a second. It now runs in a worker, and a look that is still in progress
  makes the next frame skip rather than queue, so the loop keeps pace with the camera
  instead of falling further behind it. The frame is handed over rather than copied, and
  a browser without workers still scans the old way rather than not at all.
- **Password managers can save and fill your app-lock again.** None of the secret fields
  said what they were, so a vault often would not offer to save the passphrase at all,
  which quietly pushes people toward something they can keep in their head. Since the
  strength of that secret is the only thing between an imaged device and everything on
  it, that was the wrong nudge. The app-lock, backup and restore fields now identify
  themselves properly.

## [1.13.0] - 2026-08-03

### Added
- **Carry your saved messages to a device you have added.** A device you add starts with
  none of them, deliberately, because nothing could backfill it without the relay holding
  your history. This is the separate, deliberate act that hands them across afterwards,
  and it happens entirely on screen: the device that wants the messages shows a code, the
  device that has them photographs it, and then shows a moving code back. None of it goes
  over the network, and there is no fallback that would. That is a choice: the bytes
  would be sealed either way, but this can be everything you have ever kept in one go,
  and asking the relay to carry that, even sealed, is a different promise from the one
  made about what it ever holds.
- **You choose how much to send, on real numbers.** Everything, or the last 90, 30 or 7
  days, each shown with how many messages it is, how large, and roughly how long it will
  take to hand over. Beyond a certain size it says so and asks for a shorter span rather
  than starting something that will not finish, and it refuses over that limit rather
  than quietly truncating: a cut-off history arrives looking complete, with an arbitrary
  piece missing from the middle of a conversation and nothing on either device to say so.
- Four things it will not do, all of them deliberate. It will not send to a device that
  is not on your account, because a code proves somebody photographed a screen and not
  whose screen it was. It will not accept messages belonging to a different account, for
  the mirror of that reason. It will not bring back a message you had already deleted on
  the receiving device, because the sending one may never have heard about that delete.
  And it leaves out messages from people the receiving device does not hold as contacts,
  since it would have no key for them and so no safety number to check them against.
- Running it twice is safe and changes nothing, which is what makes it safe to retry one
  that did not finish. Messages already on the receiving device are kept: this adds to
  what is there rather than replacing it.

### Changed
- **Saying plainly that this is a copy and not a sync** (DESIGN 8.12). The two devices
  agree about the past at the moment you do it, and nothing keeps them aligned
  afterwards; messages from before you added a device still exist only where they
  arrived.

## [1.12.2] - 2026-08-03

### Fixed
- **The moving code could not be read by an ordinary laptop webcam, and nothing said
  so.** It was drawn as the densest code the format allows, 177 squares across, on the
  assumption that this is always a phone held close to a screen. A webcam left to choose
  its own settings usually runs at 640x480, which is not enough pixels to resolve squares
  that small, so it read nothing at all, forever, while showing exactly what it shows
  when you simply have not aimed it properly. The code is now a third of that density
  and is drawn much larger, which together make each square about two and a half times
  the size it was, and the camera is now asked for the highest resolution it has. It
  takes a few more codes to send the same thing, which costs a fraction of a second and
  is worth it. Nothing needs to agree on this: each code says how much it carries, so a
  device on the previous version still works in both directions.
- **The receiving screen now shows what is happening.** There is a progress bar, and it
  distinguishes the three situations that previously looked identical: not reading any
  code at all, reading codes that are not a transfer, and receiving one. It also shows
  how many codes it has read and what resolution the camera actually gave, because when
  this goes wrong that is the number that explains it, and says so directly if the
  camera is too low-resolution to have a chance.
- **The sending screen now shows it is still running**, by counting the codes it has
  shown. There is no acknowledgement of any kind from the other device, by design, so
  without that counter there was nothing to tell a transfer in progress from a page that
  had stopped.
- **The scanner was doing so much work per look that it barely got to look.** It examined
  every pixel of a full-resolution frame, which on a 1080p camera is two million of them
  on the main thread, so it managed only a few attempts a second. That is fatal for
  reading a code that CHANGES several times a second rather than a printed one that sits
  still: it both looked rarely and was disproportionately likely to catch the moment a
  code was being replaced, which reads as nothing at all. It now examines only the
  centre square, which is the part the preview actually shows, at a capped size. It also
  asks the browser's own decoder first and then still tries its own when that sees
  nothing, since the two fail on different marginal frames.
- **The codes are shown more slowly, and it no longer asks you to hold still.** Each code
  now lasts about a sixth of a second rather than a tenth, so more of a hand-held
  camera's exposures land on a whole one. Slowing down costs almost nothing, because
  missed parts simply come round again, which is what the fountain coding is for. There
  is also more white space around the code, so clipping its edge no longer ruins a read.
- **It now says what to try when nothing is being read**, including the counterintuitive
  part: move the devices FURTHER apart, not closer. Most laptop cameras have a fixed
  focus set for a face at arm's length and cannot focus on something held right up to
  them, so a code that fills the view can be too blurred to read while a smaller, sharper
  one is fine. The diagnostic line now also reports how many times a second the scanner
  is managing to look.

## [1.12.1] - 2026-08-03

### Fixed
- **Starting a device over was effectively unreachable.** A device that already has its
  own Nightjar account cannot join another one, so turning an existing device into a
  second device of an account means erasing it first. That erase existed, but the only
  way to it was to download a move file, so repurposing a device meant exporting a file
  you did not want just to reach the button. It now also sits under Settings, Your
  devices, behind the same typed confirmation, and says plainly what it costs: the
  device stops being the account it is now, everyone holding that id can no longer
  reach it, and nothing is recoverable afterwards.
- **Joining an account from a device that already has one is now refused.** Linking
  deliberately keeps what a device holds rather than replacing it, because adding a
  device is not the same as moving to one. Doing it from a device that was already
  somebody would leave a single device holding two accounts: the old account's saved
  messages and live conversations filed under the new account's identity, with the old
  contact list replaced out from under them. Nothing in the app offered this, but it is
  now refused outright rather than merely unreachable.
- **Erasing a device now stops its other open tabs first.** A second tab of the same
  device kept running with the key still in memory, kept its connection open, and wrote
  contacts and conversations straight back into what had just been erased. The device
  then came back looking untouched, which read as it restoring a backup from nowhere.
- **An erase that does not finish now says so.** Every step was previously allowed to
  fail silently and the app reloaded regardless, so a device whose identity would not
  delete came back as itself, reconnected, and pulled its contacts down again, with
  nothing on screen to say the erase had not worked. A failure is now reported after the
  reload, naming what could not be removed. A successful erase also clears this device's
  saved preferences, which were being left behind.

## [1.12.0] - 2026-08-03

### Added
- **Your account and your device are now two different things, and your first device is
  both.** An account is you: it is what a conversation is filed under, and what a safety
  number covers. A device is one of the things you read Nightjar on: it is what the
  server authenticates, and what a conversation's encryption actually runs between. On
  your first device these are the same key, on purpose, and that is what lets extra
  devices arrive without disturbing anything: your id, your inbox, your conversations
  and above all your safety numbers stay exactly as they are, and nobody has to verify
  anybody again. The honest cost, in DESIGN 3.1: a first device cannot be removed from
  its own account, because it IS the account. Retiring it means moving to a new device,
  or changing your account key, which asks every contact to verify you again.
- **The app can now be told where someone's devices are, and decide whether to believe
  it.** A device list is used only if it is signed by that person's account key AND is
  newer than the last one this app accepted for them. An old list served again is
  refused, which matters because that is how a server would hide a device someone
  removed: the signature on it is perfectly genuine, and only your app's memory can
  catch it. Anything refused leaves the devices you already knew about in place, since
  failing to deliver would be the worse outcome. Any change to someone's devices raises
  an alert, because the server cannot cause one: a new device on someone's account is
  either a device they really added, or something that already holds their account key,
  and only they can tell you which.
- **Add this device to an account you already use.** On a new device, choose it during
  setup instead of entering an invite: it shows a code, you point your existing device
  at that code, and your existing device hands over what the new one needs. It consumes
  no invite, because being on your account's signed list is what authorizes it.
- **The handover happens on screen, not over the network.** The code carries a
  single-use secret, so the transfer is sealed under something the server has never
  seen, and by default it travels as a moving code from one screen to the other camera,
  so the server carries no part of it at all. If one of the devices has no camera there
  is a fallback that sends it over the relay instead: still sealed under the scanned
  code, delivered only while both devices are open, and never stored. What neither
  option hides is that it HAPPENED, because adding the device publishes a list and the
  new device registers itself. The payload is private; the event is not.
- **Messages now go to every device someone reads on.** One message becomes one
  delivery per device, each separately encrypted, and your own other devices get a copy
  of what you send so a conversation reads the same wherever you open it. For anyone
  who has not added a device, which is everyone until they do, this is byte for byte
  the single delivery it always was.
- **Messages from people running an older app still reach all your devices.** Their app
  addresses one device and always will, so a message that arrives without a claim that
  it went everywhere is passed on by the device that got it. Session-only messages are
  never passed on, deliberately: they are the one kind that promises to be written down
  nowhere, and a forward would sit in a queue until it was delivered.
- **Deleting reaches everywhere too**, in both directions: deleting a message you sent
  removes it from your other devices as well as asking theirs, and a delete you receive
  is passed to your other devices the same way a message is.
- **A devices screen, in Settings.** See what can read your messages, add another, or
  remove one. Removing is described for what it is and not oversold: others stop
  sending to that device, and it keeps everything it already had. It is not a way to
  take anything back, and for a device that is LOST rather than finished with, the
  honest position is that your account is compromised.

### Changed
- **"Delivered" now means at least one of their devices picked it up**, when someone
  reads on more than one. It is not a count and it does not say which device, on
  purpose: reporting where somebody reads their messages is exactly the kind of fact
  this indicator exists not to leak.
- **Asking a contact to resend messages you could not read is bounded per PERSON, and
  answered to the DEVICE that asked.** Both halves matter: bounding per person is what
  stops somebody reading on three devices pulling three times the limit, and that limit
  is what caps what a stolen identity is worth; answering the asking device is what
  gets the messages to the one that could not read them.

### What this deliberately does not do
- **A device you add starts empty.** Nothing you have already received moves to it.
  Messages sent and received from then on reach both.
- **Verification never syncs.** A new device shows every contact as unverified until
  you compare safety numbers on THAT device. Nothing remote can mark a contact
  verified, not even another of your own devices, and that is the point. Be clear about
  what re-checking buys: the digits are identical on both devices, so it is performing
  the ritual again rather than new proof. What it produces is a record on that device
  that nothing remote can forge.
- **Your safety numbers do not change when you add a device**, because they cover your
  account rather than each machine. A contact who verified you stays verified with no
  scary banner, which is what makes this usable. The same fact read the other way is
  the uncomfortable one, and DESIGN 1.3 and 6.2 now say it plainly: a device of yours
  that somebody else got hold of would still show your contacts matching digits. The
  signal for that is the alert when someone's devices change, not the safety number.
- **An app just restored from a backup, or moved to a new device, starts with no memory
  of anyone's device lists**, so until it builds that memory up it has nothing to refuse
  an out-of-date list against.
- **More devices means more one-time keys used**, so a device left on an account and
  never removed is a small permanent cost on every message sent to you.

## [1.11.0] - 2026-08-03

### Added
- **Groundwork for using Nightjar on more than one device.** An account can now have
  a signed list of its own devices, and the server can store one and hand it out, so
  that whoever writes to you can reach every device you read on. Nothing publishes such
  a list yet and nothing behaves differently: an account with no list reads as the
  single device it already is, which is also how an account that never adds a second
  device will keep reading. What landed is the format, the signature rules, and the
  server side that refuses anything an account did not sign.
- The parts that were worth getting right before anything depends on them, in DESIGN
  7.5 and 9: the server can store a device list but can never write one, because it
  holds no keys and checks every list against the identity key already registered for
  that account. Its refusal to accept an older list only keeps an honest server honest;
  what actually protects you is that your app remembers the newest list it has seen for
  each contact and will not go backwards. The list holds no device names, because
  anyone who might message you has to be able to read it, so naming a device would
  publish that name. It does tell the server how many devices you have and when each
  was added, which cannot be avoided if people are to reach them.

### Fixed
- **The list of contacts a moved device still needs to reach was stored unencrypted.**
  After moving to a new device, the app keeps a short list of the contacts it still
  owes a session-refresh ping, so a crash before the first connect cannot lose it. That
  list was written beside the identity in plain text rather than with the rest of your
  contact data, so a freshly moved device held a readable list of everyone you had
  just imported until it finished draining. It is now encrypted like every other
  contact blob, which makes DESIGN 8.5's statement that nothing stored names a contact
  true again. A list left over in the clear by an earlier version is picked up and
  re-encrypted the first time it is read, so no pending pings are lost.

## [1.10.0] - 2026-08-03

### Added
- **Messages lost to a moved or restored device are now asked for again.** There was
  one way Nightjar could lose a message and show it as delivered to the person who
  sent it: when your device no longer held the conversation their device was still
  using, everything they sent was unreadable here and quietly given up on, while the
  relay told them it arrived. A device that cannot read a message now asks that
  contact's device to re-establish and send its recent messages again, and their
  device answers on its own. Nothing needs to be tapped, and a contact running an
  older build simply ignores the request instead of breaking.
- The honest parts, said plainly in the app and in DESIGN 8.10: the ask can only ever
  mean "resend recent", never "resend that one message", because a device that could
  not read something never learned what it was; at most 50 messages from the last 48
  hours ever come back, so anything older stays lost; and your device tells you every
  time it resends messages for someone, including who asked.
- **What this changes if someone steals your identity** (a leaked backup and its
  passphrase, or a move file that was not theirs), now written into the threat model
  in DESIGN 1.3: as well as reading what you are sent next, they can ask each of your
  contacts to resend, and those devices answer without yours involved. The 48-hour
  window is the cap on that, and the notice on your contact's device is the only sign
  it happened, which is why it is never silent.

### Changed
- After a move, the notice about a message that could not be read no longer tells you
  to ask the person to resend it, because the app now does that itself.

## [1.9.0] - 2026-08-02

### Added
- **Move to a new device.** A new option in settings makes one encrypted file that
  carries everything this device knows to a new one: your identity, your contacts and
  who you verified, your nicknames, your deleted-conversation markers, and every saved
  message. On the new device you restore that file instead of an identity backup. The
  passphrase is generated for you and shown once, because the file holds every message
  you have saved and is typed only once; write it down, send it separately from the
  file, and do not photograph it. When the new device is working, the old one offers to
  erase itself.
- The honest parts, said plainly in the app and in DESIGN 8.3: a move is a copy, not a
  sync (the two devices never reconcile afterward); until you message each contact from
  the new device, anything they send is lost while their app shows delivered; a message
  still waiting to send when you move is never sent, so the export refuses while any is
  queued; nothing can disable the old device remotely, which is why the erase step
  exists; and a move file you did not make yourself can contain messages that were never
  sent, so only ever import your own.

### Fixed
- **Restoring a backup during onboarding no longer dead-ends.** A brand-new device
  enrolls its app-lock before onboarding, and choosing "restore" then tried to enroll a
  second time and failed. Restore now unlocks the existing lock and finishes, on every
  entry point (onboarding, a returning evicted device, or a retry after an interrupted
  restore).
- **A restored or moved device can no longer be handed a one-time prekey a contact
  already used.** The directory's anti-depletion cache re-served the same prekey to a
  repeat fetcher; after a restore that could silently break the first new conversation
  with a recently-contacted person in both directions. Re-registration now clears that
  device's fetch history server-side.
- **A crash midway through a restore can no longer attach the backup's data to the
  wrong identity.** Staging now removes any existing identity first, so a loadable
  identity exists only once the restore has fully landed; an interrupted restore returns
  to the restore screen and re-runs cleanly.

## [1.8.3] - 2026-08-02

### Fixed
- **Closed an accidental second way to deploy.** The host's own git-build integration
  had been connected alongside the release pipeline. It builds outside the pinned
  container and produces no release hash, no signature and no transparency-log entry,
  so a deploy through it would have served code the verification chain never saw while
  the app carried on attesting the previous build's hash. It is disconnected, and the
  release job now refuses to run except on a push to the main branch, by a person
  rather than a bot, after an approval. Pull requests are built and tested but can
  never deploy. The public hostname is also now declared in the deploy config instead
  of living only in dashboard settings, because the same incident removed it.
- **The deploy now uses the project's own pinned tooling.** It previously asked a
  third-party action to fetch its own copy of the deploy tool at a hardcoded version,
  which drifted from the one in the lockfile and broke the release outright. There is
  now one version instead of two, taken from the same audited lockfile that built and
  hashed the release, and one less third party holding the deployment credential.

### Changed
- **The cryptography libraries moved to their v2 line.** `@noble/curves`, `@noble/hashes`,
  `@noble/ciphers` and `@scure/base` go from 1.x to 2.2.0, each carrying a spring 2026
  upstream self-audit plus TypeScript and tree-shaking fixes. The only change the new
  line demands of this codebase is explicit `.js` module paths in imports. The proof it
  changes nothing on the wire: every pinned known-answer test passes unchanged (user ids,
  safety numbers, X3DH secrets, ratchet message bytes, sealed history and backups), and
  those tests exist precisely so that a primitive drifting by a single byte fails loudly
  instead of silently stranding every existing session.
- **The reproducible-build container moved from Node 22.16.0 to 22.23.2**, staying inside
  the pinned LTS line, with the image digest re-pinned and `.nvmrc` moved in the same
  commit so the container, the CI runners and local dev keep agreeing on one Node.
- **Cleared every open dependency advisory** (one critical, six high, three moderate),
  by moving the test tooling forward: Vitest 2 to 4, the Cloudflare Workers test pool
  0.8 to 0.20, and Wrangler with its types alongside. All of them were in the test and
  build tooling, none in anything users run, so the shipped code was never affected. They
  were worth clearing anyway: a Security tab that is permanently red is one nobody reads
  on the day it matters.
- The upgrade is **provably invisible in the released app**. Every one of the seven
  production dependencies is byte-identical (same version, same integrity hash), and the
  release hash of the built artifact is unchanged, so this needs no canary re-sign. The
  hash was recorded before the upgrade and compared after, rather than assumed.
- Vitest 4 reworked how test pools are wired, so the Workers integration is now a Vite
  plugin instead of a config wrapper, and the app project asks for Node types explicitly
  where Vitest 2 used to supply them by accident. Neither changes what is tested.

### Added
- **A private way to report a security problem.** [SECURITY.md](SECURITY.md) documents
  GitHub Private Vulnerability Reporting as the preferred route, with `admin@nightjar.chat`
  as a fallback. Until now someone who found a flaw had no way to say so privately, and
  their only options were a public issue that tells attackers before there is a fix, a
  guessed address, or nothing. It states plainly that there is no bounty, and lists what
  is already disclosed so nobody spends an evening on a documented design decision.
  Reports about the documentation are explicitly welcome: for this project a claim the
  code cannot support is a real issue.
- **Alerting for the dependencies we ship.** A `dependabot.yml` for weekly grouped
  updates, including the SHA-pinned release workflow actions and the digest-pinned build
  container, neither of which moves on its own. That pinning is what makes a rebuild
  byte-identical, and the price of it is that a Node or Debian fix never arrives unless
  a person bumps the pin, with nothing to remind them. Now something does. The release gate now runs `npm audit --omit=dev --audit-level=high`, so a known
  critical or high advisory against something that reaches users stops a deploy rather
  than waiting in an inbox. Dev-only findings do not fail the build, because a gate that
  cries wolf gets ignored on the week it matters.
- **DESIGN section 10.7** on what this can and cannot catch. Automation covers
  dependencies; it will never report a break in a cryptographic primitive we implement
  ourselves, and the document says so rather than implying coverage that does not exist.

The repository and process changes here shipped byte-identical builds when they first
landed. The library and container upgrades do change the built app, so this release
carries a new release hash and the warrant canary is re-signed for it.

## [1.8.2] - 2026-07-26

### Added
- **The message box now tells you when you are running out of room.** There is a
  limit of 8,000 characters, which is a chapter rather than a message, so almost
  nobody will ever see this. Previously the only way to find out was to write the
  whole thing, press send, and be turned down with the text still sitting there.
  A count now appears for the last 800 characters, and once you are over the limit
  it says by how much and the send button is disabled, so the message cannot reach a
  dead end.

The count and the check that lets you send are built from the same number, so they
cannot disagree. It counts the way the limit is actually measured, which means an
emoji usually costs two: the honest figure rather than the flattering one, since the
flattering one would let a send be refused with room apparently to spare.

## [1.8.1] - 2026-07-26

### Added
- **The app-lock screen now says what your passphrase or PIN has to be**, instead of
  letting you find out by being turned down. The requirements are listed under the
  box and tick off as you meet them. A tester asked for this.
- It also says what is *not* required, since that is the part people guess at: any
  characters, any length above the minimum, no mandatory symbols or digits. Capitals
  matter, and spaces at the start or end are ignored, which is worth knowing before
  you have to type it again tomorrow.

The list and the check that lets you continue are now built from the same rules, so
they cannot disagree about what is allowed.

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
