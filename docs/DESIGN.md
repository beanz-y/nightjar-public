# Nightjar: Protocol and Architecture

A private, invite-only, end-to-end encrypted messenger for friends and family.
Self-sovereign keypair identity, no phone numbers, no third-party sign-in.
Delivered as a universal Progressive Web App, honestly and openly hardened.

Status: **built and live** through P8 (design at **v0.5**). The protocol,
architecture, and hardening here were reviewed and attacked before any
cryptographic code was written; the roadmap in section 12 tracks what has shipped.

**Changelog.**
- **v0.5** is the pre-release pass alongside P8. It adds passphrase-wrapped
  identity **backup and restore** (8.3, download-only in v1, Argon2id parameters
  pinned in 14); documents the automatic **signed-prekey rotation** the client
  now performs on connect (4.1), and the **skipped-key time expiry** (5.3, 14)
  that completes the retry invariant chain; describes the multi-session
  **session book** in the body (6.4) that section 14 already referenced; corrects
  the deploy model to **push-to-main + digest-pinned container + Rekor**, with no
  SSH-signed tag (10.1/10.3); and records the client-side retention bounds (14).
  A full adversarial review of the *implementation* (P9) accompanies it.
- **v0.2** folded in a four-lens adversarial review of the protocol (signing
  oracle, send-path key reuse, mutate-before-verify DoS, OPK replay/depletion,
  half-earned "verified" badge, the web-client host-trust gap). All critical and
  high findings resolved; constants pinned in section 14.
- **v0.3** settles the delivery question. After researching native/installable
  packaging (Tauri) versus a hardened PWA, the decision is **PWA-first and
  universal**, with a documented, honestly-disclosed hardening stack (section
  10) and native as an optional, demand-gated v2. The research surfaced a more
  important point that reorders our priorities: **the operator is the key
  directory, so out-of-band safety-number verification (section 6) is the single
  highest-value security control, ahead of any code-delivery mitigation.** That
  reprioritization is now reflected in the goals, the trust section, the roadmap,
  and the honesty section.
- **v0.4** is a measure-twice consistency and honesty pass before P0. It resolves
  a self-contradiction (a verified contact is safe from a malicious server *only
  if the client code is also honest*, because bad code defeats verification),
  tightens the hardening claims ("broad" now means non-selective, and
  vantage-selective edge serving defeats even broad detection; "loud" downgraded
  to "publicly falsifiable, and only under active monitoring"), pins the invite
  fingerprint to full width, fixes the nonce description (unique-by-construction,
  not "random"), makes `@noble` the sole X25519 provider for P0, and hardens the
  plain-language disclosure. No protocol or roadmap change.

> Guiding principle: **the crypto core is boring and borrowed, the product is
> ours.** Every primitive, and each sub-protocol (X3DH, Double Ratchet), is from a
> published, peer-reviewed spec on audited primitives. The *composition* (how the
> sub-protocols, push, storage, auth, and the trust model are glued together) is
> ours, and per section 13.13 it is the part most in need of review. We innovate
> on the trust model and the product, never the mathematics. And we state every
> limitation plainly: an honest tool that says what it cannot do is worth more
> than one that quietly overpromises.

---

## 1. What Nightjar is and is not

### 1.1 Goals (with the caveats that make the promises true)

1. **Content confidentiality, for verified contacts.** A message body is
   readable only by the intended recipient's device, and unreadable to us, to
   Cloudflare, to the ISP, and to any network observer, **provided** (a) the two
   parties verified each other out of band (section 6), and (b) the client code
   they run is honest (sections 1.4 and 10). For an unverified contact, a
   malicious or compelled server can substitute the contact's identity key in the
   bundle it serves and read content (section 6.1). This conditionality is stated
   everywhere the promise appears; it is not fine print.
2. **Forward secrecy, for processed messages.** Compromising a device's current
   *ratchet* keys (or capturing the ciphertext in transit and later stealing those
   keys) does not expose past delivered-and-processed messages: each is encrypted
   under a message key deleted after use. The one exception is a bounded set of
   skipped message keys retained transiently for out-of-order delivery (section
   5.3). This is a property of the *protocol keys*, not of local storage: the
   device now **retains past messages in at-rest history**, encrypted behind the
   mandatory app-lock (section 8.5), so a forensic image is a separate exposure
   bounded by the unlock secret's strength, which forward secrecy does not address
   (section 1.3).
3. **Post-compromise security, against a later-passive attacker.** After a
   *ratchet/session-key* compromise, the conversation recovers once one
   uncompromised DH round-trip occurs. This does not heal compromise of the
   long-term identity key, a persistently active attacker, or a bad RNG.
4. **Authenticity you can verify in person.** A recipient can be sure a message
   came from the claimed identity key, and can confirm that key belongs to the
   real person via an out-of-band safety-number check (section 6). Once verified,
   a malicious server *limited to key or bundle substitution* can no longer
   impersonate that contact or MITM the conversation. A malicious operator who
   also serves dishonest client code can still defeat verification (section 6.1),
   so this guarantee, like Goal 1, is conditional on honest client code.
   **This check is the linchpin of the whole system** (section 6.1).
5. **No third-party identity leak at registration.** No email, no phone number,
   no Google/Apple account; your identity is a keypair generated on your device.
   Honest limit: Cloudflare, your ISP, and the push provider still observe that
   your device talks to Nightjar and when (section 9). We hide *who you are* from
   third parties at signup; we do not hide *that you use the app* from the
   networks carrying the packets.

### 1.2 Non-goals for v1 (stated honestly, so "hyper secure" stays truthful)

1. **Metadata privacy against our own server** (who sends to whom, and when).
   Minimized (section 9), not eliminated.
2. **Multi-device.** One device per identity in v1 (Sesame deferred).
3. **Large groups.** 1:1 only; small pairwise-fan-out groups are a v2 target.
4. **Post-quantum.** Classical X25519 in v1, downgrade-protected (section 4.4) so
   a v2 PQXDH upgrade cannot be silently stripped.
5. **Anonymity / sealed sender / cover traffic.**
6. **Forward-secret synced history and cloud backup.** History is persisted on
   your device (section 8.5) but is per-device: it is not synced, and the identity
   backup (section 8.3) does not carry it, so it does not transfer to a new device.
7. **Endpoint security.** A compromised device is outside the guarantees.
8. **A trustless web client.** A PWA cannot prove to the user that the code it
   runs is honest (section 1.4). We do not pretend otherwise; we harden it,
   disclose it, and make a non-selective broad attack publicly falsifiable
   (section 10).

### 1.3 Threat model summary

"Verified" = the two parties completed the out-of-band safety-number check
(section 6). "TOFU" = they have not.

| Adversary | Read message content? | See that/when you message? | Suppress or delay delivery? |
|---|---|---|---|
| ISP / Wi-Fi snoop / network tap | No (TLS + E2EE) | Sees encrypted traffic to our host; a VPN or Tor narrows this | Can block the network, not selectively censor |
| Cloudflare (our host) | No | Yes (routes connections) | Yes |
| Us, operating honestly | No | Could log metadata; we choose not to, code is open | We could, we do not |
| Us, malicious or court-compelled | **Content: No, but only if the contact is verified AND the client code is honest.** For a TOFU contact we can substitute the directory identity key at setup and read content (6.1). Even for a verified contact, serving dishonest client code (1.4) defeats verification (6.1). | Yes (metadata) | Yes: silently drop, delay, reorder, suppress, or withhold bundles. Cannot forge a verified contact's content without shipping modified client code (1.4). |
| Thief of our server / subpoena at rest | No stored plaintext; only undelivered ciphertext (30-day TTL, 7.1) and any opt-in server-stored identity backups, which reduce to passphrase strength (8.3) | Transient routing state only | n/a |
| Global passive network adversary | No (content) | Yes (out of scope for any practical messenger) | n/a |
| Thief of your unlocked device | Yes (it is your device) | Yes | n/a |
| Thief / forensic image of your at-rest (locked or powered-off) device | **Message history and the contact list are encrypted at rest** behind the mandatory app-lock (section 8.5); reading them reduces to the unlock secret's strength (strong for a passphrase/biometric, **weak for a short PIN** against an offline brute-force of the image). BUT the identity and ratchet **session keys stay unencrypted** (needed to run after unlock), so an image can still decrypt *future* traffic once the device is used again. | No (contact list is encrypted; but future-traffic decryption can rebuild it) | n/a |

Honest one-sentence version: **Nightjar makes the content of your conversations
unreadable to everyone but the people in them, once those people have verified
each other and are running honest client code; it does not hide that you are
talking from a determined operator or the networks carrying your packets, and it
cannot force a hostile relay to deliver your messages.**

### 1.4 The web-client trust problem, and why a hardened PWA is still the right v1

Nightjar's client is a PWA whose JavaScript is served from the same
infrastructure the threat model treats as untrusted. **This is a real, permanent
limitation, and no 2026 web mechanism closes it.** We choose the PWA anyway, with
open eyes, for reasons set out below.

**The ceiling (stated crisply).** The origin is the trust root. TLS authenticates
the host, not its honesty. Every verifier you could put *inside* a PWA (the
loader, the service worker, a stored-hash check) is itself fetched from the same
origin as the thing it verifies, so whoever can change the bundle changes the
checker in the same response. Landau's formulation is the one to keep in mind: *a
cryptosystem is incoherent if its implementation is distributed by the same
entity it purports to secure against.* Corollaries we do not fool ourselves over:
Subresource Integrity cannot protect the entry-point HTML (the operator rewrites
the integrity attributes); service-worker "install once" pinning is circular by
design and the platform deliberately engineers against it (the SW script is
re-fetched at least every 24h, and it too comes from the origin); and nothing
that monitors from outside the victim can see an attack targeted at one
authenticated user. The only mechanisms that bind code to a key instead of a
hostname (Isolated Web Apps, WEBCAT, Meta's Code Verify) all require something
installed *outside* the page, which breaks "one universal app." The whole
industry lands in the same place: no web-delivered E2EE vendor solves this
in-page. Signal refuses to ship a web client for exactly this reason; Proton
keeps its web app on *demand* grounds and tells worried users to switch to the
mobile app.

**Why this is not our biggest risk (the reframe that reorders the project).**
We are the operator *and* the key directory. A compromised or compelled us does
not need to fork a JavaScript build and route a victim to it, which is the
expensive, expert, artifact-producing path. We could just **substitute a
not-yet-verified contact's identity key in the directory**: server-side, one row,
no deploy, no artifact, and it works identically against a PWA or a signed native
app. Native packaging would not fix this. **Out-of-band safety-number
verification fixes it** (section 6). So the correct security priority order puts
verification first and code-delivery hardening second, and this document is
ordered accordingly. (Verification's own dependency on honest client code is
faced squarely in section 6.1.)

**What hardening can and cannot buy.** We cannot stop a compelled operator from
serving bad code. What we *can* raise the cost of is a **non-selective** attack:
one that ships the same bytes to everyone. Reproducible builds plus a release hash
in a public **append-only** log (one I cannot delete from or backdate) make such an
attack **publicly falsifiable**,
meaning an independent party who actively rebuilds and diffs the served bytes can
prove it happened. Two honest limits carried throughout: this is not automatic
("falsifiable" needs someone to actually monitor and diff, it is not "loud" on its
own), and a determined operator can serve modified bytes *selectively* per request
(keyed on IP, or the userId already bound to each socket in 7.3), handing clean
code to the canary and the auditing friend while backdooring the real targets,
which defeats even broad detection. So hardening raises cost and risk against lazy
or non-selective compulsion; it is not a technical guarantee, and against a
selective operator it does not detect the attack at all. The concrete stack is
section 10.

**The decision.** Ship a **hardened, universal PWA** for v1: reachable on every
device including Linux desktops and Linux-based phones with no app store, which
for our users is the difference between a tool they actually use and nothing.
Disclose the limitation in plain language (section 10.4). Keep a native build
(Tauri) as a documented, demand-gated v2 that changes the *shape* of the code
attack for those who want it (section 10.5), and point the one technical friend
who wants real verification at Firefox + WEBCAT, which costs us nothing once the
reproducible build exists. **Universality is itself a security property when the
alternative is SMS.**

---

## 2. Cryptographic primitives

All from `@noble/*` (MIT, small, audited by Trail of Bits, Kudelski, Cure53) plus
browser-native WebCrypto. **No novel primitives, no novel modes.**

| Purpose | Primitive | Source |
|---|---|---|
| Diffie-Hellman (X3DH, ratchet) | X25519 | `@noble/curves` (sole provider; see 8.1) |
| Signatures | Ed25519 | `@noble/curves` |
| Root KDF (X3DH output, DH-ratchet steps) | HKDF-SHA-256 | `@noble/hashes` |
| Symmetric-key ratchet (chain steps) | HMAC-SHA-256 | `@noble/hashes` |
| Message authenticated encryption | XChaCha20-Poly1305 | `@noble/ciphers` |
| Fingerprint / safety number | SHA-512, iterated (6.2) | `@noble/hashes` |
| Passphrase KDF (identity backup) | Argon2id (params in 14) | `@noble/hashes` |
| Web Push transport encryption | aes128gcm per RFC 8291 | lifted from Mirkwood `worker/push.js` |

XChaCha20-Poly1305 is chosen over AES-GCM because its 192-bit nonce space makes
nonce reuse a non-issue: nonces are **unique by construction**, derived by HKDF
from the unique per-message key for ratchet messages (5.1, so nothing extra is
transmitted) and drawn at random only for one-shot contexts (backup, push). Every
signature and every KDF is **domain-separated** with a distinct, versioned context
string (4.4, 5.1, 7.3): without it, one signing use becomes an oracle for another
(the v0.1 bug).

---

## 3. Identity

Two keypairs, generated on-device at first launch, never leaving in cleartext:

- **`IK_sig`** (Ed25519): *the* identity; the safety number (6.2) derives from
  its public key. Signs everything else.
- **`IK_dh`** (X25519): the DH key for X3DH. Its public key is published **and
  transmitted in the initial message**, always bound by
  `Sig(IK_sig, "Nightjar-idkbind-v1" || IK_dh_pub)`, and that signature **must be
  verified before any DH involving `IK_dh` is computed** (section 4.2).

> Separate signing and DH keys (rather than one Curve25519 key via XEdDSA)
> eliminate the "same key, two algorithms" debate at the cost of one signature.
> The split makes the `idkbind` check mandatory and tested.

**User id** = `base32(SHA-256(IK_sig_pub))` at **full 256-bit width** (never
truncated: a short id would be grindable to a routing-hijack collision, since
7.3 authorizes by matching this hash). A separate display name is cosmetic. No
passwords anywhere.

---

## 4. Prekeys and the X3DH key agreement

Implements X3DH (signal.org/docs/specifications/x3dh) with the additions noted,
so Alice can start an encrypted conversation with an offline Bob, forward-secret
from the first message.

### 4.1 Published prekey bundle (per user, held by the Directory)

- `IK_sig_pub` (Ed25519).
- `IK_dh_pub` (X25519) `+ Sig(IK_sig, "Nightjar-idkbind-v1" || IK_dh_pub)`.
- `SPK_pub` (X25519 signed prekey) `+ Sig(IK_sig, "Nightjar-spk-v1" || spk_id ||
  createdAt || expiry || SPK_pub)`, with `spk_id`, `createdAt`, and `expiry`
  inside the signed blob (createdAt is signed so the max-age check cannot be
  bypassed). The client rotates it automatically once the current SPK passes
  `SPK_ROTATION_MS` (~7 days), checked on every authenticated connect: it
  generates a fresh SPK at the next id, publishes it, and keeps the retired
  private half until initials that cite it can no longer arrive
  (`SPK_RETIRE_GRACE_MS`). The acceptance window is the 14-day max age (section
  14), so a briefly-offline owner does not break inbound sessions, and a
  longer-offline one heals on its next connect rather than becoming permanently
  unreachable for new contacts.
- `OPK_pub[]` : one-time prekeys, each with an id, **unsigned** (matching Signal;
  substitution degrades only to a session-setup DoS, and the responder fails
  closed and surfaces it).
- `version` : the ciphersuite/version octet (4.4).

The server hands out **one OPK per fetch and deletes it**; bundle fetches are
rate-limited and authenticated (at most one outstanding OPK per (fetcher,
target)) to blunt depletion (4.3). The client replenishes when low and alerts on
exhaustion.

### 4.2 Session setup (initiator Alice, responder Bob)

1. Alice fetches Bob's bundle and, **before using any key**, verifies: the
   `idkbind` signature on `IK_dh_b`, the `spk` signature on `SPK_b`, and that
   `SPK_b`'s signed `expiry` is future and no older than `2x` the rotation
   period. If Bob is known, she checks `IK_sig_b` against the pinned value (6.4);
   a mismatch is a loud key-change warning, never a silent accept.
2. Alice generates ephemeral `EK_a`.
3. `DH1 = X25519(IK_dh_a, SPK_b)`, `DH2 = X25519(EK_a, IK_dh_b)`,
   `DH3 = X25519(EK_a, SPK_b)`, `DH4 = X25519(EK_a, OPK_b)` (omitted only if no
   OPK; see 4.3).
4. `SK = HKDF-SHA256(ikm = F || DH1 || DH2 || DH3 || DH4, salt = zeros[32],
   info = "Nightjar_X3DH_v1" || version)`, `F = 0xFF x 32`.
5. **AD**, fixed once at session creation and persisted, canonical order:
   `AD = version || IK_sig_a_pub || IK_dh_a_pub || IK_sig_b_pub || IK_dh_b_pub`
   (initiator fields first). Fed as AEAD associated data on every message. A test
   asserts both sides store byte-identical AD.
6. Alice's **initial header** carries: `version`, `IK_sig_a_pub`, `IK_dh_a_pub`,
   `Sig(IK_sig_a, "Nightjar-idkbind-v1" || IK_dh_a_pub)`, `EK_a_pub`, `spk_id`
   (which of the responder's signed prekeys was used, needed to look it up across
   a rotation overlap), and `opk_id`. Bob verifies `IK_sig_a` (pinned/TOFU) **and**
   the `idkbind` signature **before** computing `DH1 = X25519(SPK_b, IK_dh_a)`.

### 4.3 Initial-message replay and OPK depletion

With no OPK, `SK` is deterministic from long/medium-term keys plus `EK_a`, so a
captured initial message would re-derive the same `SK` forever, and 5.3's replay
protection is intra-session only. Both defenses required:

- **Responder-side initial-message replay cache**: bounded, persisted dedup keyed
  on `H(initial header)`, written **only on the AEAD-success path**; repeats
  rejected; Bob commits no durable ratchet state from an initial message until his
  first genuine DH-ratchet response. Eviction must not age out an unresponded but
  valid initial message into a replayable window (in the no-OPK case its `SK` is
  deterministic), so the cache holds every un-responded initial message rather
  than evicting by time alone.
- **Depletion control**: authenticated, rate-limited fetches; aggressive OPK
  replenishment; an explicit logged "degraded / no-OPK" condition surfaced in the
  UI. Listed in section 13 as a residual limitation until fully mitigated.

### 4.4 Version / ciphersuite and downgrade protection

A `version` octet rides in the bundle and every header, is included in `AD` and
hashed into the X3DH `info`, and each party **aborts if the peer's advertised
version is below its supported floor**. This exists in v1 so the v2 PQXDH upgrade
cannot be stripped to classical without detection.

---

## 5. The Double Ratchet

Implements the Double Ratchet (signal.org/docs/specifications/doubleratchet); the
most security-critical and most-tested module.

### 5.1 Chain and message keys (all derivations domain-separated)

- Symmetric chain: `CK_next = HMAC-SHA256(CK, 0x02)`, `MK = HMAC-SHA256(CK, 0x01)`.
- DH-ratchet root step: `(RK_next, CK_next) = HKDF-SHA256(ikm = DH_out, salt = RK,
  info = "Nightjar_DRRoot_v1")`.
- Message-key expansion: `HKDF-SHA256(ikm = MK, salt = zeros,
  info = "Nightjar_MsgKey_v1")` -> 32-byte content key ‖ 24-byte nonce.
- AEAD: XChaCha20-Poly1305, associated data `= AD || header_bytes`.

Info strings are distinct and versioned; lengths and salts pinned in section 14,
covered by known-answer tests.

### 5.2 Message header

`{ version, dh_pub, pn, n }`: authenticated as AEAD associated data, visible to
the relay in v1 (ratchet public keys and counters only, no identity/content).
Header encryption is deferred to v2.

### 5.3 Receive and send discipline (the parts hobby code gets fatally wrong)

**Receive: verify before you mutate.**
1. **Bound the work first.** If `(n - Nr)` or `pn` exceeds `MAX_SKIP` (14), reject
   immediately, deriving nothing (a *compute* bound, not only storage: a forged
   `n = 10_000_000` would otherwise freeze the single-threaded page).
2. **Work in a scratch copy** for the DH-ratchet step and skipped-key derivation.
3. **Commit only on AEAD success.** Only after Poly1305 verifies do you persist
   new root/chain keys, adopted `dh_pub`, advanced counters, stored skipped keys,
   and the receive-dedup entry, **in one IndexedDB transaction**. On failure,
   discard the scratch; persisted state untouched. One forged packet must never
   desync the ratchet.

**Skipped keys.** At most `MAX_SKIP` per session, evicted oldest-first (marking
those message ids "unrecoverable" in the UI, not a false corruption error). Each
is stamped with the receive-time clock and pruned once older than
`SKIPPED_KEY_EXPIRY_MS` (14 days, section 14), which exceeds the outbox retry
horizon (7 days, 7.2), so a sender's late retry always lands on either a live
skipped key or the receiver's dedup set, never a silently-aged-out key. Consumed
keys are deleted and their number refused (replay rejection). Junk never reaches
commit (rule 3), so only real skips consume budget.

**Send: commit before you release.** Order is **advance sending chain -> derive
MK and expand -> encrypt -> commit advanced state + outbox entry (with `n` and a
message id) in one transaction -> only then hand the envelope to the socket.**
Releasing ciphertext before the chain advance is durable risks a crash reloading
the old `CK` and reusing the identical key *and* nonce on the next send (a total
break of two messages). **Encrypt exactly once**; retries re-transmit the
byte-identical stored envelope; the ratchet advances once per message id, never
per transmission attempt.

**Receive-side idempotency.** Persist a dedup entry (by message id, or
`(sender, dh_pub, n)`) in the same transaction as the ratchet advance. On
redelivery of a known id, skip processing and re-ack; raise corruption only for
an *unknown* id that fails to decrypt.

**Concurrency and multiple tabs.** IndexedDB transactions auto-close on an
event-loop yield and cannot be held across async crypto, so per-transaction
atomicity does not by itself serialize a read-modify-write. All ratchet ops for a
session run behind an in-memory async mutex, and a **single ratchet writer per
origin** is enforced across tabs via the Web Locks API (`navigator.locks`), other
tabs read-only followers. (Ordinary two-tabs case, distinct from deferred
multi-*device*.)

### 5.4 Test plan

- Known-answer vectors for every primitive (from the noble suites and the RFCs).
- Property: both parties derive identical message keys and identical stored AD;
  each message decrypts exactly once; deleted keys cannot be re-derived; sessions
  survive serialization.
- Adversarial: out-of-order and dropped messages; `MAX_SKIP` compute and storage
  bounds; replay rejection; a forged header leaving state untouched;
  **crash-before-persist on both send and receive**; redelivery idempotency; two
  overlapping receives on one session.

---

## 6. Trust bootstrapping: the highest-value control in the system

Signal's hardest problem (verify a key belongs to a real human, at billion-user
scale) needs secure enclaves. **Nightjar's users know each other in real life,**
which lets us reach a stronger end guarantee, *but only when the verification
actually happens.*

### 6.1 Why this comes first

**We are the key directory.** The cheapest attack on a compelled operator is not
backdooring client code; it is **substituting the identity key we serve in the
directory for a not-yet-verified contact** (swapping only the signed or one-time
prekeys yields at most a session-setup DoS; reading content requires substituting
the identity key), server-side, one row, no artifact, defeating E2EE completely.
The out-of-band safety-number check is the *only* thing that catches this, so it
is the number-one security control in the whole project and the first thing built
into the trust UI, ahead of any code-delivery hardening (section 10).

Honest caveat we state to users: the safety-number check is itself run by
operator-served code. The same client code renders the safety number, *and*
implements key-change detection, the pinned-key comparison, and the send-blocking
of 6.4, so a compelled operator who ships dishonest client code can show a
correct-looking number, silently suppress the key-change alert, or tamper with the
pin store, just as easily as it can swap a key. That does not make verification
pointless: it forces the attacker from "silently swap a key server-side"
(trivial, invisible, and effective against an honest client) to "ship lying client
code" (the harder, evidence-producing, section-10-watchable attack). It raises the
floor enormously, which is exactly why it comes first. It does not make a verified
contact unconditionally safe from an operator willing to ship bad code, and we say
so (Goal 4, sections 13.1 and 13.2).

### 6.2 Safety numbers

Order-independent function of both identities:
`SN = truncate( iterated-SHA512^(N_iter)( "Nightjar-SN-v1" ||
sort(IK_sig_a_pub, IK_sig_b_pub) ) )`, with `N_iter` and a displayed width of
**at least 120 bits** pinned in section 14 (a short SN is grindable to a
collision). SN covers `IK_sig` **only**, so the `idkbind` and `spk` signatures
(section 4) must be verified on every bundle. Rendered as digit groups and a QR
code for in-person comparison.

### 6.3 Invite carries trust in one direction

A one-time code (single-use, unguessable, serialized in a Durable Object, 7.1, so
it is unforgeable by a *network* attacker; the operator, who mints and renders it,
is a different matter, see the caveat below) embeds the **inviter's** full-width
`IK_sig` fingerprint (pinned to the same 256-bit width as the user id, section 14:
a truncated fingerprint would let the compelled operator-directory grind a
colliding identity key and defeat the pin, the same attack class section 3 guards
against for the user id). Handed over in person or on an already-trusted channel,
it lets the joiner pin the inviter's real key on join; the joiner's client uses it
as a full-width equality check against the `IK_sig_pub` the directory returns.
This authenticates **inviter -> joiner only**; the inviter still learns the
joiner's key via TOFU and shows the contact "unverified, scan to verify" until
the mutual check. Optional closing step: on redemption, the joiner's client
surfaces the joiner's fingerprint for the inviter to confirm. Caveat: the embedded
fingerprint is only as honest as the operator-served client that generates and
displays it (section 6.1).

### 6.4 Key-change policy (TOFU with teeth)

- **First contact:** trust on first use, except the direction an invite
  authenticated (6.3), which is pinned.
- **Key change on a known contact:** loud, blocking warning; if the contact was
  ever verified, **sending is blocked** until re-verification.
- **A restored identity keeps the same `IK_sig`** (8.3), so restore does not
  trigger false warnings. An empty store with a prior-use signal (8.2) routes to
  restore, never to silent new-identity generation.

### 6.5 The session book (glare and re-establishment)

A peer slot is not one ratchet session but a **session book**: a `currentId`
plus a bounded set (`MAX_SESSIONS_PER_PEER`, section 14) of sessions. This solves
two problems with one structure, without any userId tie-break:

- **Glare.** If two contacts each send a first-contact initial before either has
  received the other's, a single-slot design would have each side's inbound
  responder session overwrite its own just-made initiator session, diverging the
  two ratchets so every later normal message fails forever. With a book, an
  accepted initial is *promoted* to current and the prior current is *archived*,
  never clobbered.
- **Re-establishment.** After a restore (8.3) the peer legitimately starts a new
  session; it is promoted the same way.

Sends use the current session. Inbound decrypt tries the sessions in order and
keeps whichever authenticates (a wrong session throws and leaves its state
untouched, by the 5.3 discipline). The book is bounded, LRU-evicting the
least-recently-used non-current session, so a peer cannot grow it without limit.
A never-decryptable envelope is retried, then acked-and-dropped after
`POISON_MAX_ATTEMPTS` so the relay stops redelivering it forever (5.3).

---

## 7. Server and transport architecture

Cloudflare Workers + Durable Objects, deployed push-to-main. A **dumb,
store-and-delete relay**: never sees plaintext, holds ciphertext only until
delivery (or the 30-day TTL).

### 7.1 Components

- **Directory (one Durable Object).** `user id -> public prekey bundle`; serves
  bundles, vends+deletes OPKs (rate-limited, 4.1), performs **invite-gated
  registration** with redemption serialized **inside the single-threaded DO**
  (not app-level read-then-write on D1). If D1 backs storage, consumption uses an
  atomic `UPDATE ... WHERE used=0` checked by rows-affected plus a UNIQUE
  constraint in a transaction.
- **Inbox (one DO per user, `idFromName(userId)`).** Holds queued ciphertext,
  relays over a hibernation WebSocket, **deletes on ack**; alarm-purges anything
  past the 30-day TTL. Keeps a **seen-id set** (TTL >= max outbox retry horizon,
  decoupled from envelope storage) so a duplicate id is ack-and-dropped even
  after the original was delivered and deleted.
- **Push sender.** Mirkwood's `worker/push.js`, lifted (7.4).
- **Static app.** The PWA bundle, subject to sections 1.4 and 10; served as
  immutable atomic deploys whose *release hashes* are recorded in a public
  append-only log (10.1).

### 7.2 Sending a message

Encrypt once -> `{ id, to, header, ciphertext }` -> commit outbox entry -> POST
over the authenticated WebSocket -> Worker routes to `Inbox(to)`. If connected,
relay, decrypt, persist ratchet + dedup id in one transaction, ack, delete. If
offline, queue + Web Push (7.4); drain by cursor on reconnect, acking each. The
client keeps a **pending outbox** and retries the byte-identical envelope until
acked, deduping by id at both ends; retry lifetime is bounded shorter than the
receiver's skipped-key expiry, and a message that still fails is re-sent at a
fresh chain position, never a stale `n`.

### 7.3 Authentication (no passwords, no signing oracle)

On connect the Worker issues a **structured** challenge
`{ tag: "Nightjar-auth-v1", server_nonce, connection_id, origin, timestamp }`,
never opaque bytes. The device refuses to sign anything lacking the auth tag or a
fresh timestamp/nonce, and **verifies `challenge.origin` matches the origin it is
actually connected to** before signing, then returns
`Sig(IK_sig, canonical_encode(challenge))` plus `IK_sig_pub`. The Worker verifies the signature and that
`SHA-256(IK_sig_pub) == userId`, then issues a short-lived token bound to
`connection_id`. Because auth signatures are tagged `Nightjar-auth-v1` and prekey
signatures `Nightjar-idkbind-v1` / `Nightjar-spk-v1`, the login flow can never be
used to mint a signature over an attacker's chosen key.

### 7.4 Push (privacy-preserving, iOS-aware, and de-Googled/Linux-aware)

Reuses Mirkwood's RFC 8291 (aes128gcm) + RFC 8292 (VAPID) sender.

- **Ciphertext-in-payload, double-encrypted.** Our E2EE envelope rides inside the
  RFC 8291 transport encryption; push services see only doubly-encrypted bytes.
- **iOS 3-strikes rule.** iOS cancels a subscription after three pushes that
  display no notification, so **every** push calls `showNotification`. v1 shows a
  **content-free** "New secure message" and does **not** advance the ratchet in
  the service worker (two writers to one ratchet is the corruption risk of 5.3).
- **Notification truthfulness.** The SW suppresses/replaces the notification when
  a foreground client is connected, coalesces rapid pushes, and the page clears
  it on drain; onboarding frames it as a content-free nudge.
- **Subscriptions authenticated and origin-checked.** Registered only over the
  authenticated session, stored against that `userId`; before `fetch(endpoint)`
  the host is checked against an allowlist of known push origins; pruned on
  404/410 and on key change.
- **de-Googled Android and Linux phones (the universality point).** Web push on
  these devices works through **Firefox-based browsers**, whose push goes via
  Mozilla's autopush service and needs no Google. Chromium without Play Services
  cannot do web push, so onboarding for those users recommends a Firefox-based
  browser. If we later ship the native path (10.5), the same wire format is
  delivered via **UnifiedPush** (which is itself RFC 8030/8291/8292 web push), so
  the sender code is unchanged.
- **iOS install requirement.** iOS Web Push needs the PWA added to the Home
  Screen; onboarding walks iOS users through it.

### 7.5 What the server persists

Public prekey bundles; transient undelivered ciphertext (deleted on ack, 30-day
TTL); per-Inbox seen-id sets; a few push subscriptions per user; invite records;
and, **only if the user opts in**, a passphrase-wrapped identity backup blob
(8.3). No message content at rest, no delivery logs, no server-side read
receipts, no address book. User ids are opaque full-width key hashes.

---

## 8. Client-side key storage

### 8.1 Where keys live, and what non-extractability really buys

Identity private keys live in IndexedDB, generated as **extractable** raw bytes
(via `@noble`) because backup (8.3) must wrap them and a non-extractable
WebCrypto key cannot be exported. We therefore do **not** claim non-extractability
for the identity key. Ratchet state lives in IndexedDB as raw bytes (the noble
ratchet needs them in memory anyway; forward secrecy bounds the blast radius).
Honest scope: in-page script (XSS) can read every ratchet and message key and
*use* the identity key to sign the auth challenge, so the **primary** endpoint
defense is the strict CSP and DOM hygiene (8.4 and 10.2), not a storage flag.

### 8.2 Persistence and eviction (the PWA trap)

Call `navigator.storage.persist()`. **Safari ITP wipes script-writable storage
after 7 days of non-use**; a Home-Screen PWA is exempt in practice but this has
varied, so we **detect** it: a sentinel kept outside script-writable IndexedDB
(a Cache Storage marker and/or a server-side "this identity registered" flag). An
empty store *with* a prior-registration signal routes to **restore-from-backup**
and warns explicitly; it never silently generates a new identity.

### 8.3 Backup and recovery

Implemented in P8, **download-only** in v1.

- **Identity backup:** the two identity private keys **and the contact-trust map**
  (peer id, bound `IK_sig`, trust level, verification timestamps) wrapped under an
  Argon2id key from a user passphrase (params in 14), per-blob random salt,
  XChaCha20-Poly1305 AEAD, and a version/params header that is itself the AAD (so
  no header field, including the KDF cost parameters, can be altered without
  failing the tag). The key and nonce both derive from the passphrase via HKDF, so
  the nonce is unique by construction. The server never sees the passphrase, the
  blob, or the plaintext. A restored identity keeps the same `IK_sig`, so id,
  contacts, and verification status survive; each imported contact row is
  re-checked against the `userId == H(IK_sig)` binding and dropped if it fails.
- **The passphrase is the backup's whole security.** The UI offers a generated
  ~100-bit passphrase and holds typed ones to a minimum length (section 14); the
  honest framing is that whoever holds the file and the passphrase holds the
  identity, and losing either along with the device means no recovery.
- **Server-stored backups are deferred.** They would be an offline-attackable
  secret whose seizure reduces to passphrase strength (1.3), so v1 ships
  download-only, which avoids that risk. If added later they require an enforced
  passphrase-strength floor.
- **Restore forces fresh prekeys.** Staging wipes the device's session-layer
  state, then a durable one-shot flag drives a re-registration on the next
  authenticated connect: a fresh SPK + OPK batch is published and the server's
  re-registration path hard-invalidates the previously published bundle and
  outstanding OPKs. The flag is set *before* the restored identity is loadable and
  cleared *only* on a successful publish, so a crash or offline restore retries
  rather than silently leaving the Directory serving dead prekeys. In-flight
  initial messages sent in the seconds before invalidation are unrecoverable, and
  we say so.
- **History does not come back.** The backup carries the identity and contact
  trust, not message history (8.5): history is per-device, and syncing ratchet
  sessions would break forward secrecy. A restored device starts with an empty
  history and a fresh at-rest history key. Encrypted history export/import is a v2
  candidate.

### 8.4 XSS is the real endpoint enemy

Strict CSP (no inline script, no third-party origins, everything self-hosted and
bundled) and DOM hygiene (render message content as text, never `innerHTML`).
This is elevated and specified further in section 10.2.

### 8.5 Persistent message history + the app-lock (at rest)

Message history is stored on the device (before this, it lived only in RAM and was
lost on reload), encrypted at rest behind a **mandatory app-lock**. A random
32-byte **Local Data Key (LDK)** protects all at-rest local data; per-use sub-keys
(HKDF from the LDK) protect message history and the contact list. Each message is a
per-message record in the sessions IndexedDB whose **whole content, not just the
body** (content id, peer, direction, timestamp, and text) is sealed with
XChaCha20-Poly1305 under a key+nonce derived (HKDF, info `Nightjar_History_v1`,
**fresh per-record salt**) from the history sub-key; the record's IndexedDB key is
an **opaque HMAC** of (peer, direction, content id) under an index sub-key, so the
database reveals no peer/timestamp/count at rest. The AEAD AAD binds that storage
key + a history-format version. A record is written in the **same IndexedDB
transaction** as the ratchet advance and dedup marker (no ack-without-history
loss). The **contact list** (and pending-trust / aliases) is likewise sealed under
a contacts sub-key.

The LDK is **never stored unwrapped**: it is generated in RAM at enrollment,
wrapped under each enabled unlock method, and only the wraps are persisted. Methods
(at least one knowledge factor required, biometric optional):
- **passphrase / PIN**: `kek = HKDF(Argon2id(secret, salt, 64 MiB/t3/p1), fresh
  salt, "Nightjar_LockWrap_v1")`, `AEAD(kek, LDK)`;
- **biometric (WebAuthn PRF)**: `kek = HKDF(prfSecret, fresh salt, same info)`;
  unlock requires and **verifies user-verification** (the UV flag), not mere
  presence.

Because Nightjar is a PWA with no OS keychain, at-rest confidentiality reduces to
"you unlock each session": the app builds no network client and processes no
inbound messages while locked (the socket is never opened), and locking (idle
timeout / "lock now") clears the LDK and the decrypted history from RAM. Forgetting
the secret erases the saved history (a sanctioned reset), but never the identity,
which is recovered from the separate backup passphrase.

Honest at-rest posture, stated plainly:

- **Confidentiality of at-rest history + contacts reduces to the unlock secret's
  strength.** A strong passphrase or a hardware biometric is strong; a short
  **numeric PIN is weak against an extracted device image** (a PWA has no hardware
  rate-limiting, so an attacker brute-forces the small numeric space offline).
  Methods are wrapped independently, so at-rest security is that of the **weakest
  enrolled method**. The UI labels the PIN accordingly and steers at-rest-sensitive
  users to a passphrase.
- **The lock protects message history + the contact list only, and is not
  forward-secret.** The identity and ratchet **session keys stay unencrypted** (the
  app must be able to authenticate + decrypt after unlock), so a forensic image of
  the device can still decrypt *future* traffic once the device is used. We do
  **not** claim parity with Signal/WhatsApp defaults (OS-keychain-backed).
- **Biometric strength is the authenticator's.** A hardware platform authenticator
  is strong; a synced/software passkey is weaker. Biometric is never the sole
  factor (a knowledge factor always remains, so a lost authenticator is not a
  permanent lockout).

---

## 9. Metadata: the complete leak list and our honest posture

An operator who chooses to log, or anyone who can compel us, can learn:

- **The directed sender -> recipient edge** (sends ride the sender's
  authenticated WebSocket, and the X3DH initial header carries `IK_sig_a_pub` in
  cleartext).
- **Contact intent** (who fetches whose bundle).
- **Timing, volume, message counts** (via cleartext ratchet counters `n`/`pn`).
- **Presence** (persistent WebSocket).
- **Message length** (no padding in v1; ciphertext length leaks plaintext length).
- **Source IP** (unless VPN/Tor).
- **Push (only if the user opts in, P6).** Opting a device into Web Push has two
  honest costs the pseudonymous userId otherwise avoids, so it is **off by
  default, per device**: (a) the relay stores a mapping `userId -> push endpoint`
  (a stable FCM/APNs/Mozilla-autopush device token), a durable link between the
  pseudonym and a real device/push-account that a compelled operator or the push
  provider can resolve; (b) the **push provider** (Google/Apple/Mozilla, a party
  otherwise never involved) learns a per-recipient message-**arrival timeline**
  and Nightjar membership (all our pushes carry the one VAPID `k`). It does NOT
  learn content (the payload is content-free and doubly encrypted) and does NOT
  learn the sender->recipient edge (the sender never touches the push service).
  Steering de-Googled users to a Firefox/Mozilla-autopush browser keeps this off
  Google. The subscription is never surfaced to any other user, API, or log.

Mitigations: store-and-delete, no delivery logs, opaque full-width key-hash ids,
minimal logging, open code. Optional fixed-bucket padding is a candidate if we
spend the bandwidth; otherwise length leakage is an accepted v1 limitation
(section 13). We cannot hide the social graph, counts, or timing from a
determined operator, nor anything from a global passive adversary. We over-
disclose here rather than mislead.

---

## 10. Verifiability and host-integrity hardening (the hardened-PWA stack)

Section 1.4 established the ceiling: we cannot stop a compelled host from serving
bad code, and no in-page trick changes that. This section is what we build
*anyway* to make a **non-selective broad** attack (identical bytes served to
everyone) **publicly falsifiable**, and to give a technical friend a real way to
verify. Two limits carry through every item below and are not repeated each time:
"falsifiable" is not automatic (someone must actively rebuild and diff), and a
compelled operator can serve modified bytes **selectively** per request (by IP, or
the userId bound to each socket in 7.3), which defeats the canary and the auditing
friend even for a broad campaign. **Ranked by value-per-effort.** For each: **B**
= value against a *non-selective broad* attack, **T** = against a *targeted*
(one-user) or selectively-served attack.

Security priority order for the project as a whole: **safety-number verification
and loud key-change alerts (section 6) come before everything here** (they are
priority 1 in section 12), because the key-directory attack is cheaper than the
code attack and packaging does not fix it. Then the items below.

### 10.1 Reproducible build + a release hash in a public append-only log

**B: high (the enabling item). T: nothing directly, but the precondition for all
the rest.** Without a reproducible build, a published hash proves only that we
published *a* hash, not that it matches auditable source. With it, a technical
friend rebuilds from the public git tag and confirms byte-identity. Mechanics:
determinism comes from a **digest-pinned build container** (Node + OS + arch) and
`npm ci` against a committed lockfile, with **no build-time dynamic values**
(`__APP_VERSION__` is injected, never a clock; no git-describe banners). (
`SOURCE_DATE_EPOCH` / `strip-nondeterminism` are kept as documented no-ops: this
toolchain does not consume them and the manifest hashes file content only.) Then
diff two builds to byte-identity. Sign each release manifest into a public
**append-only** log (Sigstore/Rekor). (An earlier design also cut an SSH-signed
git tag; that ceremony was dropped as operator friction, and the transparency
story does not rest on it: the deploy trigger is a push to `main`, and the
release is identified by the CI run's recorded commit plus the Rekor entry's
workflow identity.) The load-bearing property is **append-only**: a prior honest
entry cannot be deleted or backdated.
It is *not* independence from the operator, because the keyless OIDC signer is our
own repo CI, which a compelled operator controls; a Rekor entry therefore attests
only "this repo's CI logged hash H at time T", never that the build is honest.
Three honest limits: reproducibility proves the binary matches the *source*, not
that the source is *honest* (a backdoor in public source reproduces perfectly and
passes the diff unless someone reads each release's changes); a malicious pinned
dependency or toolchain reproduces perfectly too (the determinism gate is a
nondeterminism check, not supply-chain integrity); and the log does not bind the
bytes a given user was *served* to any entry (that is the canary's job in 10.3, and
the canary is defeatable by selective serving). This is still the item that makes
"verifiable by a technical friend" possible rather than a slogan.

### 10.2 Strict CSP + fully static assets + no inline script + SRI + Integrity-Policy

**B: real (but not the advertised thing). T: nothing.** This does not touch the
origin; it forces any backdoor to be baked into the one first-party bundle the
hashing can watch, instead of smuggled via a stray script. `default-src 'self'`,
no `unsafe-inline`, no `unsafe-eval`, tight `connect-src` (relay + push endpoint
only), SRI on every subresource, and the `Integrity-Policy` header so every
script must carry integrity metadata. Bonus: this exact configuration also
satisfies the operator requirements of WEBCAT (10.5), free optionality on the one
fail-closed verification tool that exists.

### 10.3 Immutable atomic deploys + build hash in the UI + a canary

**B: moderate against a lazy operator and third parties. T: zero.** The deploy is
Model A: CI builds the artifact in the digest-pinned container, logs its hash to
Rekor, and `wrangler deploy`s *that same* artifact, so the audited, logged, and
served bytes are one by construction, and each deploy is a distinct, CI-recorded
event rather than an in-place edit. Honest limit: this constrains a lazy operator
and outside tamperers, but buys ~nothing against a compelled operator, who owns
the same Worker + edge that serves the assets and can mutate responses or deploy
off-pipeline, since it controls the edge. Show the release **version tag** and the operator's
**attested release hash** in an About screen, labeled as *a claim you confirm by
rebuilding* (the app cannot hash its own served bytes, 1.3, so this is never a
self-integrity verdict), so a family member can read it to the technical friend.
Run a **canary** (P7 ships the in-app warrant-canary form: a signed, dated operator
statement whose staleness or absence is the signal, verified against a
source-pinned key). Label it honestly: it catches a fleet-wide non-selective swap
or silent rewrite (the lazy version of a compelled attack) via lapse-detection plus
an out-of-band rebuild, and it catches **zero** targeted or selectively-served
attacks, because the victim is served the attacker's canary too. Its fresh state is
rendered as a freshness/authorship fact, never a green "verified" check.

### 10.4 The plain-language disclosure (the highest-leverage 200 words in the app)

Shown in onboarding and the README, in plain language, in CryptPad's voice rather
than a marketing voice:

> Nightjar's code is served by me, from my server, on every load. If someone
> compromises or compels me, I can serve you modified code and your browser will
> run it. No web app can prevent this, not Proton's, not Bitwarden's, not
> WhatsApp Web's. What I do: every release is reproducible from public source and
> its hash is signed into a public append-only log I cannot delete from or
> backdate, so anyone can rebuild and check, which makes a change served to
> *everyone* provable after the fact. It does not stop a change aimed at one
> person, and a determined
> me could serve bad code to just you. The strongest thing you can do is verify
> your contacts' safety numbers in person, though note even that check runs on code
> I serve. Also know: your messages' contents are private, but I can see *who* you
> talk to and *when* (not what you say). And keep a backup of your identity key,
> because if you lose your device without one, your account and history are gone.
> If your threat model includes being targeted by me, by anyone who can compel me,
> or by a state, use Signal.

### 10.5 Optional native path (v2, demand-gated) and the technical friend

Keep the native door open for near-free by staying a **pure static SPA** and
abstracting three things from day one: **push/notifications**, **key/secret
storage**, and **the network/transport origin** (config-injected relay URL, no
hardcoded origins). If a real user later asks for a verifiable installable build,
**Tauri v2** wraps the existing frontend to cover Windows/macOS/Linux desktop,
Android (one self-signed APK covers GrapheneOS/Calyx/Lineage), and, notably, one
ARM64 Linux build runs on Linux phones (postmarketOS/Mobian/Phosh) with no
separate target. Native only changes the *shape* of the code attack (a targeted
backdoor must become a signed, versioned, diffable artifact the user can decline),
it does not remove the developer from the trust path. iOS stays PWA-only
regardless (Apple re-signs; reproducibility impossible). Budget it as mostly a
native-push project, gated on actual demand.

**For the one technical friend who wants real verification, try Firefox + WEBCAT
before building anything native.** Once 10.1 to 10.2 exist, WEBCAT enrollment is
nearly free and gives fail-closed verification of JS + CSS + HTML against a log we
do not control. Alpha and Firefox-only, which is fine for a per-person spot check.

### 10.6 What we deliberately do NOT do

- **Client-side hash pinning / TOFU in the service worker: negative value.** The
  SW is served by the host too, so the bypass is one deleted line; every
  legitimate release trips a warning and trains click-through; and browser-level
  pinning (HPKP) was removed from all browsers by 2020 precisely because it was
  used to ransom domains and brick honest sites. Keep the SW for offline caching;
  hang no security claim on it.
- **Splitting the code host from the relay:** near-zero. The compelled party is
  the *code host*. The only split worth doing is code-host vs *hash-publisher*
  (10.1).
- **IPFS / content-addressed delivery:** does not escape the bootstrap loop (the
  gateway makes traffic suspect and the fix is out-of-band software); high cost,
  no gain over a published hash.
- **Isolated Web Apps:** the best primitive on paper (offline signing key,
  key-derived origin) with zero consumer availability (ChromeOS + enterprise
  policy + a Google allowlist); it re-imports the app-store chokepoint. Watch,
  do not build.
- **Our own Code-Verify-style extension:** four store pipelines and we would own
  the trust root; MEGA's extension was trojaned in 2018. Not worth it.

---

## 11. Reused building blocks (what we already own)

| Nightjar piece | Comes from | Reuse level |
|---|---|---|
| Per-recipient Inbox Durable Object | Mirkwood per-room DO | Reshape, high reuse |
| Web Push (RFC 8291 + VAPID) | Mirkwood `worker/push.js` | Lift near-verbatim; change payload builder |
| watching-vs-connected presence + no-double-ring notifications | Mirkwood `away`/`pushArmed` | Reshape |
| Invite-gated registration (single-use, serialized) | Not the End `getAfter()` | Reimplement in a DO |
| AES-GCM plumbing / versioned token idea | Fireworks `fieldCrypto.ts` | Borrow versioning; replace the trust model |
| PWA install, service worker, chat UI, conversation list, presence heartbeats | Not the End | Reshape, high reuse |
| Idle auto-lock for a key-holding session | Fireworks `idle.ts` | Borrow directly |
| Push-to-main Cloudflare deploy, dashboard secrets | Mirkwood / Fireworks | Same workflow |

The genuinely new surface is the crypto core (sections 3, 4, 5) and the hardening
plumbing (section 10). Everything else is a variation on shipped, verified code.

---

## 12. Build roadmap (session plan) and security priority order

**Security priority order (do these in this order of importance, independent of
convenience):** (1) out-of-band safety-number verification + loud key-change
alerts; (2) the crypto core correctness (X3DH + Double Ratchet, fully tested);
(3) reproducible build + logged release hash + strict CSP; (4) metadata
minimization; (5) everything else.

Phases (each independently testable; crypto phases gated on their test suites
before touching a network):

- **P0. Skeleton + primitives + build hygiene.** Repo, `wrangler.jsonc`, package,
  and from day one: pure static SPA, **strict CSP** (10.2), and a **reproducible
  build** pipeline (10.1) so every later release is verifiable. A
  `crypto/primitives` module (X25519, Ed25519, HKDF, HMAC, XChaCha) on `@noble` as
  the sole provider, with known-answer tests (5.4). A minimal durable IndexedDB
  put/get for the identity keys (full ratchet-state atomicity is P3). Identity
  generation, full-width user id, **safety-number rendering with pinned params**
  (KAT-testable at P0 against a synthetic identity). Keep the native door open by
  abstracting push, key storage, and transport origin (10.5).
- **P1. X3DH.** Bundle publish/fetch/verify (all signatures domain-separated and
  checked before use), session setup, version/downgrade handling, initial-message
  replay cache. Tests: same `SK` and `AD` both sides; tampered/unbound `IK_dh`,
  stale `SPK`, replayed initial messages all rejected.
- **P2. Double Ratchet.** Full send/receive with the 5.3 discipline and the 5.4
  adversarial suite.
- **P3. Persistence.** IndexedDB atomic ratchet writes, async mutex + Web Locks
  single writer, `navigator.storage.persist()`, eviction sentinel/restore routing.
- **P4. Server.** Worker + Directory DO (serialized invite redemption,
  rate-limited OPK vending) + Inbox DO (relay, store-and-delete, seen-id set) +
  structured challenge-response auth + WebSocket relay + client pending-outbox.
- **P5. Trust UI (elevated, do not defer).** Safety-number display and QR compare
  with **per-direction verified state**, and loud **key-change warnings** with
  history. This is priority-1 security; it ships as early as the app can show a
  contact, not as end-stage polish.
- **P6. Push + PWA. DONE.** Lifted `push.js` (RFC 8291/8292) typed as
  `worker/push.ts`, KAT-pinned to the RFC 8291 example. Subscriptions live in the
  per-user Inbox DO, registered ONLY over the authenticated socket (server-verified
  userId), validated against an https-only, dot-anchored **push-service allowlist**
  (SSRF guard; `redirect:'manual'`), per-user capped, and TTL-purged by the alarm.
  A new envelope pushes a **content-free** nudge (`sendNudge`, the only entry
  point; the service worker ignores `event.data`) only when no socket is
  **fresh-watching** (a foreground heartbeat re-affirms presence so a slept/zombie
  socket cannot suppress a push for more than the freshness window). The fan-out
  runs in `ctx.waitUntil()`, off the deliver path. Service worker (no asset cache,
  by design), manifest + icons, install onboarding (Home Screen on iOS, gated
  behind standalone; Firefox guidance on de-Googled/Linux), per-device opt-in.
  Off-until-secret (`VAPID_JWK`). Metadata cost disclosed in 9 + 13. Design was
  red-teamed on paper first (17 findings folded); implementation adversarially
  reviewed; browser-verified.
- **P7. Verifiability hardening. DONE.** One canonical release-hash recipe
  (`scripts/release-hash.mjs`, KAT-locked, == a pure-shell pipeline) over the
  reproducible build; CI (`.github/workflows/release.yml`) builds the artifact in
  the digest-pinned container, cosign-keyless-signs its hash into **append-only
  Rekor**, and `wrangler deploy`s that exact artifact (Model A: served == logged ==
  audited; Cloudflare git-build off). A gate job runs the full test suites and
  both typechecks before any deploy. An **in-app warrant canary** (signed
  `/canary.json`, source-pinned key, off-until-configured) whose staleness/absence
  is the signal, with a benign-outcome taxonomy so a plain offline/unreachable
  fetch stays quiet (the one exception, added in P8: a RETURNING device whose
  freshest locally-verified signature is already older than the stale horizon
  escalates a persistent unreachable to a stale-style warning, so a canary that
  is selectively 404'd cannot stay quiet forever on a device that once saw it);
  an About/"verify this build" view (version +
  attested hash as a claim-you-rebuild + the plain-language disclosure,
  runtime-gated on live canary state, pointing at `docs/VERIFYING.md`); onboarding
  leads with the safety-number pointer. Design red-teamed on paper (6 lenses, 5
  must-fixes folded before code); implementation adversarially reviewed;
  browser-verified. Going public (scrubbed, single source of truth) accompanies it.
- **P8. Backup + release hardening. DONE.** Argon2id passphrase-wrapped identity
  + contact-trust export/restore (download-only in v1), with restore forcing a
  fresh-prekey publish via a durable one-shot flag and the server hard-invalidating
  the old bundle (8.3). Ships alongside the carried-over robustness work:
  automatic **SPK rotation** on connect (4.1), **skipped-key time expiry** (5.3),
  client-side dedup/failure **TTL pruning**, WebSocket **auto-reconnect** with
  connect/request timeouts and permanent-send-error surfacing, sticky security
  notices, and the CI test gate + SHA-pinned actions.
- **P9. Hardening + beta.** Full adversarial review of the *implementation*, then
  a closed beta with a couple of family members. Consider WEBCAT enrollment for
  the technical friend.

Native (Tauri) is **not** on the critical path; it is a demand-gated v2 (10.5).

---

## 13. Known weaknesses we accept for v1 (the honesty section)

1. **Content confidentiality is conditional on out-of-band verification AND honest
   client code.** For a TOFU contact the server can substitute the directory
   identity key and read content (6.1). The safety-number check removes that
   key-swap attack, and is the single most important thing a user can do (section
   6), but it does not remove the bad-code attack: verification itself runs on
   operator-served code (6.1), so confidentiality after verification still depends
   on that code being honest.
2. **Web-delivered client code is trusted (section 1.4).** A compelled operator
   can serve a backdoored bundle; a PWA cannot prove otherwise. Our hardening
   (section 10) makes a *non-selective broad* attack publicly falsifiable *if*
   someone actively monitors and diffs; it does not make it automatically loud,
   and it does not stop a *selective* or *targeted* attack, since the operator
   controls the edge and can serve bad bytes to one userId while serving clean
   bytes to the canary and the auditing friend. Two distinct residual attacks a
   compelled operator can run, both cheap for a lone operator who already knows
   who is connecting, neither dismissed as unrealistic: (i) a **targeted
   key-directory swap** (no artifact at all), mitigated by out-of-band
   safety-number verification plus an honest key-change alert; and (ii) a
   **targeted code substitution**, mitigated only by an installed/verified client
   (native build, or Firefox + WEBCAT, section 10.5) or by using Signal. We do not
   claim to defend against a targeted adversary in the plain-PWA case; we make the
   tradeoff explicit and point at the alternatives.
3. Server-visible metadata (who/when, counts, presence, length) is minimized but
   not hidden (section 9).
4. One device per identity; no multi-device.
5. 1:1 only; no groups.
6. Classical crypto; not yet post-quantum (but downgrade-protected, 4.4).
7. History is persisted on the device (section 8.5) but per-device: it is not
   synced, and the identity backup does not carry it, so it does not transfer to a
   new device and is lost on device loss. It is **encrypted at rest behind the
   mandatory app-lock** (as is the contact list), so its at-rest confidentiality is
   the strength of the unlock secret (weak for a short PIN against a device image,
   8.5). The identity + ratchet session keys are NOT under the lock, so a device
   image can still decrypt future traffic (1.3).
8. Message-header metadata and message length are visible to the relay in v1;
   header encryption and padding deferred.
9. OPK depletion can force new inbound sessions onto the weaker no-OPK path;
   mitigated (4.3), not eliminated.
10. A server-stored identity backup reduces server-seizure resistance to
    passphrase strength (8.3); download-only avoids this.
11. A malicious relay can suppress, delay, or reorder delivery; it cannot forge a
    verified contact's content without also shipping modified client code (1.4).
12. Endpoint compromise (malware, stolen unlocked device, XSS) is outside the
    guarantees; we harden but cannot solve it.
13. **This is a hand-built protocol composition.** Every piece is from a
    published spec on audited primitives, but composition is where messengers
    fail (ETH Zurich found seven protocol bugs in Threema; this document itself
    had several in its first draft, caught only by adversarial review). Nightjar
    protects the content of ordinary conversations among people who trust each
    other, a large, genuine upgrade over SMS, Discord, or any shared-key scheme.
    It is **not** a Signal replacement for someone facing a nation-state
    adversary, and we say so plainly to every user (10.4).
14. **Web Push (opt-in) links the pseudonymous userId to a device token and
    exposes a message-arrival timeline to the push provider** (section 9). It is
    off by default and per device; content is never exposed (content-free,
    doubly-encrypted payload). A privacy-maximizing user simply leaves it off and
    relies on the persistent socket while the app is open.

---

## 14. Pinned security constants

| Constant | Value | Where |
|---|---|---|
| Signature context tags | `Nightjar-idkbind-v1`, `Nightjar-spk-v1`, `Nightjar-auth-v1` (distinct, length-framed) | 4.1, 7.3 |
| X3DH KDF | HKDF-SHA256, salt `zeros[32]`, info `"Nightjar_X3DH_v1"||version`, `F = 0xFF x 32`, out 32 B | 4.2 |
| DH-ratchet root KDF | HKDF-SHA256, salt `RK`, info `"Nightjar_DRRoot_v1"`, out 64 B | 5.1 |
| Message-key expansion | HKDF-SHA256, info `"Nightjar_MsgKey_v1"`, out 56 B (key 32 ‖ nonce 24) | 5.1 |
| AEAD | XChaCha20-Poly1305, AD `= session_AD ‖ header_bytes` | 5.1 |
| `MAX_SKIP` (compute + storage) | 1000 per session, checked before derivation | 5.3 |
| `MAX_SESSIONS_PER_PEER` (session book) | 5 (1 current + <=4 archived); LRU-evict the non-current on overflow | 6.4, 8.3 |
| `POISON_MAX_ATTEMPTS` (receive) | 10 failed decrypts before an undecryptable envelope is acked-and-dropped | 5.3 |
| Skipped-key expiry | 14 days (`SKIPPED_KEY_EXPIRY_MS`); each skipped key is timestamped on receipt and pruned past this. Chain: outbox retry (7d) < seen-id TTL (8d) < skip expiry (14d) | 5.3, 7.2 |
| Outbox retry horizon | 7 days (`OUTBOX_RETRY_HORIZON_MS`); < skip expiry | 7.2 |
| Undelivered envelope TTL | 30 days | 7.1 |
| Inbox seen-id TTL | 8 days (>= outbox retry horizon) | 7.1 |
| SPK rotation / max age / retired-key grace | rotate at ~7 days (client, on connect) / reject if signed age > 14 days / keep a retired SPK private half until expiry + 30 days (envelope TTL) for late in-flight initials | 4.1, 4.2 |
| Client dedup/failure retention | `seen` pruned past 8 days (seen-id TTL), `failures` past 30 days (envelope TTL), on connect; the replay-guard store is never pruned (4.3) | 5.3, 8.1 |
| OPK batch / policy | 100 per batch; <= 1 outstanding per (fetcher,target); replenish under 20 | 4.1, 4.3 |
| User id | `base32(SHA-256(IK_sig_pub))`, full 256-bit, untruncated | 3 |
| Invite-embedded fingerprint | inviter `IK_sig` at full 256-bit width; joiner does a full-width equality check vs the directory-returned key | 6.3 |
| Safety number | iterated SHA-512, `N_iter` = 5200, displayed width >= 120 bits, tag `"Nightjar-SN-v1"` | 6.2 |
| Argon2id (backup) | m = 64 MiB, t = 3, p = 1 (measured ~2.3 s desktop via `@noble/hashes`; 256 MiB was ~9 s and risks OOM in an iOS Safari worker; RFC 9106 constrained-env recommendation); 16-B salt; XChaCha20-Poly1305 body with the header as AAD; key+nonce via HKDF-SHA256 info `"Nightjar_Backup_v1"`; restore bounds m to [8 MiB, 256 MiB], t <= 6, p == 1 before running the KDF | 8.3 |
| Passphrase floor | typed passphrases >= 12 chars (after NFC-trim); the offered generated passphrase is 20 base32 chars (~100 bits) | 8.3 |
| Backup blob format | magic `"NJBK"`, format version `0x01`, then m/t/p/salt header, then AEAD body; download-only in v1 | 8.3 |
| Message payload format | magic `"NJM1"`, format version `0x01`, kind (`0x01` text / `0x02` delete), 16-B content msgId, then (text) a flags byte (bit0 = ephemeral, other bits reserved) + utf8 body; the ratchet plaintext. A payload with no magic is legacy plain text; a magic-but-invalid/unknown-version/unknown-kind payload is clean-ignored (never thrown or rendered) | 8.5 |
| Content vs transport id | the 16-B content msgId lives inside the ratchet plaintext (history key / delete target); the relay-visible transport envelope id is separate (dedup/ack/outbox). A first-send text may reuse its content id as the transport id (brand-new, safe); a delete gets its own fresh transport id | 8.5 |
| App-lock + at-rest data | random 32-B **LDK** wraps all local at-rest data; the LDK is never stored unwrapped, only wrapped per method: passphrase/PIN via `HKDF(Argon2id(secret, 64 MiB/t3/p1, 16-B salt), 16-B salt, "Nightjar_LockWrap_v1")`, biometric via `HKDF(prfSecret, 16-B salt, same info)`, each `XChaCha20-Poly1305(kek, LDK)` with the method kind bound in the AAD. Mandatory; >=1 knowledge factor; PIN min 6 digits (disclosed weak). Sub-keys `HKDF(LDK, "Nightjar_HistBody_v1" / "Nightjar_HistIndex_v1" / "Nightjar_Contacts_v1")` | 8.5 |
| History at rest | per-message record in the sessions IndexedDB; the **whole message** (content id, peer, direction, ts, text) sealed with XChaCha20-Poly1305 under key+nonce = HKDF(history-body sub-key, **fresh 16-B per-record salt**, info `"Nightjar_History_v1"`); IndexedDB key = `hex(HMAC(history-index sub-key, peer‖dir‖id))` (opaque: the DB reveals no peer/ts/count); AAD binds that storage key + a history-format version; written in the same tx as the ratchet advance + dedup marker. Contacts/pending/aliases sealed under the contacts sub-key with a fresh 16-B salt | 8.5 |
| Version octet | starts at `0x01` (classical X25519) | 4.4 |
| Reproducible build inputs | digest-pinned container (Node + OS + arch), committed lockfile (`npm ci`), no build-time dynamic values (`__APP_VERSION__` injected, never a clock). *`SOURCE_DATE_EPOCH`/`strip-nondeterminism` are inert here (vite emits no timestamps; the manifest hashes content only) and kept only as documented no-ops* | 10.1, P7 |
| Release hash | `sha256(manifest.txt)`; `manifest.txt` = each `dist/` file as `<sha256-hex>  <relpath>\n`, byte-sorted, LF (one recipe: `scripts/release-hash.mjs` == the pure-shell pipeline). Hashes the **build output**, so the honest claim is "rebuild and diff", not "diff the served bytes" | 10.1, P7 |
| Release transparency | keyless cosign of `manifest.txt` into public-good **Rekor** (append-only: a prior entry cannot be deleted or backdated; NOT independent of the operator, whose CI is the OIDC signer). Deploy trigger is a push to `main` (no SSH-signed tag). The audited artifact is the deployed one (CI builds in the pinned container and `wrangler deploy`s it; Cloudflare git-build is off), gated on the test + typecheck job; `uses:` actions are pinned to full commit SHAs | 10.1, P7 |
| Warrant canary | Ed25519-signed `{version, releaseHash, statement, signedAt}` at `/canary.json` (public var, off-until-set), verified vs a source-pinned pubkey; re-signed ~30 d, warn at 45 d; tag `"Nightjar-canary-v1"`; future-dated => invalid; a plain offline/unreachable fetch stays quiet, EXCEPT a returning device whose freshest locally-verified signature is older than the 45 d stale horizon escalates a persistent unreachable to a stale-style warning (so a selectively-404'd canary cannot stay quiet forever on a device that once verified it) | 10.3, P7, P8 |
| CSP | `default-src 'self'`, no `unsafe-inline`/`unsafe-eval`, `connect-src` = relay + push only, SRI on all subresources, `Integrity-Policy` on scripts | 10.2 |
| Permissions-Policy | everything denied except `camera=(self)`, needed only for the in-app QR scanner (`getUserMedia`); scanned payloads (invite / public userId) are non-secret and never leave the device | 10.2 |
| QR scanner (dependency note) | camera scanning decodes with the browser's native `BarcodeDetector` where present, else a bundled pure-JS decoder (`jsqr`, MIT, zero deps, no wasm/network). `jsqr` is the ONE non-crypto runtime dependency beyond `@noble`/`@scure`, static-imported into the single SRI-pinned bundle (so it is covered by `Integrity-Policy` and the release hash); it is executed only on the fallback path | 10.2 |
