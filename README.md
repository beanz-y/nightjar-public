# Nightjar

A private, invite-only, end-to-end encrypted messenger for friends and family.

Self-sovereign keypair identity (no phone number, no email, no Google/Apple
sign-in), built on Cloudflare Workers + Durable Objects and the Signal protocol
suite (X3DH + Double Ratchet) implemented on audited `@noble` primitives.
Delivered as a **universal Progressive Web App**: one app, every device,
including Linux desktops and Linux-based phones, no app store required.

> **Design first.** The protocol, architecture, threat model, and hardening plan
> are specified in [`docs/DESIGN.md`](docs/DESIGN.md), and were reviewed and
> attacked before any cryptographic code was written. If you are here to evaluate
> the security, start there.

## Where it stands

Built and live. The crypto core (identity, X3DH, Double Ratchet), the invite-gated
relay, the trust and safety-number verify UI, push plus PWA install, and the P7
verifiability hardening (reproducible build, a release hash in a public append-only log,
and an in-app canary) are implemented. See the roadmap in the design doc.

## The honest disclosure (read this)

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
> talk to and *when* (not what you say). And keep a backup of your identity,
> because if you lose your device without one your account is gone (message
> history stays only on each device and is never in a backup).
> If your threat model includes being targeted by me, by anyone who can compel me,
> or by a state, use Signal.

That paragraph is the point of the project's honesty posture: message contents
are unreadable to everyone but the people in a conversation (once they have
verified each other and are running honest client code), your identity is not
leaked to third parties at signup, and every limit is stated plainly rather than
buried. One caveat belongs right next to the pitch: the server still sees *who*
you talk to and *when* (not what you say). The hardening described above is
implemented (reproducible build, a release hash in a public append-only log, and an
in-app canary), though it becomes fully meaningful only once someone actually
rebuilds and checks. It is a large, genuine upgrade over SMS, Discord, or any
shared-key scheme, and it is not a Signal replacement for someone facing a
nation-state adversary.

## Why a PWA (and not native)

A universal PWA reaches every device your friends and family actually use,
including de-Googled Android and Linux phones, where the alternative is often
nothing. A web app cannot fully defend against its own host, so we harden it
openly (reproducible builds, a release hash in a public append-only log, strict CSP, a
canary) and disclose the residual gap above. A native build (Tauri) that changes
the shape of that residual gap is kept as a documented, demand-gated v2; see
`docs/DESIGN.md` section 10. The single most important defense is not packaging,
it is verifying your contacts' safety numbers in person.

## Reused from our other projects

Web Push (RFC 8291 + VAPID) and the per-room Durable Object come from
**Mirkwood**; invite-gated registration and the PWA/chat UI from **Not the
End**; the client-side crypto plumbing idea (but not its trust model) from
**Fireworks**. The genuinely new surface is the crypto core (identity, X3DH,
Double Ratchet) and the verifiability hardening.

## License

TBD. The crypto core is a clean-room implementation from public Signal
specifications on MIT-licensed `@noble` primitives; we deliberately do not link
Signal's AGPL `libsignal`. Reproducible builds and public source are a security
requirement here, not just a preference (see `docs/DESIGN.md` section 10).
