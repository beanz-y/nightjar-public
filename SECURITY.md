# Reporting a security issue

Nightjar is a small, invite-only end-to-end encrypted messenger. If you have found a
problem with it, thank you for looking, and please tell me before you tell anyone else.

## How to report

**Preferred: GitHub Private Vulnerability Reporting.** On this repository, open the
**Security** tab and choose **Report a vulnerability**. It stays private between us, it
keeps the discussion and the eventual fix in one place, and it does not require either
of us to hand the other an email address.

**By email: `admin@nightjar.chat`.** Use this if you would rather not use GitHub, or if
the report is about the hosted service rather than the code.

Please do **not** open a public issue for something exploitable. A public issue tells
attackers before there is a fix, and the people using this are friends and family.

## What to expect

This is a personal project maintained by one person, so I will be honest about the
service level rather than quote one I cannot keep:

- I aim to **acknowledge within 3 days**, and will say so even if I have no answer yet.
- I will tell you whether I think it is a real issue, and if I disagree I will explain
  why rather than going quiet.
- For something exploitable I will work on a fix straight away, and I will tell you when
  it ships. Deploys are usually same-day, since the pipeline is a push.
- I will credit you in the changelog if you want that, and leave you out if you do not.
- There is **no bug bounty**. I have no money for one. I would rather say that plainly
  than imply a reward that is not coming.

If you report something in good faith, I will not pursue you for it, and I will not
involve anyone else. Please stay within the bounds below.

## Scope

**In scope:**

- The client (`src/`), including the cryptography in `src/crypto/`
- The relay (`worker/`), including the Durable Objects and the push sender
- The build and release pipeline (`.github/workflows/`, `Dockerfile.build`, the
  reproducible-build and transparency-log machinery)
- The live service at the deployed origin
- Anywhere the documentation makes a claim the code does not support. For this project
  that IS a security issue, and I would like to hear about it.

**Please do not**, when testing the live service:

- Run automated scanners against it, or anything that degrades it for the handful of
  real people using it
- Attempt to access, modify or delete data belonging to anyone but yourself
- Use social engineering, phishing, or physical attacks against me or any user

## Already known, and deliberate

Nightjar documents its limits in [docs/DESIGN.md](docs/DESIGN.md), particularly the
threat table in section 1.3 and the metadata list in section 9. The following are known
and disclosed, so a report about them will get a pointer rather than a fix. That does
not make them uninteresting, and if you think the DISCLOSURE of one is wrong or
understated, that is very much worth reporting:

- **The app is served by the operator**, so a compelled or malicious operator could
  serve backdoored code, and no in-page check can detect that (section 1.4). This is why
  safety numbers, the reproducible build, and the transparency log exist.
- **Metadata is not hidden** from the operator: who talks to whom, when, and roughly how
  much (section 9). Sealed sender is a stated non-goal, and messages are not padded.
- **A short PIN is weak at rest** against an offline attack on a device image, and
  at-rest security is that of the weakest enrolled unlock method (section 8.5).
- **The identity key is not sealed at rest** (section 8.5), so an image of a locked
  device can still authenticate to the relay as its owner.
- **Delete-for-everyone and session-only messages depend on an honest client** on the
  other side, and neither is a guarantee (sections 8.6 and 8.7).
- **Deleting a conversation is not blocking**, which Nightjar does not have (8.9).

## Verifying what is actually deployed

Releases are built in a digest-pinned container from a committed lockfile, hashed with a
single documented recipe, and that hash is signed into a public append-only transparency
log before deployment. [docs/VERIFYING.md](docs/VERIFYING.md) explains how to rebuild a
release yourself and compare. If your finding depends on what is running rather than on
what is in the repository, that is the way to pin it down.
