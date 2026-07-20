# Verifying a Nightjar build

Nightjar is a web app served by its operator, so in principle the operator could
serve backdoored code (DESIGN.md section 1.4 and 10 are honest about this). What
this document lets a technical person do is confirm that the JavaScript the site
serves was built from this public source, and that its hash is recorded in a
public append-only transparency log. That makes a *broad* (identical-to-everyone)
backdoor publicly falsifiable by anyone who bothers to rebuild and diff. It does
NOT stop a *targeted* backdoor served to one person; only out-of-band
safety-number verification (DESIGN section 6) addresses the key-substitution
attack, and it remains the single most important thing a user can do.

## How the pipeline works

Every deploy runs `.github/workflows/release.yml` on a push to `main`:

1. A gate job runs the full test suites (`npm test`, `npm run test:worker`) and
   both typechecks. Production never receives a build whose KAT-locked crypto
   suite did not just pass.
2. The app is built **once** inside a digest-pinned container
   (`Dockerfile.build`), producing `dist/`.
3. `scripts/release-hash.mjs` computes the canonical release hash over that
   `dist/`.
4. `cosign` keyless-signs the manifest into the public-good **Rekor** log. The
   signer identity is this repository's workflow OIDC token; Rekor is
   append-only.
5. `wrangler deploy` uploads **that same** `dist/` (Model A: audited == logged ==
   served).

The version string comes from the committed `VERSION` file, not from a tag, so a
redeploy of unchanged source is byte-identical and the in-app warrant canary that
attests `{version, releaseHash}` stays valid without a re-sign.

## The canonical release hash

One recipe, defined in `scripts/release-hash.mjs`: for every file under `dist/`,
`sha256(file)` and its `/`-joined relative path form a line
`<sha256hex>  <relpath>`; the lines are byte-sorted (LC_ALL=C), joined with LF
into `manifest.txt`, and the release hash is `sha256(manifest.txt)`.

## How to verify a running build

1. Clone this repository at the deployed commit on a machine whose git checks out
   **LF** line endings (the repo ships `.gitattributes` with `eol=lf`; a CRLF
   checkout will not match). The deployed commit is the one recorded on the
   GitHub Actions run; the run's artifact name also carries the release hash.

2. Rebuild in the pinned container and print the hash (`vX.Y.Z` = the `VERSION`
   file's value at that commit):

   ```sh
   docker build -f Dockerfile.build --build-arg NIGHTJAR_VERSION=vX.Y.Z -t njb .
   cid=$(docker create njb); docker cp "$cid:/app/dist" ./dist; docker rm "$cid"
   node scripts/release-hash.mjs dist
   ```

   Pure-shell equivalent (no Node), which produces a byte-identical
   `manifest.txt`:

   ```sh
   ( cd dist && LC_ALL=C find . -type f | sed 's|^\./||' | LC_ALL=C sort \
     | while IFS= read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done ) > manifest.txt
   sha256sum manifest.txt   # the release hash
   ```

   Write the pipeline straight to a file as shown; capturing it in `$(...)` strips
   the trailing newline and changes the hash.

3. Confirm that hash equals all of: the hash the running app's canary vouches for
   (the "verify build" / About view), the hash on the corresponding Actions run
   artifact, and the bytes actually served (compare the served
   `assets/*.js`/`.css` against your rebuilt `dist/`, or their Subresource
   Integrity attributes in the served `index.html`). Find the **Rekor** entry
   independently by the artifact digest plus this repo's workflow identity and
   issuer; the cosign bundle self-verifies offline, so Rekor need not be
   reachable at verify time.

## Three honest limits

- Reproducibility proves the binary matches the **source**, not that the source
  is honest: a backdoor committed to public source reproduces perfectly.
- A malicious **pinned dependency or toolchain** also reproduces perfectly and
  passes the diff; the determinism check is a nondeterminism check, not a
  supply-chain proof.
- Rekor is **append-only** (an honest entry cannot be deleted or backdated), but
  its keyless signer is this repo's CI, which a compelled operator controls. An
  entry therefore attests "this repo's CI logged hash H at time T", never "the
  build is honest", and it does not bind the bytes any individual user was
  actually **served**.

For the strongest available check, a technical friend can rebuild on every
release and compare; pairing that with in-person safety-number verification
covers both the code-substitution and the key-substitution attacks that a
compelled operator could otherwise run.
