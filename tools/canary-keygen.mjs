#!/usr/bin/env node
// Generate the warrant-canary signing keypair ONCE (P7, DESIGN 10). Run it,
// then:
//   - paste the PUBLIC key into src/verify/canaryKey.ts (CANARY_PUBKEY_B64) and
//     commit it: being source is what puts the pin under the reproducible build.
//   - store the PRIVATE key OFFLINE (a password manager / an encrypted note). It
//     never touches the server; it is used only by tools/canary-sign.mjs to sign
//     each ~monthly canary. If it is lost, ship a release that empties
//     CANARY_PUBKEY_B64 (verifier -> `unconfigured`, benign) and re-enable with a
//     fresh key later (DESIGN 10). Never keep a copy on the relay host.

import { ed25519 } from '@noble/curves/ed25519'
import { base64urlnopad } from '@scure/base'

const priv = ed25519.utils.randomSecretKey()
const pub = ed25519.getPublicKey(priv)

process.stdout.write(
  [
    '# Nightjar canary keypair (Ed25519). Keep the PRIVATE key offline.',
    '',
    `CANARY_PUBKEY_B64  (commit into src/verify/canaryKey.ts):`,
    base64urlnopad.encode(pub),
    '',
    `CANARY_PRIVATE_KEY (store OFFLINE; export it when signing):`,
    base64urlnopad.encode(priv),
    '',
  ].join('\n'),
)
