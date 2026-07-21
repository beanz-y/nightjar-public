// Biometric app-lock via WebAuthn PRF (P10c). The platform authenticator holds a
// credential whose PRF extension yields a stable high-entropy secret ONLY after a
// successful user-verification (fingerprint/face/device PIN). That secret wraps
// the Local Data Key. There is no server: this is a local "unlock with your
// biometric" gate, so we use the authenticator purely as a PRF oracle.
//
// Red-team fix #2: on unlock we REQUIRE and then VERIFY user-verification (the UV
// flag in authenticatorData, mask 0x04), not merely user-presence, so a device
// thief who lacks the user's biometric cannot tap through.
//
// This cannot be exercised in the preview pane (no authenticator hardware); it is
// feature-detected and always paired with a passphrase/PIN fallback.

import { LOCK_PRF_INPUT } from '../crypto/constants'
import { randomBytes, utf8 } from '../crypto/primitives'

const PRF_EVAL = utf8(LOCK_PRF_INPUT) as BufferSource
const bs = (u: Uint8Array): BufferSource => u as BufferSource

/** Best-effort feature detection for platform authenticators + the PRF extension.
 *  Returns false where WebAuthn or PRF is unavailable (older browsers, no HTTPS,
 *  no platform authenticator), so the UI can hide the biometric option. */
export async function biometricAvailable(): Promise<boolean> {
  try {
    if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials) return false
    const uvpaa = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.()
    return uvpaa === true
  } catch {
    return false
  }
}

interface PrfExtResults {
  prf?: { results?: { first?: ArrayBuffer | Uint8Array } }
}

function prfFirst(cred: PublicKeyCredential): Uint8Array | null {
  const ext = cred.getClientExtensionResults() as unknown as PrfExtResults
  const first = ext?.prf?.results?.first
  if (!first) return null
  return first instanceof Uint8Array ? first : new Uint8Array(first)
}

/** Register a platform credential and derive its PRF secret. Returns the
 *  credential id (to target unlock) and the secret (to wrap the LDK). Throws with
 *  a human message when the browser/device cannot do PRF. */
export async function enrollBiometric(userId: string): Promise<{ credentialId: Uint8Array; prfSecret: Uint8Array }> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: bs(randomBytes(32)),
      rp: { name: 'Nightjar', id: location.hostname },
      user: { id: bs(utf8(userId).slice(0, 64)), name: `nightjar-${userId.slice(0, 8)}`, displayName: 'Nightjar' },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        userVerification: 'required',
      },
      timeout: 60_000,
      extensions: { prf: { eval: { first: PRF_EVAL } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null
  if (!cred) throw new Error('biometric enrollment was cancelled')
  const prfSecret = prfFirst(cred)
  if (!prfSecret) throw new Error('this device or browser does not support biometric PRF; use a passphrase or PIN')
  return { credentialId: new Uint8Array(cred.rawId), prfSecret }
}

/** Assert the enrolled credential and return its PRF secret, only after verifying
 *  that the authenticator performed USER VERIFICATION (not mere presence). */
export async function unlockBiometric(credentialId: Uint8Array): Promise<Uint8Array> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: bs(randomBytes(32)),
      allowCredentials: [{ type: 'public-key', id: bs(credentialId) }],
      userVerification: 'required',
      timeout: 60_000,
      extensions: { prf: { eval: { first: PRF_EVAL } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null
  if (!assertion) throw new Error('biometric unlock was cancelled')
  // Verify the UV flag in authenticatorData (byte offset 32, bit 0x04). Do not
  // trust the request option alone (red-team #2).
  const authData = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).authenticatorData)
  if (authData.length < 33 || (authData[32] & 0x04) === 0) {
    throw new Error('biometric unlock did not user-verify')
  }
  const prfSecret = prfFirst(assertion)
  if (!prfSecret) throw new Error('biometric PRF is unavailable on this device')
  return prfSecret
}
