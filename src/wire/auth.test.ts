import { describe, expect, it } from 'vitest'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { AUTH_CHALLENGE_TTL_MS } from '../crypto/constants'
import { deriveUserId, generateIdentity } from '../crypto/identity'
import { buildChallenge, challengeSigningInput, verifyAndSignChallenge, verifyAuthResponse } from './auth'

const ORIGIN = 'https://nightjar.example'
const CONN = 'conn-1'
const TS = 1_700_000_000_000
const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i)

// Independently computed (node) so a change to the canonical signing layout or
// the domain-separation framing is caught, not frozen from the code.
const KAT_SIGNING_INPUT =
  '000000104e696768746a61722d617574682d763100000010000102030405060708090a0b0c0d0e0f00000006636f6e6e2d310000001868747470733a2f2f6e696768746a61722e6578616d706c65000000080000018bcfe56800'
const KAT_SEED = Uint8Array.from({ length: 32 }, () => 0x42)
const KAT_IKSIG_PUB = '2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12'
const KAT_SIG =
  '2557a17ad4d7c4095ac3cafdf2bde90642f3953fa5534a71f0716029d15f7e4e92206c68c3bf481583c308ea21b912f8b5db9bce3621bc04c99be1cfbc294705'
const KAT_USERID = 'gcl6fxxcznfdjnjyidg3obno24igpq3pndnq4d2vtq7t7icdgfpq'

const fixedChallenge = () => buildChallenge(ORIGIN, CONN, TS, NONCE)

describe('buildChallenge', () => {
  it('carries the auth tag, origin, connection id and a 16-byte nonce', () => {
    const c = fixedChallenge()
    expect(c.tag).toBe('Nightjar-auth-v1')
    expect(c.origin).toBe(ORIGIN)
    expect(c.connectionId).toBe(CONN)
    expect(c.serverNonce).toBe('AAECAwQFBgcICQoLDA0ODw')
    expect(c.ts).toBe(TS)
  })
})

describe('challengeSigningInput', () => {
  it('matches the pinned canonical bytes (domain-separated, length-framed)', () => {
    expect(bytesToHex(challengeSigningInput(fixedChallenge()))).toBe(KAT_SIGNING_INPUT)
  })

  it('rejects a challenge whose tag is not the auth tag', () => {
    const c = { ...fixedChallenge(), tag: 'Nightjar-spk-v1' }
    expect(() => challengeSigningInput(c)).toThrow(/tag/)
  })
})

describe('sign + verify round trip', () => {
  it('a valid signature yields the correct authenticated user id', () => {
    const id = generateIdentity()
    const c = buildChallenge(ORIGIN, CONN, TS)
    const sig = verifyAndSignChallenge(c, ORIGIN, id.ikSig.privateKey, TS)
    const result = verifyAuthResponse(c, id.ikSig.publicKey, sig, TS)
    expect(result.userId).toBe(id.userId)
    expect(result.userId).toBe(deriveUserId(id.ikSig.publicKey))
  })

  it('produces the pinned deterministic signature and user id (Ed25519 KAT)', () => {
    const c = fixedChallenge()
    const sig = verifyAndSignChallenge(c, ORIGIN, KAT_SEED, TS)
    expect(bytesToHex(sig)).toBe(KAT_SIG)
    const result = verifyAuthResponse(c, hexToBytes(KAT_IKSIG_PUB), sig, TS)
    expect(result.userId).toBe(KAT_USERID)
  })
})

describe('client refuses to sign a bad challenge (origin binding is the point)', () => {
  const id = generateIdentity()

  it('refuses a challenge whose origin is not the connected origin', () => {
    const c = buildChallenge('https://evil.example', CONN, TS)
    expect(() => verifyAndSignChallenge(c, ORIGIN, id.ikSig.privateKey, TS)).toThrow(/origin/)
  })

  it('refuses a stale challenge', () => {
    const c = buildChallenge(ORIGIN, CONN, TS)
    expect(() => verifyAndSignChallenge(c, ORIGIN, id.ikSig.privateKey, TS + AUTH_CHALLENGE_TTL_MS + 1)).toThrow(
      /stale/,
    )
  })

  it('refuses a challenge dated in the future', () => {
    const c = buildChallenge(ORIGIN, CONN, TS + 60 * 60 * 1000)
    expect(() => verifyAndSignChallenge(c, ORIGIN, id.ikSig.privateKey, TS)).toThrow(/future/)
  })

  it('refuses a challenge missing the auth tag', () => {
    const c = { ...buildChallenge(ORIGIN, CONN, TS), tag: 'nope' }
    expect(() => verifyAndSignChallenge(c, ORIGIN, id.ikSig.privateKey, TS)).toThrow(/auth tag/)
  })
})

describe('server rejects a bad response', () => {
  it('rejects a signature by a different key', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    const c = buildChallenge(ORIGIN, CONN, TS)
    const sig = verifyAndSignChallenge(c, ORIGIN, a.ikSig.privateKey, TS)
    expect(() => verifyAuthResponse(c, b.ikSig.publicKey, sig, TS)).toThrow(/verify/)
  })

  it('rejects a tampered signature', () => {
    const id = generateIdentity()
    const c = buildChallenge(ORIGIN, CONN, TS)
    const sig = verifyAndSignChallenge(c, ORIGIN, id.ikSig.privateKey, TS)
    sig[0] ^= 0xff
    expect(() => verifyAuthResponse(c, id.ikSig.publicKey, sig, TS)).toThrow(/verify/)
  })

  it('rejects a signature made for a different challenge (nonce swap)', () => {
    const id = generateIdentity()
    const issued = buildChallenge(ORIGIN, CONN, TS)
    const other = buildChallenge(ORIGIN, CONN, TS) // fresh random nonce
    const sig = verifyAndSignChallenge(other, ORIGIN, id.ikSig.privateKey, TS)
    expect(() => verifyAuthResponse(issued, id.ikSig.publicKey, sig, TS)).toThrow(/verify/)
  })

  it('rejects an expired challenge even with a valid signature', () => {
    const id = generateIdentity()
    const c = buildChallenge(ORIGIN, CONN, TS)
    const sig = verifyAndSignChallenge(c, ORIGIN, id.ikSig.privateKey, TS)
    expect(() => verifyAuthResponse(c, id.ikSig.publicKey, sig, TS + AUTH_CHALLENGE_TTL_MS + 1)).toThrow(
      /expired/,
    )
  })
})
