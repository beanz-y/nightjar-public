import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { hash256 } from './primitives'
import {
  type Argon2Kdf,
  type BioWrap,
  type KnowledgeWrap,
  AppLockAuthError,
  LDK_BYTES,
  generateLdk,
  normalizeSecret,
  subKey,
  unwrapBiometric,
  unwrapKnowledge,
  wrapBiometric,
  wrapKnowledge,
} from './appLock'

// Fast deterministic stand-in for Argon2id so the suite stays quick (the real
// Argon2id at 64 MiB is exercised by backup.test.ts). It must depend on BOTH the
// secret and the salt, like a real KDF.
const stubKdf: Argon2Kdf = (secret, salt) => hash256(new Uint8Array([...secret, ...salt]))
const kdf = { kdf: stubKdf }

describe('app-lock key wrapping (P10c)', () => {
  it('round-trips the LDK under a knowledge factor', async () => {
    const ldk = generateLdk()
    expect(ldk.length).toBe(LDK_BYTES)
    const rec = await wrapKnowledge(ldk, 'correct horse battery staple', 'pass', kdf)
    const out = await unwrapKnowledge(rec, 'correct horse battery staple', stubKdf)
    expect(bytesToHex(out)).toBe(bytesToHex(ldk))
  })

  it('rejects the wrong secret with AppLockAuthError', async () => {
    const rec = await wrapKnowledge(generateLdk(), 'right-secret-123', 'pass', kdf)
    await expect(unwrapKnowledge(rec, 'wrong-secret-123', stubKdf)).rejects.toBeInstanceOf(AppLockAuthError)
  })

  it('uses fresh salts per wrap (no reuse even for the same LDK + secret)', async () => {
    const ldk = generateLdk()
    const a = (await wrapKnowledge(ldk, 's', 'pin', kdf)) as KnowledgeWrap
    const b = (await wrapKnowledge(ldk, 's', 'pin', kdf)) as KnowledgeWrap
    expect(bytesToHex(a.argonSalt)).not.toBe(bytesToHex(b.argonSalt))
    expect(bytesToHex(a.hkdfSalt)).not.toBe(bytesToHex(b.hkdfSalt))
    expect(bytesToHex(a.wrap)).not.toBe(bytesToHex(b.wrap))
    // Both still open.
    expect(bytesToHex(await unwrapKnowledge(a, 's', stubKdf))).toBe(bytesToHex(ldk))
    expect(bytesToHex(await unwrapKnowledge(b, 's', stubKdf))).toBe(bytesToHex(ldk))
  })

  it('a tampered wrap fails to open', async () => {
    const rec = (await wrapKnowledge(generateLdk(), 's', 'pass', kdf)) as KnowledgeWrap
    const bad = { ...rec, wrap: rec.wrap.slice() }
    bad.wrap[0] ^= 0xff
    await expect(unwrapKnowledge(bad, 's', stubKdf)).rejects.toBeInstanceOf(AppLockAuthError)
  })

  it('binds the method kind in the AAD: a pin record relabelled pass will not open', async () => {
    const rec = (await wrapKnowledge(generateLdk(), '123456', 'pin', kdf)) as KnowledgeWrap
    const relabelled = { ...rec, kind: 'pass' as const }
    await expect(unwrapKnowledge(relabelled, '123456', stubKdf)).rejects.toBeInstanceOf(AppLockAuthError)
  })

  it('round-trips the LDK under a biometric PRF secret, and rejects a wrong one', async () => {
    const ldk = generateLdk()
    const prf = hash256(new Uint8Array([1, 2, 3]))
    const credId = new Uint8Array([9, 9, 9])
    const rec = wrapBiometric(ldk, credId, prf) as BioWrap
    expect(bytesToHex(unwrapBiometric(rec, prf))).toBe(bytesToHex(ldk))
    const wrongPrf = hash256(new Uint8Array([4, 5, 6]))
    expect(() => unwrapBiometric(rec, wrongPrf)).toThrow(AppLockAuthError)
  })

  it('subKey: distinct info -> distinct keys, same info -> same key, length 32', () => {
    const ldk = generateLdk()
    const a = subKey(ldk, 'Nightjar_HistBody_v1')
    const b = subKey(ldk, 'Nightjar_Contacts_v1')
    const a2 = subKey(ldk, 'Nightjar_HistBody_v1')
    expect(a.length).toBe(32)
    expect(bytesToHex(a)).not.toBe(bytesToHex(b))
    expect(bytesToHex(a)).toBe(bytesToHex(a2))
    // A different LDK yields different sub-keys.
    expect(bytesToHex(subKey(generateLdk(), 'Nightjar_HistBody_v1'))).not.toBe(bytesToHex(a))
  })

  it('normalizeSecret applies NFC + trim', () => {
    // NFD "é" (e + combining acute) normalizes to NFC and trims surrounding space.
    expect(normalizeSecret('  é  ')).toBe('é')
  })
})
