import { describe, expect, it } from 'vitest'
import { generateIdentity } from '../crypto/identity'
import { bytesEqual } from '../crypto/primitives'
import { buildOwnBundle, generateOneTimePrekeys, generateSignedPrekey } from '../crypto/prekeys'
import { InMemoryLock } from './lock'
import { MemoryKeyStore } from './keystore'
import { PrekeyStore } from './prekeyStore'

const NOW = 1_700_000_000_000

async function fresh() {
  const id = generateIdentity()
  const own = buildOwnBundle(id, NOW, { spkId: 1, opkStartId: 1, opkCount: 3 })
  const prekeys = new PrekeyStore(new MemoryKeyStore(), new InMemoryLock())
  await prekeys.setFromRegistration({
    spk: { id: own.spk.id, createdAt: own.spk.createdAt, expiry: own.spk.expiry, pub: own.spk.pub, sig: own.spk.sig },
    spkPrivById: own.spkPrivById,
    opks: own.opks,
    opkPrivById: own.opkPrivById,
  })
  return { own, prekeys }
}

describe('PrekeyStore', () => {
  it('persists and looks up the signed prekey and one-time prekeys by id', async () => {
    const { own, prekeys } = await fresh()
    const keys = await prekeys.responderKeys()
    expect([...keys.spkPrivById.keys()]).toEqual([1])
    expect([...keys.opkPrivById.keys()].sort((a, b) => a - b)).toEqual([1, 2, 3])
    expect(bytesEqual(keys.spkPrivById.get(1)!, own.spkPrivById.get(1)!)).toBe(true)
    expect(bytesEqual(keys.spkPubById.get(1)!, own.spk.pub)).toBe(true)

    const kp = await prekeys.spkKeyPair(1)
    expect(kp).not.toBeNull()
    expect(bytesEqual(kp!.publicKey, own.spk.pub)).toBe(true)

    // The signed prekey round-trips to wire form (for OPK replenishment republish).
    const wire = await prekeys.signedPrekeyWire()
    expect(wire?.id).toBe(1)
    expect(wire?.sig).toBeTypeOf('string')
  })

  it('consumes a one-time prekey exactly once', async () => {
    const { prekeys } = await fresh()
    expect(await prekeys.availableOpkCount()).toBe(3)
    await prekeys.consumeOpk(2)
    expect(await prekeys.availableOpkCount()).toBe(2)
    const keys = await prekeys.responderKeys()
    expect(keys.opkPrivById.has(2)).toBe(false)
    // Consuming again is a no-op, not an error.
    await prekeys.consumeOpk(2)
    expect(await prekeys.availableOpkCount()).toBe(2)
  })

  it('appends replenishment prekeys without colliding ids', async () => {
    const { prekeys } = await fresh()
    expect(await prekeys.maxOpkId()).toBe(3)
    const more = generateOneTimePrekeys(4, 2).map((p) => ({ id: p.opk.id, priv: p.priv }))
    await prekeys.addOpks(more)
    expect(await prekeys.availableOpkCount()).toBe(5)
    expect(await prekeys.maxOpkId()).toBe(5)
    // Re-adding known ids does not duplicate.
    await prekeys.addOpks(more)
    expect(await prekeys.availableOpkCount()).toBe(5)
  })
})

describe('SPK rotation storage (P8)', () => {
  const DAY = 86_400_000

  async function withRotated() {
    const { own, prekeys } = await fresh()
    const id = generateIdentity()
    const rotated = generateSignedPrekey(id, 2, NOW + 8 * DAY)
    await prekeys.addSpk({
      id: 2,
      createdAt: rotated.spk.createdAt,
      expiry: rotated.spk.expiry,
      priv: rotated.priv,
      pub: rotated.spk.pub,
      sig: rotated.spk.sig,
    })
    return { own, prekeys }
  }

  it('addSpk keeps the old SPK and signedPrekeyWire returns the newest', async () => {
    const { prekeys } = await withRotated()
    const keys = await prekeys.responderKeys()
    expect([...keys.spkPrivById.keys()].sort((a, b) => a - b)).toEqual([1, 2])
    expect((await prekeys.signedPrekeyWire())?.id).toBe(2)
    expect((await prekeys.newestSpk())?.id).toBe(2)
    expect(await prekeys.maxSpkId()).toBe(2)
    // Both keypairs remain resolvable for in-flight initials.
    expect(await prekeys.spkKeyPair(1)).not.toBeNull()
    expect(await prekeys.spkKeyPair(2)).not.toBeNull()
  })

  it('rejects a duplicate SPK id', async () => {
    const { prekeys } = await withRotated()
    const id = generateIdentity()
    const dup = generateSignedPrekey(id, 2, NOW)
    await expect(
      prekeys.addSpk({ id: 2, createdAt: NOW, expiry: NOW + DAY, priv: dup.priv, pub: dup.spk.pub, sig: dup.spk.sig }),
    ).rejects.toThrow(/already stored/)
  })

  it('tracks the published SPK id only when marked', async () => {
    const { prekeys } = await withRotated()
    expect(await prekeys.publishedSpkId()).toBeNull()
    await prekeys.markSpkPublished(2)
    expect(await prekeys.publishedSpkId()).toBe(2)
  })

  it('pruneRetiredSpks drops an SPK only past expiry + grace, and never the newest', async () => {
    const { prekeys } = await withRotated()
    // SPK 1: createdAt NOW, expiry NOW+14d. Within grace (30d after expiry): kept.
    expect(await prekeys.pruneRetiredSpks(NOW + 20 * DAY)).toBe(0)
    // Past expiry + grace (~44d): pruned; SPK 2 remains.
    expect(await prekeys.pruneRetiredSpks(NOW + 60 * DAY)).toBe(1)
    const keys = await prekeys.responderKeys()
    expect([...keys.spkPrivById.keys()]).toEqual([2])
    // The newest survives any horizon.
    expect(await prekeys.pruneRetiredSpks(NOW + 500 * DAY)).toBe(0)
    expect((await prekeys.newestSpk())?.id).toBe(2)
  })
})
