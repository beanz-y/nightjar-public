// A real end-to-end exercise of the persistence stack (DESIGN P3). Runs a full
// X3DH + Double Ratchet exchange between two in-page parties THROUGH the durable
// SessionStore and the single-writer lock, including re-opening a session from
// storage to prove the state actually persisted and resumed. Used as the P3
// proof-of-life in the browser, where the real IndexedDB / Web Locks paths run.

import { generateIdentity } from '../crypto/identity'
import { utf8 } from '../crypto/primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { initRatchetInitiator, initRatchetResponder } from '../crypto/ratchet'
import { x3dhInitiate, x3dhRespond } from '../crypto/x3dh'
import type { Lock } from '../storage/lock'
import type { SessionStore } from '../storage/sessionStore'
import { RatchetSession } from './ratchetSession'

const decode = (b: Uint8Array): string => new TextDecoder().decode(b)

export async function runPersistedRatchetSelfTest(
  store: SessionStore,
  lock: Lock,
  now: number,
): Promise<{ ok: boolean; detail: string }> {
  const aliceId = generateIdentity()
  const bobId = generateIdentity()
  const own = buildOwnBundle(bobId, now, { spkId: 1, opkStartId: 1, opkCount: 1 })
  const bundle: FetchedBundle = {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opk: own.opks[0],
  }
  const ini = x3dhInitiate(aliceId, bundle, now)
  const res = x3dhRespond(bobId, ini.header, { spkPrivById: own.spkPrivById, opkPrivById: own.opkPrivById }, now)
  const bobSpkPriv = own.spkPrivById.get(1)
  if (!bobSpkPriv) return { ok: false, detail: 'self-test setup error: missing signed-prekey private' }

  const aliceState = initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub)
  const bobState = initRatchetResponder(res.sk, res.ad, { privateKey: bobSpkPriv, publicKey: bundle.spk.pub })

  // Unique keys per invocation so concurrent runs (e.g. React StrictMode's
  // double-invoked effect in dev) do not clobber each other's session state.
  const tag = crypto.randomUUID()
  const aliceKey = `selftest:${tag}:bob`
  const bobKey = `selftest:${tag}:alice`
  const alice = await RatchetSession.create(aliceKey, aliceState, store, lock)
  const bob = await RatchetSession.create(bobKey, bobState, store, lock)

  try {
    const e1 = await alice.encrypt(utf8('hello from alice'))
    const p1 = decode(await bob.decrypt(e1.header, e1.ciphertext))

    // Re-open Alice's session FROM STORAGE (a fresh instance) and send again:
    // proves the ratchet advanced state was persisted and resumed, not just held
    // in memory.
    const aliceResumed = RatchetSession.open(aliceKey, store, lock)
    const e2 = await aliceResumed.encrypt(utf8('second, from a resumed session'))
    const p2 = decode(await bob.decrypt(e2.header, e2.ciphertext))

    const ok = p1 === 'hello from alice' && p2 === 'second, from a resumed session'
    return {
      ok,
      detail: ok
        ? 'exchanged 2 messages through the persisted ratchet; the 2nd was sent from a session re-opened from storage'
        : `unexpected plaintext: "${p1}" / "${p2}"`,
    }
  } finally {
    await store.delete(aliceKey)
    await store.delete(bobKey)
  }
}
