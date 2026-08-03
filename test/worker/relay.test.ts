import { SELF, env, runInDurableObject } from 'cloudflare:test'
import { describe, expect, it, vi } from 'vitest'
import { MAX_DELIVERED_CHECK_IDS, MAX_PUSH_SUBS } from '../../src/crypto/constants'
import { type Identity, deviceIdOf, generateIdentity } from '../../src/crypto/identity'
import { utf8 } from '../../src/crypto/primitives'
import { OWN_BUNDLE_VERSION, buildOwnBundle, generateSignedPrekey, verifyFetchedBundle } from '../../src/crypto/prekeys'
import { initRatchetInitiator, initRatchetResponder, ratchetDecrypt, ratchetEncrypt } from '../../src/crypto/ratchet'
import { x3dhInitiate, x3dhRespond } from '../../src/crypto/x3dh'
import { signRoster } from '../../src/crypto/roster'
import { verifyAndSignChallenge } from '../../src/wire/auth'
import {
  type WireEnvelope,
  b64decode,
  b64encode,
  decodeFetchedBundle,
  decodeInitialHeader,
  decodeMessageHeaderWire,
  encodeDeviceRoster,
  encodeInitialHeader,
  encodeMessageHeaderWire,
  encodePublishedBundle,
} from '../../src/wire/codec'
import type { ServerMessage } from '../../src/wire/messages'

const BASE = 'http://example.com'
const ORIGIN = 'http://example.com'
const decode = (b: Uint8Array) => new TextDecoder().decode(b)
let seq = 0
const nextReq = () => `req-${seq++}`

// A minimal promise-driven client over the hibernation WebSocket. It buffers
// unsolicited server messages (e.g. `deliver`) so a later waitFor can pick them
// up in any order.
class Conn {
  private readonly queue: ServerMessage[] = []
  private readonly waiters: Array<{ pred: (m: ServerMessage) => boolean; resolve: (m: ServerMessage) => void }> = []

  constructor(private readonly ws: WebSocket) {
    ws.accept()
    ws.addEventListener('message', (e) => {
      const m = JSON.parse(e.data as string) as ServerMessage
      const i = this.waiters.findIndex((w) => w.pred(m))
      if (i >= 0) {
        const [w] = this.waiters.splice(i, 1)
        w.resolve(m)
      } else {
        this.queue.push(m)
      }
    })
  }

  send(m: unknown): void {
    this.ws.send(JSON.stringify(m))
  }

  waitPred(pred: (m: ServerMessage) => boolean): Promise<ServerMessage> {
    const i = this.queue.findIndex(pred)
    if (i >= 0) return Promise.resolve(this.queue.splice(i, 1)[0])
    return new Promise((resolve) => this.waiters.push({ pred, resolve }))
  }

  waitFor<T extends ServerMessage['t']>(t: T): Promise<Extract<ServerMessage, { t: T }>> {
    return this.waitPred((m) => m.t === t) as Promise<Extract<ServerMessage, { t: T }>>
  }

  close(): void {
    this.ws.close()
  }
}

// Connect the way the client now does: userId in the Sec-WebSocket-Protocol
// subprotocol, NOT the URL (keeps it out of request logs).
async function connect(userId: string): Promise<Conn> {
  const res = await SELF.fetch(`${BASE}/connect`, {
    headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': userId },
  })
  const ws = res.webSocket
  if (!ws) throw new Error(`no webSocket in response (status ${res.status})`)
  return new Conn(ws)
}

// The legacy query-param path, still accepted during rollout for a client loaded
// before the subprotocol change.
async function connectLegacy(userId: string): Promise<Conn> {
  const res = await SELF.fetch(`${BASE}/connect?u=${userId}`, { headers: { Upgrade: 'websocket' } })
  const ws = res.webSocket
  if (!ws) throw new Error(`no webSocket in response (status ${res.status})`)
  return new Conn(ws)
}

async function connectAndAuth(id: Identity): Promise<Conn> {
  const conn = await connect(id.userId)
  const ch = await conn.waitFor('challenge')
  const sig = verifyAndSignChallenge(ch.challenge, ORIGIN, id.ikSig.privateKey, Date.now())
  conn.send({ t: 'auth', ikSigPub: b64encode(id.ikSig.publicKey), sig: b64encode(sig) })
  await conn.waitFor('authed')
  return conn
}

async function adminInvite(): Promise<string> {
  const res = await SELF.fetch(`${BASE}/admin/invite`, {
    method: 'POST',
    headers: { Authorization: 'Bearer test-admin-token' },
  })
  const j = (await res.json()) as { code: string }
  return j.code
}

type OwnBundle = ReturnType<typeof buildOwnBundle>

function ownBundleFor(id: Identity): OwnBundle {
  return buildOwnBundle(id, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 5 })
}

async function register(conn: Conn, own: OwnBundle, inviteCode: string): Promise<ServerMessage> {
  const bundle = encodePublishedBundle({
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opks: own.opks,
  })
  const reqId = nextReq()
  conn.send({ t: 'register', reqId, inviteCode, bundle })
  return conn.waitPred((m) => (m.t === 'registered' || m.t === 'error') && (m as { reqId?: string }).reqId === reqId)
}

describe('health + admin', () => {
  it('serves /health', async () => {
    const res = await SELF.fetch(`${BASE}/health`)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
  })

  it('mints an admin invite with the token, rejects a bad token', async () => {
    const ok = await SELF.fetch(`${BASE}/admin/invite`, {
      method: 'POST',
      headers: { Authorization: 'Bearer test-admin-token' },
    })
    expect(ok.status).toBe(200)
    const bad = await SELF.fetch(`${BASE}/admin/invite`, {
      method: 'POST',
      headers: { Authorization: 'Bearer wrong' },
    })
    expect(bad.status).toBe(401)
  })
})

describe('auth handshake', () => {
  it('rejects a connect with a malformed user id', async () => {
    const res = await SELF.fetch(`${BASE}/connect?u=not-a-user-id`, { headers: { Upgrade: 'websocket' } })
    expect(res.status).toBe(400)
  })

  it('routes by the subprotocol and echoes it on the 101', async () => {
    const id = generateIdentity()
    const res = await SELF.fetch(`${BASE}/connect`, {
      headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': id.userId },
    })
    const ws = res.webSocket
    if (!ws) throw new Error(`no webSocket (status ${res.status})`)
    // The 101 must echo the negotiated subprotocol or strict browsers abort (1006).
    expect(res.headers.get('Sec-WebSocket-Protocol')).toBe(id.userId)
    const conn = new Conn(ws)
    const ch = await conn.waitFor('challenge')
    const sig = verifyAndSignChallenge(ch.challenge, ORIGIN, id.ikSig.privateKey, Date.now())
    conn.send({ t: 'auth', ikSigPub: b64encode(id.ikSig.publicKey), sig: b64encode(sig) })
    await conn.waitFor('authed')
    conn.close()
  })

  it('still accepts the legacy ?u= query param during rollout', async () => {
    const id = generateIdentity()
    const conn = await connectLegacy(id.userId)
    const ch = await conn.waitFor('challenge')
    const sig = verifyAndSignChallenge(ch.challenge, ORIGIN, id.ikSig.privateKey, Date.now())
    conn.send({ t: 'auth', ikSigPub: b64encode(id.ikSig.publicKey), sig: b64encode(sig) })
    await conn.waitFor('authed')
    conn.close()
  })

  it('rejects a forged signature and closes', async () => {
    const id = generateIdentity()
    const conn = await connect(id.userId)
    const ch = await conn.waitFor('challenge')
    const sig = verifyAndSignChallenge(ch.challenge, ORIGIN, id.ikSig.privateKey, Date.now())
    sig[0] ^= 0xff // tamper
    conn.send({ t: 'auth', ikSigPub: b64encode(id.ikSig.publicKey), sig: b64encode(sig) })
    const err = await conn.waitFor('error')
    expect(err.code).toBe('auth_failed')
  })

  it('rejects authing to another user’s inbox (identity mismatch)', async () => {
    const owner = generateIdentity()
    const attacker = generateIdentity()
    // Connect to the OWNER's inbox but sign with the ATTACKER's key.
    const conn = await connect(owner.userId)
    const ch = await conn.waitFor('challenge')
    const sig = verifyAndSignChallenge(ch.challenge, ORIGIN, attacker.ikSig.privateKey, Date.now())
    conn.send({ t: 'auth', ikSigPub: b64encode(attacker.ikSig.publicKey), sig: b64encode(sig) })
    const err = await conn.waitFor('error')
    expect(err.code).toBe('identity_mismatch')
  })

  it('rejects an app message before authentication', async () => {
    const id = generateIdentity()
    const conn = await connect(id.userId)
    await conn.waitFor('challenge')
    conn.send({ t: 'mintInvite', reqId: nextReq() })
    const err = await conn.waitFor('error')
    expect(err.code).toBe('unauthenticated')
  })
})

describe('registration + invites', () => {
  it('registers behind an admin invite and reports opk count', async () => {
    const id = generateIdentity()
    const conn = await connectAndAuth(id)
    const invite = await adminInvite()
    const m = await register(conn, ownBundleFor(id), invite)
    expect(m.t).toBe('registered')
    expect((m as { opkCount: number }).opkCount).toBe(5)
  })

  it('rejects a second registration on the same single-use invite', async () => {
    const invite = await adminInvite()
    const a = generateIdentity()
    const b = generateIdentity()
    const aConn = await connectAndAuth(a)
    const bConn = await connectAndAuth(b)
    expect((await register(aConn, ownBundleFor(a), invite)).t).toBe('registered')
    const second = await register(bConn, ownBundleFor(b), invite)
    expect(second.t).toBe('error')
    expect((second as { code: string }).code).toBe('invite_used')
  })

  it('serialises a concurrent race for one invite to exactly one winner', async () => {
    const invite = await adminInvite()
    const a = generateIdentity()
    const b = generateIdentity()
    const aConn = await connectAndAuth(a)
    const bConn = await connectAndAuth(b)
    const [ra, rb] = await Promise.all([
      register(aConn, ownBundleFor(a), invite),
      register(bConn, ownBundleFor(b), invite),
    ])
    const outcomes = [ra.t, rb.t].sort()
    expect(outcomes).toEqual(['error', 'registered'])
  })

  it('refuses to mint an invite before the user is registered', async () => {
    const id = generateIdentity()
    const conn = await connectAndAuth(id)
    const reqId = nextReq()
    conn.send({ t: 'mintInvite', reqId })
    const err = await conn.waitPred((m) => m.t === 'error' && (m as { reqId?: string }).reqId === reqId)
    expect((err as { code: string }).code).toBe('not_registered')
  })

  it('lets a registered user mint an invite that a newcomer redeems', async () => {
    const inviter = generateIdentity()
    const iConn = await connectAndAuth(inviter)
    await register(iConn, ownBundleFor(inviter), await adminInvite())
    const reqId = nextReq()
    iConn.send({ t: 'mintInvite', reqId })
    const inviteMsg = await iConn.waitFor('invite')
    expect(inviteMsg.inviterFingerprint).toBe(inviter.userId)

    const newcomer = generateIdentity()
    const nConn = await connectAndAuth(newcomer)
    expect((await register(nConn, ownBundleFor(newcomer), inviteMsg.code)).t).toBe('registered')
  })
})

describe('mutual invite (inviteRedemptions)', () => {
  async function inviteRedemptions(conn: Conn): Promise<string[]> {
    const reqId = nextReq()
    conn.send({ t: 'inviteRedemptions', reqId })
    const m = await conn.waitPred((x) => x.t === 'redemptions' && (x as { reqId?: string }).reqId === reqId)
    return (m as { joiners: string[] }).joiners
  }

  it('reports the server-verified joiner, scoped to the inviter’s own invites', async () => {
    const inviter = generateIdentity()
    const iConn = await connectAndAuth(inviter)
    await register(iConn, ownBundleFor(inviter), await adminInvite())

    // Before anyone redeems, the inviter has no joiners.
    expect(await inviteRedemptions(iConn)).toEqual([])

    const reqId = nextReq()
    iConn.send({ t: 'mintInvite', reqId })
    const inviteMsg = await iConn.waitFor('invite')

    const joiner = generateIdentity()
    const jConn = await connectAndAuth(joiner)
    expect((await register(jConn, ownBundleFor(joiner), inviteMsg.code)).t).toBe('registered')

    // Now the inviter learns the joiner from the server-verified used_by stamp.
    expect(await inviteRedemptions(iConn)).toEqual([joiner.userId])

    // A different registered user cannot read the inviter’s joiners: the query is
    // scoped to the caller’s challenge-verified id, never a client claim.
    const other = generateIdentity()
    const oConn = await connectAndAuth(other)
    await register(oConn, ownBundleFor(other), await adminInvite())
    expect(await inviteRedemptions(oConn)).toEqual([])
  })

  it('returns an empty list for an authenticated-but-unregistered user', async () => {
    const id = generateIdentity()
    const conn = await connectAndAuth(id)
    expect(await inviteRedemptions(conn)).toEqual([])
  })
})

describe('OPK vending', () => {
  it('returns the SAME OPK to a repeated fetch by one fetcher (anti-depletion)', async () => {
    const bob = generateIdentity()
    const bConn = await connectAndAuth(bob)
    await register(bConn, ownBundleFor(bob), await adminInvite())

    const alice = generateIdentity()
    const aConn = await connectAndAuth(alice)
    await register(aConn, ownBundleFor(alice), await adminInvite())

    const fetchBundle = async () => {
      const reqId = nextReq()
      aConn.send({ t: 'fetchBundle', reqId, target: bob.userId })
      return aConn.waitPred((m) => m.t === 'bundle' && (m as { reqId?: string }).reqId === reqId)
    }
    const b1 = (await fetchBundle()) as Extract<ServerMessage, { t: 'bundle' }>
    const b2 = (await fetchBundle()) as Extract<ServerMessage, { t: 'bundle' }>
    expect(b1.bundle?.opk?.id).toBeTypeOf('number')
    expect(b2.bundle?.opk?.id).toBe(b1.bundle?.opk?.id)
  })

  it('vends distinct OPKs to distinct fetchers and degrades when depleted', async () => {
    // Bob registers with exactly ONE one-time prekey.
    const bob = generateIdentity()
    const bOwn = buildOwnBundle(bob, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 1 })
    const bConn = await connectAndAuth(bob)
    await register(bConn, bOwn, await adminInvite())

    const fetchAs = async (fetcher: Identity) => {
      const conn = await connectAndAuth(fetcher)
      await register(conn, ownBundleFor(fetcher), await adminInvite())
      const reqId = nextReq()
      conn.send({ t: 'fetchBundle', reqId, target: bob.userId })
      return (await conn.waitPred(
        (m) => m.t === 'bundle' && (m as { reqId?: string }).reqId === reqId,
      )) as Extract<ServerMessage, { t: 'bundle' }>
    }
    const first = await fetchAs(generateIdentity())
    const second = await fetchAs(generateIdentity())
    expect(first.bundle?.opk).not.toBeNull()
    expect(first.degraded).toBe(false)
    // Only one OPK existed; the second fetcher gets the no-OPK (degraded) path.
    expect(second.bundle?.opk).toBeNull()
    expect(second.degraded).toBe(true)
  })
})

describe('end-to-end messaging through the relay', () => {
  it('delivers an initial X3DH message and a ratchet reply', async () => {
    const alice = generateIdentity()
    const bob = generateIdentity()
    const aConn = await connectAndAuth(alice)
    const bConn = await connectAndAuth(bob)
    await register(aConn, ownBundleFor(alice), await adminInvite())
    const bOwn = ownBundleFor(bob)
    await register(bConn, bOwn, await adminInvite())

    // Alice fetches Bob's bundle and runs X3DH.
    const fReq = nextReq()
    aConn.send({ t: 'fetchBundle', reqId: fReq, target: bob.userId })
    const bundleMsg = (await aConn.waitPred(
      (m) => m.t === 'bundle' && (m as { reqId?: string }).reqId === fReq,
    )) as Extract<ServerMessage, { t: 'bundle' }>
    const fetched = decodeFetchedBundle(bundleMsg.bundle!)

    const ini = x3dhInitiate(alice, fetched, Date.now())
    let aState = initRatchetInitiator(ini.sk, ini.ad, fetched.spk.pub)
    const enc1 = ratchetEncrypt(aState, utf8('hello bob'))
    aState = enc1.state
    aConn.send({
      t: 'send',
      to: bob.userId,
      env: {
        id: 'm1',
        kind: 'initial',
        header: encodeMessageHeaderWire(enc1.header),
        ciphertext: b64encode(enc1.ciphertext),
        initialHeader: encodeInitialHeader(ini.header),
      } satisfies WireEnvelope,
    })
    expect((await aConn.waitFor('sent')).id).toBe('m1')

    // Bob receives, runs X3DH respond + ratchet, decrypts, acks.
    const deliver = await bConn.waitFor('deliver')
    const wEnv = deliver.env
    const ih = decodeInitialHeader(wEnv.initialHeader!)
    const resp = x3dhRespond(
      bob,
      ih,
      { spkPrivById: bOwn.spkPrivById, opkPrivById: bOwn.opkPrivById },
      Date.now(),
    )
    let bState = initRatchetResponder(resp.sk, resp.ad, {
      privateKey: bOwn.spkPrivById.get(1)!,
      publicKey: bOwn.spk.pub,
    })
    const dec1 = ratchetDecrypt(bState, decodeMessageHeaderWire(wEnv.header), b64decode(wEnv.ciphertext))
    bState = dec1.state
    expect(decode(dec1.plaintext)).toBe('hello bob')
    bConn.send({ t: 'ack', id: wEnv.id })

    // Bob replies; Alice receives and decrypts.
    const enc2 = ratchetEncrypt(bState, utf8('hi alice'))
    bState = enc2.state
    bConn.send({
      t: 'send',
      to: alice.userId,
      env: {
        id: 'm2',
        kind: 'normal',
        header: encodeMessageHeaderWire(enc2.header),
        ciphertext: b64encode(enc2.ciphertext),
      } satisfies WireEnvelope,
    })
    const deliver2 = await aConn.waitFor('deliver')
    const dec2 = ratchetDecrypt(
      aState,
      decodeMessageHeaderWire(deliver2.env.header),
      b64decode(deliver2.env.ciphertext),
    )
    expect(decode(dec2.plaintext)).toBe('hi alice')
  })

  it('rejects a send from an unregistered sender (relay gated on registration)', async () => {
    const alice = generateIdentity() // never registers
    const bob = generateIdentity()
    const aConn = await connectAndAuth(alice)
    const bConn = await connectAndAuth(bob)
    await register(bConn, ownBundleFor(bob), await adminInvite())
    aConn.send({
      t: 'send',
      to: bob.userId,
      env: {
        id: 'x1',
        kind: 'normal',
        header: encodeMessageHeaderWire({ version: 1, dhPub: new Uint8Array(32), pn: 0, n: 0 }),
        ciphertext: b64encode(new Uint8Array(16)),
      } satisfies WireEnvelope,
    })
    const err = await aConn.waitFor('error')
    expect(err.code).toBe('not_registered')
  })

  it('refreshes OPKs on re-registration so a new inbound session still decrypts', async () => {
    const bob = generateIdentity()
    const bConn = await connectAndAuth(bob)
    // First registration, then a re-registration with a FRESH prekey set (same
    // key, new OPK keypairs at the same ids). The directory must serve the new
    // OPK publics, not the stale ones.
    expect((await register(bConn, ownBundleFor(bob), await adminInvite())).t).toBe('registered')
    const bOwn = ownBundleFor(bob)
    expect((await register(bConn, bOwn, 'ignored-on-reregister')).t).toBe('registered')

    const alice = generateIdentity()
    const aConn = await connectAndAuth(alice)
    await register(aConn, ownBundleFor(alice), await adminInvite())
    const fReq = nextReq()
    aConn.send({ t: 'fetchBundle', reqId: fReq, target: bob.userId })
    const bundleMsg = (await aConn.waitPred(
      (m) => m.t === 'bundle' && (m as { reqId?: string }).reqId === fReq,
    )) as Extract<ServerMessage, { t: 'bundle' }>
    const fetched = decodeFetchedBundle(bundleMsg.bundle!)

    const ini = x3dhInitiate(alice, fetched, Date.now())
    const enc = ratchetEncrypt(initRatchetInitiator(ini.sk, ini.ad, fetched.spk.pub), utf8('after re-register'))
    aConn.send({
      t: 'send',
      to: bob.userId,
      env: {
        id: 'rr1',
        kind: 'initial',
        header: encodeMessageHeaderWire(enc.header),
        ciphertext: b64encode(enc.ciphertext),
        initialHeader: encodeInitialHeader(ini.header),
      } satisfies WireEnvelope,
    })
    const deliver = await bConn.waitFor('deliver')
    const ih = decodeInitialHeader(deliver.env.initialHeader!)
    // Bob responds with the FRESH prekey material (bOwn); if the directory had
    // kept the stale OPK pub, DH4 would diverge and this decrypt would throw.
    const resp = x3dhRespond(bob, ih, { spkPrivById: bOwn.spkPrivById, opkPrivById: bOwn.opkPrivById }, Date.now())
    const dec = ratchetDecrypt(
      initRatchetResponder(resp.sk, resp.ad, { privateKey: bOwn.spkPrivById.get(1)!, publicKey: bOwn.spk.pub }),
      decodeMessageHeaderWire(deliver.env.header),
      b64decode(deliver.env.ciphertext),
    )
    expect(decode(dec.plaintext)).toBe('after re-register')
  })

  it('clears a re-registered fetcher\'s prior vends so a re-fetch does not re-serve a consumed OPK (Phase D)', async () => {
    // The vend cache is idempotent per (fetcher, target): a repeat fetch returns
    // the SAME one-time prekey, whose private half the target consumed on the
    // first handshake. After a MOVE, the fetcher re-registers; if that vend
    // survived, its next fetch would be handed the already-consumed OPK and the
    // new session would never decrypt. Re-registration must clear vends where
    // this user is the FETCHER, so the re-fetch vends a fresh OPK.
    const bob = generateIdentity()
    const bConn = await connectAndAuth(bob)
    expect((await register(bConn, ownBundleFor(bob), await adminInvite())).t).toBe('registered')

    const alice = generateIdentity()
    const aConn = await connectAndAuth(alice)
    await register(aConn, ownBundleFor(alice), await adminInvite())

    const fetchOpkId = async (): Promise<number | null> => {
      const req = nextReq()
      aConn.send({ t: 'fetchBundle', reqId: req, target: bob.userId })
      const msg = (await aConn.waitPred(
        (m) => m.t === 'bundle' && (m as { reqId?: string }).reqId === req,
      )) as Extract<ServerMessage, { t: 'bundle' }>
      return decodeFetchedBundle(msg.bundle!).opk?.id ?? null
    }

    const first = await fetchOpkId()
    expect(first).not.toBeNull()
    // Same fetcher, no re-register: idempotent vend returns the SAME id.
    expect(await fetchOpkId()).toBe(first)

    // Alice re-registers (the move's fresh prekey publish), then re-fetches.
    await register(aConn, ownBundleFor(alice), 'ignored-on-reregister')
    const afterReregister = await fetchOpkId()
    expect(afterReregister).not.toBeNull()
    expect(afterReregister).not.toBe(first)
  })

  it('queues while offline and drains on reconnect, then ack-drops a replay', async () => {
    const alice = generateIdentity()
    const bob = generateIdentity()
    const aConn = await connectAndAuth(alice)
    await register(aConn, ownBundleFor(alice), await adminInvite())
    const bOwn = ownBundleFor(bob)
    // Bob registers, then disconnects (offline).
    const bConn0 = await connectAndAuth(bob)
    await register(bConn0, bOwn, await adminInvite())
    bConn0.close()

    // Alice fetches + sends while Bob is offline.
    const fReq = nextReq()
    aConn.send({ t: 'fetchBundle', reqId: fReq, target: bob.userId })
    const bundleMsg = (await aConn.waitPred(
      (m) => m.t === 'bundle' && (m as { reqId?: string }).reqId === fReq,
    )) as Extract<ServerMessage, { t: 'bundle' }>
    const fetched = decodeFetchedBundle(bundleMsg.bundle!)
    const ini = x3dhInitiate(alice, fetched, Date.now())
    const enc = ratchetEncrypt(initRatchetInitiator(ini.sk, ini.ad, fetched.spk.pub), utf8('offline hello'))
    aConn.send({
      t: 'send',
      to: bob.userId,
      env: {
        id: 'q1',
        kind: 'initial',
        header: encodeMessageHeaderWire(enc.header),
        ciphertext: b64encode(enc.ciphertext),
        initialHeader: encodeInitialHeader(ini.header),
      } satisfies WireEnvelope,
    })
    expect((await aConn.waitFor('sent')).id).toBe('q1')

    // Bob reconnects and drains the queued message.
    const bConn1 = await connectAndAuth(bob)
    const deliver = await bConn1.waitFor('deliver')
    expect(deliver.env.id).toBe('q1')
    const ih = decodeInitialHeader(deliver.env.initialHeader!)
    const resp = x3dhRespond(bob, ih, { spkPrivById: bOwn.spkPrivById, opkPrivById: bOwn.opkPrivById }, Date.now())
    const dec = ratchetDecrypt(
      initRatchetResponder(resp.sk, resp.ad, { privateKey: bOwn.spkPrivById.get(1)!, publicKey: bOwn.spk.pub }),
      decodeMessageHeaderWire(deliver.env.header),
      b64decode(deliver.env.ciphertext),
    )
    expect(decode(dec.plaintext)).toBe('offline hello')
    bConn1.send({ t: 'ack', id: 'q1' })

    // Alice retransmits the byte-identical envelope (lost `sent`); the relay must
    // ack-and-drop it, never re-deliver to Bob.
    aConn.send({
      t: 'send',
      to: bob.userId,
      env: {
        id: 'q1',
        kind: 'initial',
        header: encodeMessageHeaderWire(enc.header),
        ciphertext: b64encode(enc.ciphertext),
        initialHeader: encodeInitialHeader(ini.header),
      } satisfies WireEnvelope,
    })
    expect((await aConn.waitFor('sent')).id).toBe('q1')
    // Give the relay a beat; Bob must NOT receive a second delivery.
    let redelivered = false
    void bConn1.waitFor('deliver').then(() => {
      redelivered = true
    })
    await new Promise((r) => setTimeout(r, 100))
    expect(redelivered).toBe(false)
  })
})

// The delivery indicator. The relay reports what it already knows (an envelope was
// picked up and dropped from the queue), so the tests check exactly that: the live
// report reaches a connected sender, and a sender who was away can ask afterwards.
// Nothing is stored for either: no delivery log is created (DESIGN 7.5).
describe('delivery reporting', () => {
  async function pair() {
    const alice = generateIdentity()
    const bob = generateIdentity()
    const aConn = await connectAndAuth(alice)
    const bConn = await connectAndAuth(bob)
    await register(aConn, ownBundleFor(alice), await adminInvite())
    await register(bConn, ownBundleFor(bob), await adminInvite())
    return { alice, bob, aConn, bConn }
  }
  // The relay structurally validates every envelope, so these carry a real header
  // and ciphertext. The contents are irrelevant here: nothing decrypts them.
  const envelope = (id: string): WireEnvelope => ({
    id,
    kind: 'normal',
    header: encodeMessageHeaderWire({ version: 1, dhPub: new Uint8Array(32), pn: 0, n: 0 }),
    ciphertext: b64encode(new Uint8Array(16)),
  })

  it('tells a connected sender when the recipient picks a message up', async () => {
    const { alice, bob, aConn, bConn } = await pair()
    aConn.send({ t: 'send', to: bob.userId, env: envelope('d1') })
    expect((await aConn.waitFor('sent')).id).toBe('d1')
    const deliver = await bConn.waitFor('deliver')
    bConn.send({ t: 'ack', id: deliver.env.id })
    const report = await aConn.waitFor('delivered')
    expect(report.id).toBe('d1')
    // Named so the sender can find its own local row; it is the acking user.
    expect(report.from).toBe(bob.userId)
    void alice
  })

  it('answers a catch-up query for a sender who was offline when it happened', async () => {
    // The live report is fire-and-forget with nothing queued behind it, so this
    // path is what makes the indicator work for a phone that was asleep.
    const { alice, bob, aConn, bConn } = await pair()
    aConn.send({ t: 'send', to: bob.userId, env: envelope('d2') })
    await aConn.waitFor('sent')
    const deliver = await bConn.waitFor('deliver')
    bConn.send({ t: 'ack', id: deliver.env.id })
    await aConn.waitFor('delivered') // ordering: the ack has been processed

    const reqId = nextReq()
    aConn.send({ t: 'deliveredCheck', reqId, to: bob.userId, ids: ['d2', 'never-sent'] })
    const list = (await aConn.waitPred(
      (m) => m.t === 'deliveredList' && (m as { reqId?: string }).reqId === reqId,
    )) as Extract<ServerMessage, { t: 'deliveredList' }>
    // Only the id actually picked up comes back: absence is never a false positive.
    expect(list.ids).toEqual(['d2'])
    void alice
  })

  it('reports nothing for an envelope still sitting in the queue', async () => {
    const { bob, aConn } = await pair()
    aConn.send({ t: 'send', to: bob.userId, env: envelope('d3') })
    await aConn.waitFor('sent')
    // Bob never connects, so nothing is acked and nothing is delivered.
    const reqId = nextReq()
    aConn.send({ t: 'deliveredCheck', reqId, to: bob.userId, ids: ['d3'] })
    const list = (await aConn.waitPred(
      (m) => m.t === 'deliveredList' && (m as { reqId?: string }).reqId === reqId,
    )) as Extract<ServerMessage, { t: 'deliveredList' }>
    expect(list.ids).toEqual([])
  })

  it('bounds how many ids one query may ask about', async () => {
    const { bob, aConn } = await pair()
    const reqId = nextReq()
    const ids = Array.from({ length: MAX_DELIVERED_CHECK_IDS + 50 }, (_, i) => `x${i}`)
    aConn.send({ t: 'deliveredCheck', reqId, to: bob.userId, ids })
    const list = (await aConn.waitPred(
      (m) => m.t === 'deliveredList' && (m as { reqId?: string }).reqId === reqId,
    )) as Extract<ServerMessage, { t: 'deliveredList' }>
    expect(list.ids).toEqual([]) // none exist, and the DO did bounded work
  })

  it('rejects a query naming a malformed recipient', async () => {
    const { aConn } = await pair()
    const reqId = nextReq()
    aConn.send({ t: 'deliveredCheck', reqId, to: 'not-a-user-id', ids: ['x'] })
    const err = (await aConn.waitPred(
      (m) => m.t === 'error' && (m as { reqId?: string }).reqId === reqId,
    )) as Extract<ServerMessage, { t: 'error' }>
    expect(err.code).toBe('bad_to')
  })
})

// Web Push subscription surface (P6). Storage lives in the per-user Inbox DO and
// is inspected directly via runInDurableObject (subscriptions are never exposed
// over any client-reachable API). Push SENDING is proven by the RFC 8291 KAT in
// push.test.ts; here we prove the authenticated subscription surface + guards.
describe('push subscriptions (P6)', () => {
  const P256DH = b64encode(new Uint8Array(65))
  const AUTH = b64encode(new Uint8Array(16))
  const ENDPOINT = 'https://fcm.googleapis.com/fcm/send/test-endpoint'

  const subCount = (userId: string): Promise<number> =>
    runInDurableObject(
      env.INBOX.get(env.INBOX.idFromName(userId)),
      (_i: unknown, state: DurableObjectState) =>
        (state.storage.sql.exec('SELECT COUNT(*) AS c FROM push_subs').toArray()[0] as { c: number }).c,
    )

  it('rejects pushSubscribe before authentication and writes no row (H1)', async () => {
    const id = generateIdentity()
    const conn = await connect(id.userId)
    await conn.waitFor('challenge')
    conn.send({ t: 'pushSubscribe', endpoint: ENDPOINT, p256dh: P256DH, auth: AUTH })
    expect((await conn.waitFor('error')).code).toBe('unauthenticated')
    expect(await subCount(id.userId)).toBe(0)
    conn.close()
  })

  it('rejects pushSubscribe before registration (N3)', async () => {
    const id = generateIdentity()
    const conn = await connectAndAuth(id)
    conn.send({ t: 'pushSubscribe', endpoint: ENDPOINT, p256dh: P256DH, auth: AUTH })
    expect((await conn.waitFor('error')).code).toBe('not_registered')
    conn.close()
  })

  it('validates the endpoint against the allowlist and the key sizes', async () => {
    const id = generateIdentity()
    const conn = await connectAndAuth(id)
    await register(conn, ownBundleFor(id), await adminInvite())
    conn.send({ t: 'pushSubscribe', endpoint: 'https://evil.example.com/x', p256dh: P256DH, auth: AUTH })
    expect((await conn.waitFor('error')).code).toBe('bad_endpoint')
    conn.send({ t: 'pushSubscribe', endpoint: ENDPOINT, p256dh: b64encode(new Uint8Array(10)), auth: AUTH })
    expect((await conn.waitFor('error')).code).toBe('bad_pushkeys')
    conn.close()
  })

  it('stores a registered subscription and drops it on unsubscribe', async () => {
    const id = generateIdentity()
    const conn = await connectAndAuth(id)
    await register(conn, ownBundleFor(id), await adminInvite())
    conn.send({ t: 'pushSubscribe', endpoint: ENDPOINT, p256dh: P256DH, auth: AUTH })
    await vi.waitFor(async () => expect(await subCount(id.userId)).toBe(1))
    conn.send({ t: 'pushUnsubscribe', endpoint: ENDPOINT })
    await vi.waitFor(async () => expect(await subCount(id.userId)).toBe(0))
    conn.close()
  })

  it('caps subscriptions per user, evicting the oldest past the cap', async () => {
    const id = generateIdentity()
    const conn = await connectAndAuth(id)
    await register(conn, ownBundleFor(id), await adminInvite())
    for (let i = 0; i < MAX_PUSH_SUBS + 3; i++) {
      conn.send({ t: 'pushSubscribe', endpoint: `${ENDPOINT}-${i}`, p256dh: P256DH, auth: AUTH })
    }
    await vi.waitFor(async () => expect(await subCount(id.userId)).toBe(MAX_PUSH_SUBS))
    conn.close()
  })
})

describe('SPK rotation through the directory (P8)', () => {
  const DAY = 86_400_000

  it('publishBundle with a rotated SPK replaces the served one, and the new SPK verifies where the old would fail max-age', async () => {
    const bob = generateIdentity()
    // Register with an 8-day-old bundle (accepted: under the 14-day max age).
    // This simulates a user whose registration SPK has aged past the rotation
    // cadence, the exact state maybeRotateSpk fires on.
    const own = buildOwnBundle(bob, Date.now() - 8 * DAY, { spkId: 1, opkStartId: 1, opkCount: 2 })
    const conn = await connectAndAuth(bob)
    const reg = await register(conn, own, await adminInvite())
    expect(reg.t).toBe('registered')

    // Rotate: publish a FRESH SPK (id 2) with no new OPKs, as the client does.
    const rotated = generateSignedPrekey(bob, 2, Date.now())
    const reqId = nextReq()
    conn.send({
      t: 'publishBundle',
      reqId,
      spk: {
        id: rotated.spk.id,
        createdAt: rotated.spk.createdAt,
        expiry: rotated.spk.expiry,
        pub: b64encode(rotated.spk.pub),
        sig: b64encode(rotated.spk.sig),
      },
      opks: [],
    })
    const pub = await conn.waitPred((m) => (m.t === 'published' || m.t === 'error') && (m as { reqId?: string }).reqId === reqId)
    expect(pub.t).toBe('published')

    // A fetcher now receives the rotated SPK, and it verifies at a `now` one
    // week ahead, where the registration-time SPK would already be 15 days old
    // and fail the initiator's max-age check.
    const alice = generateIdentity()
    const aliceConn = await connectAndAuth(alice)
    const aliceOwn = ownBundleFor(alice)
    const regA = await register(aliceConn, aliceOwn, await adminInvite())
    expect(regA.t).toBe('registered')

    const fetchReq = nextReq()
    aliceConn.send({ t: 'fetchBundle', reqId: fetchReq, target: bob.userId })
    const bm = (await aliceConn.waitFor('bundle')) as Extract<ServerMessage, { t: 'bundle' }>
    expect(bm.bundle).not.toBeNull()
    const fetched = decodeFetchedBundle(bm.bundle!)
    expect(fetched.spk.id).toBe(2)

    const later = Date.now() + 7 * DAY
    expect(() => verifyFetchedBundle(fetched, later)).not.toThrow()
    // The pre-rotation SPK really would have been rejected at that time.
    const stale = { ...fetched, spk: own.spk }
    expect(() => verifyFetchedBundle(stale, later)).toThrow(/expired|too old/)

    conn.close()
    aliceConn.close()
  })
})

describe('device rosters over the socket (Sesame)', () => {
  it('publishes and serves a roster, and answers null for an account without one', async () => {
    const alice = generateIdentity()
    const conn = await connectAndAuth(alice)
    expect((await register(conn, ownBundleFor(alice), await adminInvite())).t).toBe('registered')

    // Before publishing anything, an account is the single device it already is.
    const emptyReq = nextReq()
    conn.send({ t: 'fetchRoster', reqId: emptyReq, accountId: alice.userId })
    const none = (await conn.waitFor('roster')) as Extract<ServerMessage, { t: 'roster' }>
    expect(none.roster).toBeNull()

    const laptop = generateIdentity()
    const devices = [alice, laptop].map((d) => ({
      deviceId: deviceIdOf(d.ikSig.publicKey),
      dkSigPub: d.ikSig.publicKey,
      addedAt: Date.now(),
    }))
    const roster = signRoster(alice.userId, 1, devices, alice.ikSig.privateKey)
    const pubReq = nextReq()
    conn.send({ t: 'publishRoster', reqId: pubReq, roster: encodeDeviceRoster(roster) })
    const published = (await conn.waitFor('rosterPublished')) as Extract<ServerMessage, { t: 'rosterPublished' }>
    expect(published.version).toBe(1)

    const getReq = nextReq()
    conn.send({ t: 'fetchRoster', reqId: getReq, accountId: alice.userId })
    const got = (await conn.waitFor('roster')) as Extract<ServerMessage, { t: 'roster' }>
    expect(got.roster).toEqual(encodeDeviceRoster(roster))
    conn.close()
  })

  it('refuses a roster the account did not sign, over the socket like anywhere else', async () => {
    const alice = generateIdentity()
    const conn = await connectAndAuth(alice)
    expect((await register(conn, ownBundleFor(alice), await adminInvite())).t).toBe('registered')

    const impostor = generateIdentity()
    const forged = signRoster(
      alice.userId,
      1,
      [{ deviceId: deviceIdOf(alice.ikSig.publicKey), dkSigPub: alice.ikSig.publicKey, addedAt: Date.now() }],
      impostor.ikSig.privateKey,
    )
    const reqId = nextReq()
    conn.send({ t: 'publishRoster', reqId, roster: encodeDeviceRoster(forged) })
    const err = await conn.waitFor('error')
    expect(err.code).toBe('bad_roster')
    conn.close()
  })

  it('lets a device publish for its account even though it authenticates as itself', async () => {
    // The case that made caller-based authorization wrong: a linked device is not
    // the account, and still has to be able to update the account's roster.
    const alice = generateIdentity()
    const other = generateIdentity()
    const aliceConn = await connectAndAuth(alice)
    const otherConn = await connectAndAuth(other)
    expect((await register(aliceConn, ownBundleFor(alice), await adminInvite())).t).toBe('registered')
    expect((await register(otherConn, ownBundleFor(other), await adminInvite())).t).toBe('registered')

    const roster = signRoster(
      alice.userId,
      1,
      [{ deviceId: deviceIdOf(alice.ikSig.publicKey), dkSigPub: alice.ikSig.publicKey, addedAt: Date.now() }],
      alice.ikSig.privateKey,
    )
    // Sent on a socket authenticated as somebody else entirely.
    const reqId = nextReq()
    otherConn.send({ t: 'publishRoster', reqId, roster: encodeDeviceRoster(roster) })
    const published = (await otherConn.waitFor('rosterPublished')) as Extract<ServerMessage, { t: 'rosterPublished' }>
    expect(published.version).toBe(1)
    aliceConn.close()
    otherConn.close()
  })
})
