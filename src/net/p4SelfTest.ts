// In-browser P4 proof-of-life: two parties (Alice and Bob), each a full
// NightjarClient with its own in-memory stores, talking through the REAL relay
// Worker over two authenticated WebSockets. Given one bootstrap (admin) invite,
// Alice registers, mints an invite for Bob, Bob registers, and they exchange
// messages both directions. This exercises the entire P4 stack end-to-end in a
// real browser: auth handshake, invite-gated registration, bundle fetch + OPK
// vend, X3DH, the ratchet, store-and-deliver, and acks.

import { generateIdentity } from '../crypto/identity'
import { MemoryKeyStore } from '../storage/keystore'
import { InMemoryLock } from '../storage/lock'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

export interface P4SelfTestResult {
  ok: boolean
  log: string[]
}

function makeClient(received: string[], errors: string[]): NightjarClient {
  const id = generateIdentity()
  const lock = new InMemoryLock()
  const keys = new MemoryKeyStore()
  const prekeys = new PrekeyStore(keys, lock)
  const contacts = new ContactStore(keys, lock)
  return new NightjarClient(id, new MemorySessionStore(), prekeys, contacts, lock, {
    onMessage: (_from, text) => received.push(text),
    onError: (detail) => errors.push(detail),
  })
}

async function waitUntil(pred: () => boolean, ms = 4000): Promise<void> {
  const start = performance.now()
  while (!pred()) {
    if (performance.now() - start > ms) throw new Error('timed out waiting for a message')
    await new Promise((r) => setTimeout(r, 25))
  }
}

export async function runP4SelfTest(bootstrapInvite: string): Promise<P4SelfTestResult> {
  const log: string[] = []
  const aRecv: string[] = []
  const bRecv: string[] = []
  const errors: string[] = []
  const alice = makeClient(aRecv, errors)
  const bob = makeClient(bRecv, errors)

  try {
    await alice.connect()
    await bob.connect()
    log.push(`connected: alice ${alice.userId.slice(0, 8)}…, bob ${bob.userId.slice(0, 8)}…`)

    await alice.register(bootstrapInvite.trim())
    log.push('alice registered with the bootstrap invite')

    const invite = await alice.mintInvite()
    log.push(`alice minted an invite for bob (${invite.code})`)

    await bob.register(invite.code)
    log.push('bob registered with alice’s invite')

    // Bob pins Alice via the invite (inviter -> joiner authentication, 6.3).
    await bob.addInviteContact(alice.userId)
    log.push('bob pinned alice via the invite')

    await alice.sendText(bob.userId, 'hello from alice')
    await waitUntil(() => bRecv.length > 0)
    log.push(`bob received: "${bRecv[0]}"`)

    await bob.sendText(alice.userId, 'hi back from bob')
    await waitUntil(() => aRecv.length > 0)
    log.push(`alice received: "${aRecv[0]}"`)

    // A second message from alice exercises the established-session (normal) path.
    await alice.sendText(bob.userId, 'and a second one')
    await waitUntil(() => bRecv.length > 1)
    log.push(`bob received: "${bRecv[1]}"`)

    // Per-direction trust (6.3): bob authenticated alice via the invite, while
    // alice only learned bob's key via TOFU (unverified until they scan in person).
    const bobToAlice = await bob.trustOf(alice.userId)
    const aliceToBob = await alice.trustOf(bob.userId)
    log.push(`trust: bob->alice = ${bobToAlice}, alice->bob = ${aliceToBob}`)

    const ok =
      bRecv[0] === 'hello from alice' &&
      aRecv[0] === 'hi back from bob' &&
      bRecv[1] === 'and a second one' &&
      bobToAlice === 'invite' &&
      aliceToBob === 'unverified' &&
      errors.length === 0
    // Surface the FULL ids (both stay registered in the Directory) so the app can
    // message one and exercise the contact + verify UI against a real peer.
    log.push(`alice id: ${alice.userId}`)
    log.push(`bob id: ${bob.userId}`)
    if (errors.length) log.push(`errors: ${errors.join('; ')}`)
    return { ok, log }
  } catch (e) {
    log.push(`FAILED: ${String(e instanceof Error ? e.message : e)}`)
    if (errors.length) log.push(`errors: ${errors.join('; ')}`)
    return { ok: false, log }
  } finally {
    alice.close()
    bob.close()
  }
}

// The P5 session-glare scenario over the REAL relay: Alice and Bob each send a
// first-contact initial before either has received, then each sends a follow-up
// on the promoted (opposite-arm) session. Before the multi-session fix, the
// follow-ups decrypted against the wrong ratchet and were lost forever.
export async function runGlareSelfTest(bootstrapInvite: string): Promise<P4SelfTestResult> {
  const log: string[] = []
  const aRecv: string[] = []
  const bRecv: string[] = []
  const errors: string[] = []
  const alice = makeClient(aRecv, errors)
  const bob = makeClient(bRecv, errors)

  try {
    await alice.connect()
    await bob.connect()
    await alice.register(bootstrapInvite.trim())
    const invite = await alice.mintInvite()
    await bob.register(invite.code)
    log.push('both registered; forcing simultaneous first contact')

    // Both send a first-contact initial before either receives (glare).
    await Promise.all([alice.sendText(bob.userId, 'A1'), bob.sendText(alice.userId, 'B1')])
    await waitUntil(() => aRecv.includes('B1') && bRecv.includes('A1'))
    log.push('both initials delivered; each side promoted a responder session')

    // Follow-ups now ride the opposite arm of the glare and must still decrypt.
    await Promise.all([alice.sendText(bob.userId, 'A2'), bob.sendText(alice.userId, 'B2')])
    await waitUntil(() => bRecv.includes('A2') && aRecv.includes('B2'))
    log.push('follow-ups (opposite-arm sessions) decrypted both ways')

    // A couple more rounds to be sure it stays converged.
    await alice.sendText(bob.userId, 'A3')
    await bob.sendText(alice.userId, 'B3')
    await waitUntil(() => bRecv.includes('A3') && aRecv.includes('B3'))

    const ok =
      bRecv.includes('A1') &&
      bRecv.includes('A2') &&
      bRecv.includes('A3') &&
      aRecv.includes('B1') &&
      aRecv.includes('B2') &&
      aRecv.includes('B3') &&
      errors.length === 0
    log.push(`alice received: ${aRecv.join(', ')}`)
    log.push(`bob received: ${bRecv.join(', ')}`)
    if (errors.length) log.push(`errors: ${errors.join('; ')}`)
    return { ok, log }
  } catch (e) {
    log.push(`FAILED: ${String(e instanceof Error ? e.message : e)}`)
    if (errors.length) log.push(`errors: ${errors.join('; ')}`)
    return { ok: false, log }
  } finally {
    alice.close()
    bob.close()
  }
}
