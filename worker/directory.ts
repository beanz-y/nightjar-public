// Directory Durable Object (DESIGN 7.1). A single instance (idFromName('main'))
// holding the public prekey directory: it registers identities behind a
// single-use invite, serves prekey bundles, and vends one-time prekeys with
// per-(fetcher,target) idempotency so a spammed fetch cannot deplete a user's
// OPKs (DESIGN 4.3). It never sees a private key or any plaintext.
//
// Invite redemption is a guarded read-modify-write run inside one transaction:
// the DO's single-threaded turn is the atomic batch (the NtE getAfter dance
// collapses to plain code here), so the one-way `used` flip and self-stamped
// `used_by` are invariants we assert directly.

import {
  CLOCK_SKEW_MS,
  INVITE_TTL_MS,
  MAX_AVAILABLE_OPKS,
  MAX_INVITE_REDEMPTIONS,
  MAX_OPKS_PER_REQUEST,
  MAX_OUTSTANDING_INVITES,
  MAX_ROTATION_CHAIN,
  OPK_VEND_TTL_MS,
  SPK_MAX_AGE_MS,
  TAG_SPK,
  VERSION_FLOOR,
} from '../src/crypto/constants'
import { deriveUserId, deviceIdOf } from '../src/crypto/identity'
import { domainSeparate, ed25519Verify, u32be, u64be } from '../src/crypto/primitives'
import { type FetchedBundle, type SignedPrekey, verifyFetchedBundle } from '../src/crypto/prekeys'
import { verifyRoster } from '../src/crypto/roster'
import { verifyRotation } from '../src/crypto/rotation'
import {
  type WireDeviceRoster,
  type WireFetchedBundle,
  type WireOneTimePrekey,
  type WirePublishedBundle,
  type WireRotationStatement,
  type WireSignedPrekey,
  b64decode,
  b64encode,
  decodeDeviceRoster,
  decodeRotationStatement,
  decodePublishedBundle,
  decodeSignedPrekey,
  encodePublishedBundle,
  encodeSignedPrekey,
} from '../src/wire/codec'
import { newInviteCode } from '../src/server/invites'
import { DirectoryError, json } from './shared'

interface RegisterBody {
  userId: string
  inviteCode: string
  bundle: WirePublishedBundle
  now: number
}
interface PublishBody {
  userId: string
  spk: WireSignedPrekey
  opks: WireOneTimePrekey[]
  now: number
}
interface PublishRosterBody {
  roster: WireDeviceRoster
}
interface PublishRotationBody {
  statement: WireRotationStatement
}
interface RegisterDeviceBody {
  /** Server-verified: the id of the socket that asked, never a body claim. */
  deviceId: string
  /** Claimed, and checked against that account's signed roster. */
  accountId: string
  bundle: WirePublishedBundle
  now: number
}
interface FetchBody {
  fetcher: string
  target: string
  now: number
}

/** How often the invite-purge alarm runs while invites remain. */
const INVITE_PURGE_INTERVAL_MS = 24 * 60 * 60 * 1000

/** Verify a signed prekey's signature + freshness against a known IK_sig. */
function verifySignedPrekey(spk: SignedPrekey, ikSigPub: Uint8Array, now: number): boolean {
  const input = domainSeparate(TAG_SPK, u32be(spk.id), u64be(spk.createdAt), u64be(spk.expiry), spk.pub)
  if (!ed25519Verify(spk.sig, input, ikSigPub)) return false
  if (now >= spk.expiry) return false
  if (spk.createdAt > now + CLOCK_SKEW_MS) return false
  if (now - spk.createdAt > SPK_MAX_AGE_MS) return false
  return true
}

export class Directory {
  private readonly sql: SqlStorage

  constructor(private readonly ctx: DurableObjectState, _env: unknown) {
    this.sql = ctx.storage.sql
    ctx.blockConcurrencyWhile(async () => this.migrate())
  }

  private migrate(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        ik_sig_pub TEXT NOT NULL,
        ik_dh_pub TEXT NOT NULL,
        idkbind_sig TEXT NOT NULL,
        version INTEGER NOT NULL,
        registered_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS spks (
        user_id TEXT PRIMARY KEY,
        spk_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        expiry INTEGER NOT NULL,
        pub TEXT NOT NULL,
        sig TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS opks (
        user_id TEXT NOT NULL,
        opk_id INTEGER NOT NULL,
        pub TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'available',
        PRIMARY KEY (user_id, opk_id)
      );
      CREATE TABLE IF NOT EXISTS vends (
        fetcher TEXT NOT NULL,
        target TEXT NOT NULL,
        opk_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (fetcher, target)
      );
      CREATE TABLE IF NOT EXISTS invites (
        code TEXT PRIMARY KEY,
        inviter TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        used_by TEXT,
        used_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_invites_inviter ON invites(inviter);
      CREATE TABLE IF NOT EXISTS rosters (
        account_id TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        blob TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS rotations (
        old_account_id TEXT PRIMARY KEY,
        new_account_id TEXT NOT NULL,
        new_account_key TEXT NOT NULL,
        chain_len INTEGER NOT NULL,
        blob TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_rotations_new ON rotations(new_account_id);
    `)
  }

  async fetch(req: Request): Promise<Response> {
    const path = new URL(req.url).pathname
    try {
      switch (path) {
        case '/mintInvite': {
          const r = this.mintInvite((await req.json()) as { inviter: string; now: number })
          await this.ensurePurgeAlarm(Date.now())
          return json(r)
        }
        case '/register': {
          const r = this.register((await req.json()) as RegisterBody)
          await this.ensurePurgeAlarm(Date.now())
          return json(r)
        }
        case '/publishBundle':
          return json(this.publishBundle((await req.json()) as PublishBody))
        case '/fetchBundle':
          return json(this.fetchBundle((await req.json()) as FetchBody))
        case '/isRegistered':
          return json(this.isRegistered((await req.json()) as { userId: string }))
        case '/inviteRedemptions':
          return json(this.inviteRedemptions((await req.json()) as { inviter: string }))
        case '/publishRoster':
          return json(this.publishRoster((await req.json()) as PublishRosterBody))
        case '/registerDevice':
          return json(this.registerDevice((await req.json()) as RegisterDeviceBody))
        case '/fetchRoster':
          return json(this.fetchRoster((await req.json()) as { accountId: string }))
        case '/publishRotation':
          return json(this.publishRotation((await req.json()) as PublishRotationBody))
        case '/fetchRotation':
          return json(this.fetchRotation((await req.json()) as { accountId: string }))
        default:
          return json({ code: 'not_found', msg: 'unknown directory op' }, 404)
      }
    } catch (e) {
      if (e instanceof DirectoryError) return json({ code: e.code, msg: e.message }, e.status)
      return json({ code: 'internal', msg: String(e instanceof Error ? e.message : e) }, 500)
    }
  }

  // --- invites -----------------------------------------------------------

  private mintInvite(body: { inviter: string; now: number }): { code: string } {
    // Only the admin (bootstrap) or an already-registered user may mint invites
    // (DESIGN 6.3). This gates the whole graph to people someone vouched for.
    if (body.inviter !== '@admin') {
      const user = this.sql.exec('SELECT user_id FROM users WHERE user_id = ?', body.inviter).toArray()[0]
      if (!user) throw new DirectoryError('not_registered', 'register before minting invites')
      // Cap outstanding (unused, unexpired) invites per inviter so a single
      // account cannot flood the shared Directory (P4 review).
      const outstanding = this.sql
        .exec(
          'SELECT COUNT(*) AS c FROM invites WHERE inviter = ? AND used = 0 AND created_at > ?',
          body.inviter,
          body.now - INVITE_TTL_MS,
        )
        .toArray()[0] as { c: number }
      if (outstanding.c >= MAX_OUTSTANDING_INVITES) {
        throw new DirectoryError('too_many_invites', 'too many outstanding invites; use or wait for some to expire')
      }
    }
    const code = newInviteCode()
    this.sql.exec(
      'INSERT INTO invites (code, inviter, created_at, used) VALUES (?, ?, ?, 0)',
      code,
      body.inviter,
      body.now,
    )
    return { code }
  }

  // Guarded, one-way redemption. No await between the read and the write, so
  // within this single-threaded DO turn the check-then-act is atomic.
  private redeemInvite(code: string, userId: string, now: number): void {
    const inv = this.sql.exec('SELECT used, created_at FROM invites WHERE code = ?', code).toArray()[0] as
      | { used: number; created_at: number }
      | undefined
    if (!inv) throw new DirectoryError('bad_invite', 'invite not found')
    if (inv.used) throw new DirectoryError('invite_used', 'invite already used')
    if (now - inv.created_at > INVITE_TTL_MS) throw new DirectoryError('invite_expired', 'invite has expired')
    const cursor = this.sql.exec(
      'UPDATE invites SET used = 1, used_by = ?, used_at = ? WHERE code = ? AND used = 0',
      userId,
      now,
      code,
    )
    if (cursor.rowsWritten !== 1) throw new DirectoryError('invite_used', 'invite already used')
  }

  // Who redeemed the invites this inviter minted (mutual invite, DESIGN 6.3): the
  // server-verified user ids stamped into `used_by` at redemption. `inviter` is the
  // caller's challenge-verified id (the Inbox forwards it, never a client claim), so
  // a user can only ever read THEIR OWN joiners, not enumerate anyone else's graph.
  // Bounded to the most recent MAX_INVITE_REDEMPTIONS so a prolific inviter cannot
  // return an unbounded array (the redeemed set is capped only by the 30-day purge).
  private inviteRedemptions(body: { inviter: string }): { joiners: string[] } {
    const rows = this.sql
      .exec(
        'SELECT used_by FROM invites WHERE inviter = ? AND used = 1 AND used_by IS NOT NULL ORDER BY used_at DESC LIMIT ?',
        body.inviter,
        MAX_INVITE_REDEMPTIONS,
      )
      .toArray() as Array<{ used_by: string }>
    return { joiners: rows.map((r) => r.used_by) }
  }

  // --- registration ------------------------------------------------------

  private register(body: RegisterBody): { opkCount: number } {
    const decoded = decodePublishedBundle(body.bundle)
    if (decoded.opks.length > MAX_OPKS_PER_REQUEST) {
      throw new DirectoryError('too_many_opks', 'one-time prekey batch too large')
    }

    // Defence in depth: the id must be the hash of the presented signing key,
    // and the identity binding + signed prekey must verify, or we never store it.
    if (deriveUserId(decoded.ikSigPub) !== body.userId) {
      throw new DirectoryError('bad_userid', 'user id does not match IK_sig public key')
    }
    if (decoded.version < VERSION_FLOOR) throw new DirectoryError('bad_version', 'version below floor')
    const asFetched: FetchedBundle = { ...decoded, opk: null }
    try {
      verifyFetchedBundle(asFetched, body.now)
    } catch (e) {
      throw new DirectoryError('bad_bundle', `bundle failed verification: ${String(e)}`)
    }

    const canon = encodePublishedBundle(decoded)
    const existing = this.sql.exec('SELECT ik_sig_pub FROM users WHERE user_id = ?', body.userId).toArray()[0] as
      | { ik_sig_pub: string }
      | undefined

    if (existing) {
      // Re-registration by the same identity (a retry, or a restored device)
      // republishes prekeys but does NOT consume another invite. A different key
      // claiming a registered id is refused (the id IS a hash of the key).
      if (existing.ik_sig_pub !== canon.ikSigPub) {
        throw new DirectoryError('id_taken', 'user id already registered to a different key')
      }
      return this.ctx.storage.transactionSync(() => {
        // Hard-invalidate the previous prekeys and outstanding vends (DESIGN 8.3):
        // the client regenerates fresh OPK keypairs at the same ids, so keeping
        // the old public rows (INSERT OR IGNORE) would serve keys whose private
        // half the owner no longer holds, silently breaking new inbound sessions.
        this.sql.exec('DELETE FROM opks WHERE user_id = ?', body.userId)
        this.sql.exec('DELETE FROM vends WHERE target = ?', body.userId)
        // Also drop vends where this user was the FETCHER (Phase D). The vend
        // cache re-serves the SAME one-time prekey to a repeat fetcher for 7
        // days; a restored or moved device re-fetching a recently-contacted
        // peer would be handed a prekey that peer already consumed, its initial
        // would never decrypt, and both directions black-hole while showing
        // delivered. A re-registration is a declaration that this device's
        // session world restarted, so its fetch history restarts with it.
        this.sql.exec('DELETE FROM vends WHERE fetcher = ?', body.userId)
        this.storeBundle(body.userId, canon)
        return { opkCount: this.opkCount(body.userId) }
      })
    }

    return this.ctx.storage.transactionSync(() => {
      this.redeemInvite(body.inviteCode, body.userId, body.now)
      this.sql.exec(
        'INSERT INTO users (user_id, ik_sig_pub, ik_dh_pub, idkbind_sig, version, registered_at) VALUES (?, ?, ?, ?, ?, ?)',
        body.userId,
        canon.ikSigPub,
        canon.ikDhPub,
        canon.idkbindSig,
        canon.version,
        body.now,
      )
      this.storeBundle(body.userId, canon)
      return { opkCount: this.opkCount(body.userId) }
    })
  }

  private storeBundle(userId: string, canon: WirePublishedBundle): void {
    this.sql.exec(
      'INSERT OR REPLACE INTO spks (user_id, spk_id, created_at, expiry, pub, sig) VALUES (?, ?, ?, ?, ?, ?)',
      userId,
      canon.spk.id,
      canon.spk.createdAt,
      canon.spk.expiry,
      canon.spk.pub,
      canon.spk.sig,
    )
    for (const opk of canon.opks) {
      this.sql.exec(
        "INSERT OR IGNORE INTO opks (user_id, opk_id, pub, status) VALUES (?, ?, ?, 'available')",
        userId,
        opk.id,
        opk.pub,
      )
    }
  }

  // --- prekey publish / replenish (rotate SPK, append OPKs) --------------

  private publishBundle(body: PublishBody): { opkCount: number } {
    const stored = this.sql.exec('SELECT ik_sig_pub FROM users WHERE user_id = ?', body.userId).toArray()[0] as
      | { ik_sig_pub: string }
      | undefined
    if (!stored) throw new DirectoryError('not_registered', 'publish before register')
    if (!Array.isArray(body.opks) || body.opks.length > MAX_OPKS_PER_REQUEST) {
      throw new DirectoryError('too_many_opks', 'one-time prekey batch too large')
    }

    const ikSigPub = b64decode(stored.ik_sig_pub, 32)
    const spk = decodeSignedPrekey(body.spk)
    if (!verifySignedPrekey(spk, ikSigPub, body.now)) {
      throw new DirectoryError('bad_spk', 'signed prekey failed verification')
    }
    const canonSpk = encodeSignedPrekey(spk)

    return this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        'INSERT OR REPLACE INTO spks (user_id, spk_id, created_at, expiry, pub, sig) VALUES (?, ?, ?, ?, ?, ?)',
        body.userId,
        canonSpk.id,
        canonSpk.createdAt,
        canonSpk.expiry,
        canonSpk.pub,
        canonSpk.sig,
      )
      // Enforce a per-user ceiling on accumulated available OPKs, so repeated
      // replenishment cannot grow the shared Directory without bound (P4 review).
      let available = this.opkCount(body.userId)
      for (const w of body.opks) {
        if (available >= MAX_AVAILABLE_OPKS) break
        b64decode(w.pub, 32) // structural check (throws on a bad key)
        const dup = this.sql.exec('SELECT 1 FROM opks WHERE user_id = ? AND opk_id = ?', body.userId, w.id).toArray()[0]
        if (dup) continue
        this.sql.exec(
          "INSERT INTO opks (user_id, opk_id, pub, status) VALUES (?, ?, ?, 'available')",
          body.userId,
          w.id,
          w.pub,
        )
        available++
      }
      return { opkCount: this.opkCount(body.userId) }
    })
  }

  // --- bundle fetch + OPK vend ------------------------------------------

  /**
   * The account key this Directory knows for an account id, and how many
   * rotations that account is from the registered one it began as.
   *
   * Two sources, and the second exists because of rotation. An account normally
   * IS a registered user: its first device's identity key is its account key, and
   * that is what lets every single-device user become a one-device account with
   * nothing moving. After a rotation the new account id belongs to no device and
   * has no user row, so the key comes from the rotation the Directory recorded.
   *
   * Rotations are consulted first. If an id ever answers from both (which needs
   * somebody to rotate onto a key that is also a registered device's, so they
   * hold both private halves anyway), the two agree about the KEY, because an
   * account id is the hash of it. They can disagree about the chain length, and
   * taking the longer one is the conservative half of that choice.
   *
   * Returning null means "no such account", and that is the gate that keeps the
   * account namespace invite-gated: without it, anyone could mint ids out of
   * fresh keypairs and fill the one shared Directory with rosters for accounts
   * that do not exist.
   */
  private accountKeyOf(accountId: string): { key: Uint8Array; chainLen: number } | null {
    const rotated = this.sql
      .exec('SELECT new_account_key, chain_len FROM rotations WHERE new_account_id = ?', accountId)
      .toArray()[0] as { new_account_key: string; chain_len: number } | undefined
    if (rotated) return { key: b64decode(rotated.new_account_key, 32), chainLen: rotated.chain_len }
    const user = this.sql.exec('SELECT ik_sig_pub FROM users WHERE user_id = ?', accountId).toArray()[0] as
      | { ik_sig_pub: string }
      | undefined
    if (user) return { key: b64decode(user.ik_sig_pub, 32), chainLen: 0 }
    return null
  }

  // --- device rosters (Sesame) -------------------------------------------
  //
  // An account's roster says which devices are its own, so a sender knows every
  // device to deliver a copy to. The Directory stores it and serves it; it can
  // never author one, because it holds no account key.
  //
  // Authorization is the SIGNATURE, not the caller. That is deliberate: a linked
  // device authenticates to the relay as ITSELF (its own device id), so requiring
  // the caller to be the account would make every device but the first unable to
  // publish. Anyone may relay a validly signed roster, and the worst they can do
  // is publish one the account genuinely signed, no earlier than the account
  // signed it, which is not an attack.
  //
  // The server checks the signature and monotonicity so a peer cannot publish
  // rubbish for someone else, and so an account cannot be quietly rolled back
  // here. That is a LIVENESS guarantee, not a security one: a hostile operator
  // owns this code and can serve whatever it likes. The binding defence is the
  // client's high-water mark (src/crypto/roster.ts isRosterNewer).
  private publishRoster(body: PublishRosterBody): { version: number } {
    // Shape first, signature below. A malformed roster is the caller's mistake, so
    // it is a 400 rather than the 500 an unwrapped decode throw would produce.
    let roster
    try {
      roster = decodeDeviceRoster(body.roster)
    } catch (e) {
      throw new DirectoryError('bad_roster', String(e instanceof Error ? e.message : e), 400)
    }
    // Verified under the key this Directory ALREADY holds for that account id,
    // never one carried in with the roster, which would only prove the roster was
    // signed by whoever wrote it.
    const owner = this.accountKeyOf(roster.accountId)
    if (!owner) throw new DirectoryError('not_registered', 'no such account')
    try {
      verifyRoster(roster, owner.key, Date.now())
    } catch (e) {
      throw new DirectoryError('bad_roster', String(e instanceof Error ? e.message : e), 400)
    }
    // An account that has rotated is finished, and its old list stops changing.
    // What is already stored keeps being SERVED, so contacts who have not heard
    // about the rotation still reach the devices they know. What is refused is
    // any CHANGE to it, including a removal: the honest consequence is that a
    // device the rotation was meant to retire stays on the list un-followed
    // contacts use, until they follow the rotation, which is the thing that
    // actually retires it. Liveness rather than security, like the monotonicity
    // below, and `registerDevice` refuses the same account for the same reason.
    const moved = this.sql.exec('SELECT 1 AS x FROM rotations WHERE old_account_id = ?', roster.accountId).toArray()[0]
    if (moved) {
      throw new DirectoryError('account_rotated', 'that account has rotated; publish under the new account key', 409)
    }
    // Monotonic, and equal versions are refused for the same reason the client
    // refuses them: two different rosters at one version means something is wrong.
    const current = this.sql.exec('SELECT version, blob FROM rosters WHERE account_id = ?', roster.accountId).toArray()[0] as
      | { version: number; blob: string }
      | undefined
    if (current && roster.version <= current.version) {
      throw new DirectoryError('stale_roster', `roster version ${roster.version} does not follow ${current.version}`, 409)
    }
    // Storing the new list and retiring the prekeys of devices it drops are one
    // change, so they commit together: a crash between them would leave an account
    // whose stored list disagrees with which of its devices are reachable.
    return this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        'INSERT INTO rosters (account_id, version, blob, updated_at) VALUES (?, ?, ?, ?) ' +
          'ON CONFLICT(account_id) DO UPDATE SET version = excluded.version, blob = excluded.blob, updated_at = excluded.updated_at',
        roster.accountId,
        roster.version,
        JSON.stringify(body.roster),
        Date.now(),
      )
      this.dropUnlistedDevices(
        roster.accountId,
        current ? (JSON.parse(current.blob) as WireDeviceRoster) : null,
        body.roster,
      )
      return { version: roster.version }
    })
  }

  /**
   * Register an additional DEVICE of an account (Sesame). A new device is not a
   * new user, so it consumes no invite: the account already passed that gate, and
   * charging an invite per device would make linking a laptop cost the same as
   * bringing a person in.
   *
   * What replaces the invite is the roster. The account must already have
   * published a signed roster listing this device, which only the account key can
   * produce, so authorization comes from the account itself rather than from us.
   *
   * `deviceId` is the SERVER-VERIFIED id of the socket that asked, never a claim
   * in the body, exactly as ordinary registration works. `accountId` IS a claim,
   * and a false one fails immediately: an account that did not list this device
   * has no roster entry for it, and the roster is signed.
   */
  private registerDevice(body: RegisterDeviceBody): { opkCount: number } {
    // An account that has rotated is finished here too. Its roster is frozen, so
    // without this a device listed on that frozen list could keep registering
    // itself under the retired account forever, which is a right the freeze was
    // meant to end. Registering under the NEW account id is unaffected.
    const moved = this.sql.exec('SELECT 1 AS x FROM rotations WHERE old_account_id = ?', body.accountId).toArray()[0]
    if (moved) {
      throw new DirectoryError('account_rotated', 'that account has rotated; register under the new account id', 409)
    }
    const roster = this.sql.exec('SELECT blob FROM rosters WHERE account_id = ?', body.accountId).toArray()[0] as
      | { blob: string }
      | undefined
    if (!roster) throw new DirectoryError('no_roster', 'that account has not listed any devices')
    const listed = (JSON.parse(roster.blob) as WireDeviceRoster).devices.some((d) => d.deviceId === body.deviceId)
    if (!listed) throw new DirectoryError('not_listed', 'that account has not listed this device')

    const decoded = decodePublishedBundle(body.bundle)
    if (decoded.opks.length > MAX_OPKS_PER_REQUEST) {
      throw new DirectoryError('too_many_opks', 'one-time prekey batch too large')
    }
    // Same proof of possession ordinary registration demands: the id is the hash
    // of the presented key, and the signed prekey verifies under it, so publishing
    // a bundle requires the device's private half rather than just its public id
    // (which the roster makes public to everyone).
    if (deviceIdOf(decoded.ikSigPub) !== body.deviceId) {
      throw new DirectoryError('bad_userid', 'device id does not match IK_sig public key')
    }
    if (decoded.version < VERSION_FLOOR) throw new DirectoryError('bad_version', 'version below floor')
    try {
      verifyFetchedBundle({ ...decoded, opk: null }, body.now)
    } catch (e) {
      throw new DirectoryError('bad_bundle', `bundle failed verification: ${String(e)}`)
    }
    const canon = encodePublishedBundle(decoded)
    const existing = this.sql.exec('SELECT ik_sig_pub FROM users WHERE user_id = ?', body.deviceId).toArray()[0] as
      | { ik_sig_pub: string }
      | undefined
    if (existing && existing.ik_sig_pub !== canon.ikSigPub) {
      throw new DirectoryError('id_taken', 'device id already registered to a different key')
    }

    return this.ctx.storage.transactionSync(() => {
      if (existing) {
        // Re-registration by the same device: same hard invalidation ordinary
        // re-registration performs, for the same reason (fresh private halves).
        this.sql.exec('DELETE FROM opks WHERE user_id = ?', body.deviceId)
        this.sql.exec('DELETE FROM vends WHERE target = ?', body.deviceId)
        this.sql.exec('DELETE FROM vends WHERE fetcher = ?', body.deviceId)
      } else {
        this.sql.exec(
          'INSERT INTO users (user_id, ik_sig_pub, ik_dh_pub, idkbind_sig, version, registered_at) VALUES (?, ?, ?, ?, ?, ?)',
          body.deviceId,
          canon.ikSigPub,
          canon.ikDhPub,
          canon.idkbindSig,
          decoded.version,
          body.now,
        )
      }
      this.storeBundle(body.deviceId, canon)
      return { opkCount: this.opkCount(body.deviceId) }
    })
  }

  /** Drop the published prekeys of devices an account has just stopped listing, so
   *  a device that was removed can no longer have NEW sessions opened to it. This
   *  is the only part of removal a server can enforce, and it is worth saying what
   *  it is not: sessions that already exist keep working, and a device that kept a
   *  copy of the account key can sign itself back on. Removal is not revocation.
   *
   *  The account's own row is never dropped, whatever a roster says. It holds the
   *  account key that every future roster is verified against, so deleting it
   *  would leave the account unable to change its own device list ever again.
   *
   *  After an account-key ROTATION that protection no longer applies, and that is
   *  the point rather than a gap: the new account id belongs to no device, its key
   *  comes from the recorded rotation instead of a user row, and so the device that
   *  used to hold the account key becomes an ordinary device the account can drop.
   *  Rotation is what makes a first device removable at all. */
  private dropUnlistedDevices(accountId: string, before: WireDeviceRoster | null, after: WireDeviceRoster): void {
    if (!before) return
    const kept = new Set(after.devices.map((d) => d.deviceId))
    for (const d of before.devices) {
      if (kept.has(d.deviceId) || d.deviceId === accountId) continue
      this.sql.exec('DELETE FROM spks WHERE user_id = ?', d.deviceId)
      this.sql.exec('DELETE FROM opks WHERE user_id = ?', d.deviceId)
      this.sql.exec('DELETE FROM vends WHERE target = ?', d.deviceId)
    }
  }

  /** The account's current roster, or null if it has never published one (which
   *  is every account until it links a second device). A null is not an error:
   *  the caller treats the account as a single device at its account id. */
  private fetchRoster(body: { accountId: string }): {
    roster: WireDeviceRoster | null
    rotation: WireRotationStatement | null
  } {
    const row = this.sql.exec('SELECT blob FROM rosters WHERE account_id = ?', body.accountId).toArray()[0] as
      | { blob: string }
      | undefined
    // The forwarding pointer rides along, because this is the moment it is needed:
    // a sender asking where somebody's devices are is exactly who has to find out
    // that they moved. Answering both in one round trip is what keeps the follow
    // off the hot path, and an older client simply ignores the extra field.
    const moved = this.sql
      .exec('SELECT blob FROM rotations WHERE old_account_id = ?', body.accountId)
      .toArray()[0] as { blob: string } | undefined
    return {
      roster: row ? (JSON.parse(row.blob) as WireDeviceRoster) : null,
      rotation: moved ? (JSON.parse(moved.blob) as WireRotationStatement) : null,
    }
  }

  // --- account-key rotation (Sesame) -------------------------------------
  //
  // An account id is the hash of its account key, so replacing the key means
  // replacing the id, and every contact would otherwise be looking at a stranger.
  // A rotation statement is what carries the relationship across: signed by the
  // account being rotated, counter-signed by the key taking over.
  //
  // The Directory does exactly two things with it, and neither makes it an
  // authority. It RECORDS the successor, which is what lets a rotated account
  // publish a roster at all: without a recorded rotation there is no user row for
  // the new id and no key to verify anything against, so a rotated account could
  // never say where its devices are. And it SERVES the statement to anyone who
  // asks about the old id, so a contact who was offline while it happened can
  // still find out, verify it under the key they already hold, and follow.
  //
  // Authorization is the SIGNATURE, exactly as for rosters: the caller is
  // irrelevant, because it may be any device of the account, and a stranger
  // relaying a genuinely signed statement achieves nothing the account did not
  // already say.
  //
  // What the Directory refuses is narrow and worth stating, because all of it is
  // LIVENESS, not security. A hostile operator owns this code and can serve
  // whatever it likes; a client's defence is that it verifies every hop under the
  // key it already holds, and that the binding a rotation produces is UNVERIFIED
  // until a human re-does the safety-number comparison.
  private publishRotation(body: PublishRotationBody): { newAccountId: string; chainLen: number } {
    // Shape first, signatures below. A malformed statement is the caller's
    // mistake, so it is a 400 rather than the 500 a raw decode throw would be.
    let st
    try {
      st = decodeRotationStatement(body.statement)
    } catch (e) {
      throw new DirectoryError('bad_rotation', String(e instanceof Error ? e.message : e), 400)
    }
    const from = this.accountKeyOf(st.oldAccountId)
    // The account namespace stays invite-gated through rotation: a statement can
    // only start from an account this Directory already knows.
    if (!from) throw new DirectoryError('not_registered', 'no such account')
    try {
      verifyRotation(st, from.key, Date.now())
    } catch (e) {
      throw new DirectoryError('bad_rotation', String(e instanceof Error ? e.message : e), 400)
    }
    const chainLen = from.chainLen + 1
    if (chainLen > MAX_ROTATION_CHAIN) {
      throw new DirectoryError(
        'too_many_rotations',
        `an account may be rotated at most ${MAX_ROTATION_CHAIN} times`,
        409,
      )
    }
    // Rotating INTO an account that has itself rotated away would make the chain
    // a cycle, and a client walking it would never arrive anywhere.
    const targetMoved = this.sql.exec('SELECT 1 AS x FROM rotations WHERE old_account_id = ?', st.newAccountId).toArray()[0]
    if (targetMoved) {
      throw new DirectoryError('rotation_target_stale', 'that account has itself rotated away', 409)
    }
    // First valid rotation wins, like an invite redemption. A second one to a
    // DIFFERENT key is refused: allowing it would let whoever holds the old key
    // flip a whole contact list back and forth between successors. Repeating the
    // one already recorded answers normally, so retrying an interrupted rotation
    // is safe. Neither is a security control (an attacker holding the old key can
    // simply be the one who publishes first, and can tell contacts directly
    // without the Directory at all); it keeps the record stable and small.
    const existing = this.sql
      .exec('SELECT new_account_id, chain_len FROM rotations WHERE old_account_id = ?', st.oldAccountId)
      .toArray()[0] as { new_account_id: string; chain_len: number } | undefined
    if (existing) {
      if (existing.new_account_id !== st.newAccountId) {
        throw new DirectoryError('rotation_exists', 'that account has already rotated to a different key', 409)
      }
      return { newAccountId: existing.new_account_id, chainLen: existing.chain_len }
    }
    // One write after the reads above, and the DO's turn is single-threaded with
    // nothing awaited in between, so the check and the insert are already atomic.
    this.sql.exec(
      'INSERT INTO rotations (old_account_id, new_account_id, new_account_key, chain_len, blob, created_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?)',
      st.oldAccountId,
      st.newAccountId,
      // Re-encoded from the DECODED bytes rather than stored as the caller wrote
      // it, so the column this Directory later verifies rosters against cannot
      // depend on an encoding quirk in the string it arrived as. The blob below
      // is kept verbatim, because that is what gets served for others to check.
      b64encode(st.newAccountKey),
      chainLen,
      JSON.stringify(body.statement),
      Date.now(),
    )
    return { newAccountId: st.newAccountId, chainLen }
  }

  /** The rotation an account published, or null if it never did (almost all of
   *  them). ONE hop: a chain is followed by asking again for the successor,
   *  because each hop has to be verified under the key the hop before it
   *  introduced, and no server can do that on anyone's behalf. */
  private fetchRotation(body: { accountId: string }): { statement: WireRotationStatement | null } {
    const row = this.sql.exec('SELECT blob FROM rotations WHERE old_account_id = ?', body.accountId).toArray()[0] as
      | { blob: string }
      | undefined
    return { statement: row ? (JSON.parse(row.blob) as WireRotationStatement) : null }
  }

  private fetchBundle(body: FetchBody): { bundle: WireFetchedBundle | null; degraded: boolean } {
    const user = this.sql.exec('SELECT * FROM users WHERE user_id = ?', body.target).toArray()[0] as
      | { ik_sig_pub: string; ik_dh_pub: string; idkbind_sig: string; version: number }
      | undefined
    if (!user) return { bundle: null, degraded: false }

    const spk = this.sql.exec('SELECT * FROM spks WHERE user_id = ?', body.target).toArray()[0] as
      | { spk_id: number; created_at: number; expiry: number; pub: string; sig: string }
      | undefined
    if (!spk) return { bundle: null, degraded: false }

    const opk = this.ctx.storage.transactionSync(() => this.vendOpk(body.fetcher, body.target, body.now))

    const bundle: WireFetchedBundle = {
      version: user.version,
      ikSigPub: user.ik_sig_pub,
      ikDhPub: user.ik_dh_pub,
      idkbindSig: user.idkbind_sig,
      spk: { id: spk.spk_id, createdAt: spk.created_at, expiry: spk.expiry, pub: spk.pub, sig: spk.sig },
      opk: opk ? { id: opk.opk_id, pub: opk.pub } : null,
    }
    return { bundle, degraded: opk === null }
  }

  // One OPK per (fetcher,target), idempotent within OPK_VEND_TTL_MS. A repeat
  // fetch returns the SAME already-vended OPK instead of consuming another; only
  // after the vend window expires is a fresh OPK vended and the stale one dropped.
  private vendOpk(fetcher: string, target: string, now: number): { opk_id: number; pub: string } | null {
    const vend = this.sql
      .exec('SELECT opk_id, expires_at FROM vends WHERE fetcher = ? AND target = ?', fetcher, target)
      .toArray()[0] as { opk_id: number; expires_at: number } | undefined

    if (vend && vend.expires_at > now) {
      const held = this.sql
        .exec('SELECT opk_id, pub FROM opks WHERE user_id = ? AND opk_id = ?', target, vend.opk_id)
        .toArray()[0] as { opk_id: number; pub: string } | undefined
      if (held) return held // idempotent: same OPK to the same fetcher
    }

    if (vend) {
      // A stale vend: drop its (abandoned, single-use) OPK before vending anew.
      this.sql.exec('DELETE FROM opks WHERE user_id = ? AND opk_id = ?', target, vend.opk_id)
      this.sql.exec('DELETE FROM vends WHERE fetcher = ? AND target = ?', fetcher, target)
    }

    const avail = this.sql
      .exec("SELECT opk_id, pub FROM opks WHERE user_id = ? AND status = 'available' ORDER BY opk_id LIMIT 1", target)
      .toArray()[0] as { opk_id: number; pub: string } | undefined
    if (!avail) return null // degraded: no-OPK path (DESIGN 4.3)

    this.sql.exec("UPDATE opks SET status = 'vended' WHERE user_id = ? AND opk_id = ?", target, avail.opk_id)
    this.sql.exec(
      'INSERT OR REPLACE INTO vends (fetcher, target, opk_id, expires_at) VALUES (?, ?, ?, ?)',
      fetcher,
      target,
      avail.opk_id,
      now + OPK_VEND_TTL_MS,
    )
    return avail
  }

  // --- misc --------------------------------------------------------------

  private isRegistered(body: { userId: string }): { registered: boolean; opkCount: number } {
    const user = this.sql.exec('SELECT user_id FROM users WHERE user_id = ?', body.userId).toArray()[0]
    return { registered: !!user, opkCount: user ? this.opkCount(body.userId) : 0 }
  }

  // Purge expired unused invites and long-since-used ones, so the shared
  // Directory does not accumulate invite rows forever (P4 review).
  async alarm(): Promise<void> {
    const now = Date.now()
    this.sql.exec('DELETE FROM invites WHERE used = 0 AND created_at < ?', now - INVITE_TTL_MS)
    this.sql.exec('DELETE FROM invites WHERE used = 1 AND used_at < ?', now - INVITE_TTL_MS)
    const remaining = this.sql.exec('SELECT COUNT(*) AS c FROM invites').toArray()[0] as { c: number }
    if (remaining.c > 0) await this.ctx.storage.setAlarm(now + INVITE_PURGE_INTERVAL_MS)
  }

  private async ensurePurgeAlarm(now: number): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(now + INVITE_PURGE_INTERVAL_MS)
    }
  }

  private opkCount(userId: string): number {
    const row = this.sql
      .exec("SELECT COUNT(*) AS c FROM opks WHERE user_id = ? AND status = 'available'", userId)
      .toArray()[0] as { c: number }
    return row.c
  }
}
