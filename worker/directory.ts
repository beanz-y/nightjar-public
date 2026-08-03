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
  OPK_VEND_TTL_MS,
  SPK_MAX_AGE_MS,
  TAG_SPK,
  VERSION_FLOOR,
} from '../src/crypto/constants'
import { deriveUserId } from '../src/crypto/identity'
import { domainSeparate, ed25519Verify, u32be, u64be } from '../src/crypto/primitives'
import { type FetchedBundle, type SignedPrekey, verifyFetchedBundle } from '../src/crypto/prekeys'
import { verifyRoster } from '../src/crypto/roster'
import {
  type WireDeviceRoster,
  type WireFetchedBundle,
  type WireOneTimePrekey,
  type WirePublishedBundle,
  type WireSignedPrekey,
  b64decode,
  decodeDeviceRoster,
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
        case '/fetchRoster':
          return json(this.fetchRoster((await req.json()) as { accountId: string }))
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
    // The account key is the identity key registered under the account id. On an
    // account's first device those are the same key, which is what lets an
    // existing single-device user become a one-device account with nothing moving.
    const owner = this.sql.exec('SELECT ik_sig_pub FROM users WHERE user_id = ?', roster.accountId).toArray()[0] as
      | { ik_sig_pub: string }
      | undefined
    if (!owner) throw new DirectoryError('not_registered', 'no such account')
    try {
      verifyRoster(roster, b64decode(owner.ik_sig_pub, 32), Date.now())
    } catch (e) {
      throw new DirectoryError('bad_roster', String(e instanceof Error ? e.message : e), 400)
    }
    // Monotonic, and equal versions are refused for the same reason the client
    // refuses them: two different rosters at one version means something is wrong.
    const current = this.sql.exec('SELECT version FROM rosters WHERE account_id = ?', roster.accountId).toArray()[0] as
      | { version: number }
      | undefined
    if (current && roster.version <= current.version) {
      throw new DirectoryError('stale_roster', `roster version ${roster.version} does not follow ${current.version}`, 409)
    }
    this.sql.exec(
      'INSERT INTO rosters (account_id, version, blob, updated_at) VALUES (?, ?, ?, ?) ' +
        'ON CONFLICT(account_id) DO UPDATE SET version = excluded.version, blob = excluded.blob, updated_at = excluded.updated_at',
      roster.accountId,
      roster.version,
      JSON.stringify(body.roster),
      Date.now(),
    )
    return { version: roster.version }
  }

  /** The account's current roster, or null if it has never published one (which
   *  is every account until it links a second device). A null is not an error:
   *  the caller treats the account as a single device at its account id. */
  private fetchRoster(body: { accountId: string }): { roster: WireDeviceRoster | null } {
    const row = this.sql.exec('SELECT blob FROM rosters WHERE account_id = ?', body.accountId).toArray()[0] as
      | { blob: string }
      | undefined
    return { roster: row ? (JSON.parse(row.blob) as WireDeviceRoster) : null }
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
