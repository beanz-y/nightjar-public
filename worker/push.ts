// Web Push for Nightjar (P6, DESIGN 7.4) -- the tier that reaches a CLOSED or
// backgrounded installed app. A message delivered over the live WebSocket only
// reaches a foreground page; a real push is delivered by the browser's push
// service, so the app need not be running at all.
//
// Lifted near-verbatim from Mirkwood's proven worker/push.js (typed here). Two
// specs are in play, both implemented below:
//   - RFC 8291: the payload is encrypted end-to-end (aes128gcm) with keys only
//     the subscribing browser holds. The push service relays ciphertext it
//     cannot read. In Nightjar the payload is additionally CONTENT-FREE (no
//     plaintext, no ciphertext, no sender id) -- the service worker only shows a
//     "new secure message" nudge and never advances the ratchet (DESIGN 7.4).
//   - RFC 8292 (VAPID): each request is signed with our private key so the push
//     service can tell who is sending, and only we can push to our subscribers.
//
// Off-until-secret: every entry point is a silent no-op unless VAPID_JWK is
// configured, so the repo carries no key material and push stays off until the
// secret is set in the Cloudflare dashboard (see tools/vapid-keys.mjs).
//
// Crypto is checked offline against the RFC 8291 section 5 worked example in
// test/push.test.ts.

import type { Env } from './shared'

/** A stored Web Push subscription (the browser's PushSubscription, split out). */
export interface PushSub {
  endpoint: string
  p256dh: string
  auth: string
}

// A neutral placeholder so the public source carries no operator-identity trace
// (DESIGN 10). The real deployment sets VAPID_SUBJECT (a mailto:/https: contact
// the push service may use) as a dashboard var; this default only applies if it is
// left unset.
const DEFAULT_SUBJECT = 'mailto:admin@example.invalid'

// How long the push service keeps trying if the device is offline. A message
// nudge that lands hours later is still useful, but not indefinitely.
const PUSH_TTL = 24 * 3600

// RFC 8188 record size. Our payloads are a few hundred bytes; one record.
const RECORD_SIZE = 4096

// Known Web Push service hosts (DESIGN 7.4: "checked against an allowlist of
// known push origins"). The Inbox does a SERVER-SIDE fetch(endpoint), so without
// this a registered user could register an endpoint for their own inbox pointing
// at an arbitrary host and, by getting others to message them, make our Worker
// POST to it (SSRF / reflection). We fetch ONLY these providers.
//   - Mozilla autopush (Firefox, and de-Googled Android / Linux via Firefox)
//   - FCM (Chrome / Chromium with Play Services)
//   - WNS (Edge)
//   - Apple (Safari / iOS web push)
const PUSH_HOSTS = ['push.services.mozilla.com', 'fcm.googleapis.com', 'notify.windows.com', 'push.apple.com']

/** Is this a well-formed https endpoint on a known push service? Rejects
 *  userinfo tricks, look-alike suffixes (fcm.googleapis.com.evil.com), FQDN
 *  trailing dots, and non-https. Host must be an allowed host or a dot-delimited
 *  subdomain of one. */
export function isAllowedPushEndpoint(endpoint: string): boolean {
  let url: URL
  try {
    url = new URL(endpoint)
  } catch {
    return false
  }
  if (url.protocol !== 'https:') return false
  if (url.username !== '' || url.password !== '') return false
  let host = url.hostname.toLowerCase()
  if (host.endsWith('.')) host = host.slice(0, -1)
  return PUSH_HOSTS.some((h) => host === h || host.endsWith('.' + h))
}

const TE = (s: string): Uint8Array => new TextEncoder().encode(s)

function b64urlEncode(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64urlDecode(str: string): Uint8Array {
  const b64 = String(str).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

// HKDF (RFC 5869). Web Push chains two of these: once to mix the subscription's
// auth secret into the ECDH secret, then once per derived value (key, nonce).
async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, bytes: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8)
  return new Uint8Array(bits)
}

interface VapidJwk {
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
  d: string
  ext?: boolean
}

// A pasted secret may carry fields (use, key_ops, alg) that make importKey
// reject it for signing, so rebuild the JWK from just the parts that matter.
function parseJwk(env: Env): VapidJwk {
  const jwk = JSON.parse(env.VAPID_JWK as string) as Partial<VapidJwk>
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d || !jwk.x || !jwk.y) {
    throw new Error('VAPID_JWK is not a P-256 private JWK (expected kty EC, crv P-256, with d/x/y)')
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d, ext: true }
}

export function pushConfigured(env: Env): boolean {
  return !!(env && env.VAPID_JWK)
}

// The applicationServerKey the browser must subscribe with: the uncompressed
// P-256 point (0x04 || x || y) rebuilt from the private JWK it is signed by.
export function vapidPublicKey(env: Env): string {
  const jwk = parseJwk(env)
  return b64urlEncode(concat(new Uint8Array([4]), b64urlDecode(jwk.x), b64urlDecode(jwk.y)))
}

interface EncryptOpts {
  salt?: Uint8Array
  asKeys?: CryptoKeyPair
}

/*
 * RFC 8291 section 3.4 + RFC 8188. Returns the complete request body:
 *   salt(16) || rs(4) || idlen(1) || as_public(65) || aes128gcm ciphertext
 *
 * `opts.salt` and `opts.asKeys` exist so the test can pin the RFC's fixed values
 * and compare against its published body; production passes neither and gets a
 * fresh random salt and ephemeral keypair per message (required: the key/nonce
 * must never repeat).
 */
export async function encryptPayload(
  plaintext: string,
  p256dh: string,
  auth: string,
  opts: EncryptOpts = {},
): Promise<Uint8Array> {
  const uaPublic = b64urlDecode(p256dh)
  const authSecret = b64urlDecode(auth)
  const salt = opts.salt || crypto.getRandomValues(new Uint8Array(16))
  // Casts keep this source typechecking under BOTH @cloudflare/workers-types (the
  // Worker) and the Node/DOM lib (the node test importing this module): the two
  // disagree on generateKey/exportKey return unions and on the ECDH derive-param
  // name (workers-types calls it `$public`; the runtime uses the standard
  // `public`). At runtime workerd implements standard WebCrypto, so `public` is
  // correct; the KAT in push.test.ts proves the bytes.
  const asKeys: CryptoKeyPair =
    opts.asKeys ||
    ((await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair)
  const asPublic = new Uint8Array((await crypto.subtle.exportKey('raw', asKeys.publicKey)) as ArrayBuffer)

  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const deriveAlg = { name: 'ECDH', public: uaKey } as unknown as Parameters<typeof crypto.subtle.deriveBits>[0]
  const shared = new Uint8Array(await crypto.subtle.deriveBits(deriveAlg, asKeys.privateKey, 256))

  // The auth secret is the salt here, binding the keys to this subscription.
  const keyInfo = concat(TE('WebPush: info'), new Uint8Array([0]), uaPublic, asPublic)
  const ikm = await hkdf(authSecret, shared, keyInfo, 32)
  const cek = await hkdf(salt, ikm, concat(TE('Content-Encoding: aes128gcm'), new Uint8Array([0])), 16)
  const nonce = await hkdf(salt, ikm, concat(TE('Content-Encoding: nonce'), new Uint8Array([0])), 12)

  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt'])
  // 0x02 delimits the last (only) record; 0x01 would mean more follow.
  const padded = concat(TE(plaintext), new Uint8Array([2]))
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, padded))

  const header = new Uint8Array(21)
  header.set(salt, 0)
  new DataView(header.buffer).setUint32(16, RECORD_SIZE)
  header[20] = asPublic.length // 65
  return concat(header, asPublic, ciphertext)
}

/*
 * RFC 8292: a short-lived ES256 JWT scoped to the push service's origin, plus
 * our public key, so the service can authenticate the sender. WebCrypto's ECDSA
 * signature is already the raw r||s that JWS wants.
 */
export async function vapidAuth(env: Env, endpoint: string, now = Date.now()): Promise<string> {
  const jwk = parseJwk(env)
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  const header = b64urlEncode(TE(JSON.stringify({ typ: 'JWT', alg: 'ES256' })))
  const claims = b64urlEncode(
    TE(
      JSON.stringify({
        aud: new URL(endpoint).origin,
        exp: Math.floor(now / 1000) + 12 * 3600, // spec caps this at 24h
        sub: env.VAPID_SUBJECT || DEFAULT_SUBJECT,
      }),
    ),
  )
  const unsigned = `${header}.${claims}`
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, TE(unsigned))
  return `vapid t=${unsigned}.${b64urlEncode(sig)}, k=${vapidPublicKey(env)}`
}

export interface PushResult {
  ok: boolean
  skipped?: boolean
  status?: number
  gone?: boolean
  error?: string
}

// The ONLY notification Nightjar ever sends: content-free (no plaintext, no
// ciphertext, no sender id, no envelope id). The service worker shows this fixed
// text verbatim and never advances the ratchet (DESIGN 7.4). Hardcoded here so no
// call site can inject message content onto a lockscreen (red-team M2).
export const NUDGE_PAYLOAD = { title: 'Nightjar', body: 'New secure message' } as const

/** Abort a push fetch that hangs, so the relay's deliver path is never coupled
 *  to push-service latency for long (red-team M5). */
const PUSH_FETCH_TIMEOUT_MS = 10_000

/*
 * Deliver one push. Never throws: a push failing must not disturb the relay.
 * `gone` marks a subscription the browser has discarded (uninstalled, permission
 * revoked, expired) so the caller can forget it. The endpoint is checked against
 * the push-service allowlist first (SSRF guard, DESIGN 7.4), and redirects are
 * NOT followed (`redirect:'manual'`): a push service does not legitimately
 * redirect a signed POST, and following one could carry our VAPID JWT + body to
 * an arbitrary host. A 3xx therefore surfaces as a plain failure (ok:false), NOT
 * as `gone`, so the subscription is retried rather than pruned.
 */
async function sendPush(
  env: Env,
  sub: PushSub,
  payload: unknown,
  opts: EncryptOpts & { ttl?: number } = {},
): Promise<PushResult> {
  if (!pushConfigured(env)) return { ok: false, skipped: true }
  if (!isAllowedPushEndpoint(sub.endpoint)) return { ok: false, error: 'endpoint not on push-service allowlist' }
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), PUSH_FETCH_TIMEOUT_MS)
  try {
    const body = await encryptPayload(JSON.stringify(payload), sub.p256dh, sub.auth, opts)
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      redirect: 'manual',
      signal: ac.signal,
      headers: {
        Authorization: await vapidAuth(env, sub.endpoint),
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        TTL: String(opts.ttl ?? PUSH_TTL),
        Urgency: 'high',
      },
      body,
    })
    return {
      ok: res.ok,
      status: res.status,
      // 404/410: the subscription no longer exists and never will again.
      gone: res.status === 404 || res.status === 410,
    }
  } catch (e) {
    return { ok: false, error: String((e as Error)?.message || e).slice(0, 200) }
  } finally {
    clearTimeout(timer)
  }
}

/** Send the one content-free nudge to a subscription. The relay's only entry
 *  point into push: it cannot choose the payload, so nothing on a lockscreen can
 *  ever be message-derived (red-team M2). */
export function sendNudge(env: Env, sub: PushSub, opts: EncryptOpts & { ttl?: number } = {}): Promise<PushResult> {
  return sendPush(env, sub, NUDGE_PAYLOAD, opts)
}
