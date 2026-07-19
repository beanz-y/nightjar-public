// Shared types and helpers for the Nightjar relay Worker + Durable Objects.

/** userId = lowercase, unpadded base32 of SHA-256(IK_sig_pub): 52 chars over the
 *  RFC 4648 base32 alphabet (a-z, 2-7). Used to validate routing keys before we
 *  ever touch a Durable Object. */
export const USER_ID_RE = /^[a-z2-7]{52}$/

export interface Env {
  ASSETS: Fetcher
  DIRECTORY: DurableObjectNamespace
  INBOX: DurableObjectNamespace
  /** Optional admin bearer token for minting the bootstrap invite. When unset,
   *  the /admin/invite endpoint is a 404 (off-until-secret, like Mirkwood). */
  ADMIN_TOKEN?: string
  /** Optional VAPID private JWK (P-256) that signs Web Push requests (P6, DESIGN
   *  7.4). When unset, push is a silent no-op (off-until-secret). Generate with
   *  tools/vapid-keys.mjs; set as a Cloudflare dashboard Secret. */
  VAPID_JWK?: string
  /** Optional contact (mailto:/https:) the push service may use; defaults to a
   *  built-in mailto. */
  VAPID_SUBJECT?: string
  /** Optional signed warrant-canary document served at GET /canary.json (P7,
   *  DESIGN 10.3). This is PUBLIC signed data, not a secret: it is set as a plain
   *  dashboard var so the operator can refresh it (~monthly) without a rebuild, and
   *  it stays out of the hashed build tree. When unset the route returns a real
   *  404 (off-until-configured); the client then reports `unconfigured`/`absent`
   *  depending on whether a public key is pinned in the build. */
  CANARY_JSON?: string
}

export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

/** The http(s) origin of a request, normalising any ws/wss scheme back to
 *  http/https so it matches the browser's location.origin (which the client
 *  compares the auth challenge against, DESIGN 7.3). */
export function httpOrigin(req: Request): string {
  const origin = new URL(req.url).origin
  return origin.replace(/^ws(s?):\/\//, 'http$1://')
}

/** Length-safe, content-constant-time string compare, for the admin token. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/** The single Directory DO instance. */
export function directoryStub(env: Env): DurableObjectStub {
  return env.DIRECTORY.get(env.DIRECTORY.idFromName('main'))
}

/** The Inbox DO for a given user id. */
export function inboxStub(env: Env, userId: string): DurableObjectStub {
  return env.INBOX.get(env.INBOX.idFromName(userId))
}

/** Call an internal DO JSON endpoint (synthetic host; only path + body matter). */
export async function callDO<T>(stub: DurableObjectStub, path: string, body: unknown): Promise<T> {
  const res = await stub.fetch(`https://do${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = (await res.json()) as T
  if (!res.ok) {
    const err = data as { code?: string; msg?: string }
    throw new DirectoryError(err.code ?? 'internal', err.msg ?? 'internal error', res.status)
  }
  return data
}

/** An error carrying a stable code + HTTP status, surfaced to the client as an
 *  { t:'error' } message. */
export class DirectoryError extends Error {
  constructor(
    readonly code: string,
    msg: string,
    readonly status = 400,
  ) {
    super(msg)
  }
}
