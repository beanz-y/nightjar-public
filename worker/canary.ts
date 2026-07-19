// Serve the operator's signed warrant canary (P7, DESIGN 10.3). Kept in its own
// module (web-standard Request/Response + the Env type only, no Durable Object
// imports) so its full logic is unit-tested in the fast node suite; the miniflare
// suite only has to prove the route is wired ahead of the static-asset fallthrough.
//
// Off-until-configured: a real 404 when CANARY_JSON is unset, so the client can
// tell "the signal was removed" (absent) apart from a routine build. GET/HEAD only;
// the body is served verbatim as JSON with a short cache so a re-signed canary
// propagates well within the freshness window (the signature covers signedAt, so
// edge-caching cannot forge a fresh date). Public read: no auth, no DO, no userId.

import type { Env } from './shared'

export function handleCanary(req: Request, env: Env): Response {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return new Response('method not allowed', { status: 405, headers: { allow: 'GET, HEAD' } })
  }
  if (!env.CANARY_JSON) return new Response('not found', { status: 404 })
  return new Response(req.method === 'HEAD' ? null : env.CANARY_JSON, {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'public, max-age=1800',
    },
  })
}
