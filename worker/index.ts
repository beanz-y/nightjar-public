// Nightjar relay Worker (DESIGN 7). A thin router in front of two Durable Object
// classes; it serves the static PWA for everything else. Public surface:
//   GET  /connect?u=<userId>   upgrade to the user's authenticated Inbox socket
//   POST /admin/invite         mint the bootstrap invite (ADMIN_TOKEN gated)
//   GET  /health               liveness probe
// Everything a client does after connecting rides the WebSocket (see inbox.ts);
// the Directory DO is reached only internally, never from the public edge.

import { formatInviteCode } from '../src/server/invites'
import { handleCanary } from './canary'
import { Directory } from './directory'
import { Inbox } from './inbox'
import { type Env, USER_ID_RE, callDO, directoryStub, inboxStub, json, safeEqual } from './shared'

// The DO classes must be exported from the Worker's main module (wrangler.jsonc).
export { Directory, Inbox }

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url)

    if (url.pathname === '/connect') {
      if ((req.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') {
        return new Response('expected a websocket', { status: 426 })
      }
      const u = url.searchParams.get('u') ?? ''
      if (!USER_ID_RE.test(u)) return new Response('bad user id', { status: 400 })
      // Route to this user's Inbox; forward the request verbatim so the Upgrade
      // handshake completes inside the DO.
      return inboxStub(env, u).fetch(new Request(url.toString(), req))
    }

    if (url.pathname === '/admin/invite' && req.method === 'POST') {
      return handleAdminInvite(req, env)
    }

    if (url.pathname === '/health') return json({ ok: true })

    // The warrant canary (P7, DESIGN 10.3). MUST be matched here for ALL methods,
    // BEFORE the ASSETS fallthrough: the SPA fallback would otherwise return
    // index.html/200 for an unset canary, and the client would mis-parse HTML as a
    // canary. Public read (no auth, no DO, no userId); public signed data.
    if (url.pathname === '/canary.json') return handleCanary(req, env)

    // Everything else is the static PWA (index.html for unknown SPA routes).
    return env.ASSETS.fetch(req)
  },
}

// Bootstrap invite minting. Off entirely until an ADMIN_TOKEN secret is set in
// the dashboard (off-until-secret, like Mirkwood's telemetry). Lets the operator
// mint the first invite to register user zero without a land-grab; after that,
// registered users mint invites for each other over their authenticated session.
async function handleAdminInvite(req: Request, env: Env): Promise<Response> {
  if (!env.ADMIN_TOKEN) return new Response('not found', { status: 404 })
  const header = req.headers.get('Authorization') ?? ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : ''
  if (token.length === 0 || !safeEqual(token, env.ADMIN_TOKEN)) {
    return new Response('unauthorized', { status: 401 })
  }
  try {
    const r = await callDO<{ code: string }>(directoryStub(env), '/mintInvite', {
      inviter: '@admin',
      now: Date.now(),
    })
    return json({ code: r.code, formatted: formatInviteCode(r.code) })
  } catch (e) {
    return json({ code: 'internal', msg: String(e instanceof Error ? e.message : e) }, 500)
  }
}
