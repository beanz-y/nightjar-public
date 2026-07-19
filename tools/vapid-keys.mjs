/*
 * Generate the VAPID keypair that signs Nightjar's push notifications (P6,
 * DESIGN 7.4). Web Push is entirely OFF until this secret is set, so the repo
 * carries no key material (off-until-secret, like ADMIN_TOKEN).
 *
 *   node tools/vapid-keys.mjs
 *
 * Prints one JSON line to paste into the Cloudflare dashboard as the secret
 * VAPID_JWK (Workers & Pages -> nightjar -> Settings -> Variables and Secrets,
 * type "Secret" -- NOT a Build variable, which never reaches the running
 * Worker). Nothing else to configure: the public application-server key the
 * browser subscribes with is DERIVED from this JWK at runtime and handed to the
 * client in the authenticated `authed` message, so the two can never drift.
 *
 * Optional second var VAPID_SUBJECT (a mailto: or https: contact the push
 * service may use); if unset the Worker falls back to a neutral placeholder.
 * Set your real contact in the dashboard, not in source.
 *
 * No npm dependency and no wrangler CLI -- just Node's WebCrypto, the same
 * primitives the Worker uses (worker/push.ts).
 *
 * This key is the identity of Nightjar's push sender. Treat the private half
 * like any other secret: dashboard only, never the repo. Losing it is
 * survivable (generate a new one), but every existing subscription stops working
 * until each device toggles notifications off and on again.
 */

const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])

const jwk = await crypto.subtle.exportKey('jwk', keys.privateKey)
// Only the parts the Worker needs, so a stray "use"/"key_ops" field can never
// make importKey reject the pasted secret.
const secret = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d }

const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))
const publicKey = Buffer.from(raw).toString('base64url')

console.log('\nVAPID_JWK  (paste as a Secret in the Cloudflare dashboard)')
console.log('-----------------------------------------------------------')
console.log(JSON.stringify(secret))
console.log('\npublic key (informational -- the Worker derives this itself and')
console.log('            hands it to the client over the authenticated socket)')
console.log('-----------------------------------------------------------')
console.log(publicKey)
console.log("\nAfter saving the secret, confirm the dashboard's deploy prompt so a")
console.log('new version ships; then enable notifications in the app to subscribe.\n')
