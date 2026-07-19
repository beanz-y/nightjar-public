// Web Push crypto known-answer tests (P6), run in the real workerd runtime (the
// Worker's own environment). The preview cannot grant push permission and no push
// service accepts a made-up subscription, so the closed-app tier can't be driven
// end-to-end; what CAN be proved offline is the part that would fail SILENTLY on a
// real device (a browser drops a payload it cannot decrypt, with no visible
// error): the RFC 8291 encryption. So we pin the RFC's own worked example -- given
// its fixed keys and salt, encryptPayload must reproduce its published body byte
// for byte. Plus the SSRF endpoint allowlist and the VAPID public-key derivation.
//
// Lives in the workers pool (not the node suite) so worker/push.ts is only ever
// typechecked under @cloudflare/workers-types, and the crypto runs on the same
// WebCrypto the Worker uses in production.

import { describe, expect, it } from 'vitest'
import { encryptPayload, isAllowedPushEndpoint, pushConfigured, vapidPublicKey } from '../../worker/push'
import type { Env } from '../../worker/shared'

const b64urlDecode = (str: string): Uint8Array => {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
const b64urlEncode = (bytes: Uint8Array): string => {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// Values transcribed verbatim from RFC 8291 section 5.
const RFC = {
  plaintext: 'When I grow up, I want to be a watermelon',
  auth: 'BTBZMqHH6r4Tts7J_aSIgg',
  uaPublic: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  asPublic: 'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  asPrivate: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
  salt: 'DGv6ra1nlYgDCS1FRnbzlw',
  body:
    'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml' +
    'mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT' +
    'pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
}

describe('RFC 8291 section 5 push encryption example', () => {
  it('reproduces the RFC body byte for byte from its fixed salt + keypair', async () => {
    const asPoint = b64urlDecode(RFC.asPublic)
    const asKeys = {
      privateKey: await crypto.subtle.importKey(
        'jwk',
        {
          kty: 'EC',
          crv: 'P-256',
          x: b64urlEncode(asPoint.slice(1, 33)),
          y: b64urlEncode(asPoint.slice(33, 65)),
          d: RFC.asPrivate,
        },
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits'],
      ),
      publicKey: await crypto.subtle.importKey('raw', asPoint, { name: 'ECDH', namedCurve: 'P-256' }, true, []),
    }
    const body = await encryptPayload(RFC.plaintext, RFC.uaPublic, RFC.auth, { salt: b64urlDecode(RFC.salt), asKeys })
    expect(b64urlEncode(body)).toBe(RFC.body)
    // Structure, so a mismatch above is diagnosable rather than just "different".
    expect(body.length).toBe(144) // 16 salt + 4 rs + 1 idlen + 65 key + 58 ciphertext
    expect(b64urlEncode(body.slice(0, 16))).toBe(RFC.salt)
    expect(body[20]).toBe(65)
    expect(b64urlEncode(body.slice(21, 86))).toBe(RFC.asPublic)
  })

  it('a real browser can decrypt a fresh (random salt + keypair) payload', async () => {
    const uaPoint = b64urlDecode(RFC.uaPublic)
    const uaPriv = await crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC',
        crv: 'P-256',
        x: b64urlEncode(uaPoint.slice(1, 33)),
        y: b64urlEncode(uaPoint.slice(33, 65)),
        d: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94', // RFC's ua_private
      },
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    )
    const msg = await encryptPayload('hello nightjar', RFC.uaPublic, RFC.auth)
    const salt = msg.slice(0, 16)
    const asPub = msg.slice(21, 21 + msg[20])
    const ciphertext = msg.slice(21 + msg[20])
    const asKey = await crypto.subtle.importKey('raw', asPub, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: asKey }, uaPriv, 256))
    const hkdf = async (s: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number) => {
      const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
      return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: s, info }, k, len * 8))
    }
    const cat = (...a: Uint8Array[]) => {
      const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0))
      let at = 0
      for (const x of a) {
        o.set(x, at)
        at += x.length
      }
      return o
    }
    const TE = (s: string) => new TextEncoder().encode(s)
    const keyInfo = cat(TE('WebPush: info'), new Uint8Array([0]), uaPoint, asPub)
    const ikm = await hkdf(b64urlDecode(RFC.auth), shared, keyInfo, 32)
    const cek = await hkdf(salt, ikm, cat(TE('Content-Encoding: aes128gcm'), new Uint8Array([0])), 16)
    const nonce = await hkdf(salt, ikm, cat(TE('Content-Encoding: nonce'), new Uint8Array([0])), 12)
    const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt'])
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ciphertext))
    expect(new TextDecoder().decode(plain.slice(0, -1))).toBe('hello nightjar')
  })
})

describe('VAPID public key derivation', () => {
  it('derives the uncompressed P-256 point from the private JWK', async () => {
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const jwk = await crypto.subtle.exportKey('jwk', keys.privateKey)
    const env = { VAPID_JWK: JSON.stringify({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d }) } as Env
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))
    expect(vapidPublicKey(env)).toBe(b64urlEncode(raw))
  })

  it('pushConfigured is false until VAPID_JWK is set', () => {
    expect(pushConfigured({} as Env)).toBe(false)
    expect(pushConfigured({ VAPID_JWK: '{"kty":"EC"}' } as Env)).toBe(true)
  })
})

describe('push endpoint SSRF allowlist', () => {
  it('accepts the real push services and their subdomains', () => {
    for (const ok of [
      'https://updates.push.services.mozilla.com/wpush/v2/abc',
      'https://fcm.googleapis.com/fcm/send/abc',
      'https://db5p.notify.windows.com/w/?token=abc',
      'https://web.push.apple.com/xyz',
      'https://push.services.mozilla.com/x', // exact allowed host
      'https://fcm.googleapis.com./x', // FQDN trailing dot
    ]) {
      expect(isAllowedPushEndpoint(ok), ok).toBe(true)
    }
  })

  it('rejects look-alikes, userinfo tricks, non-https, and junk', () => {
    for (const bad of [
      'https://fcm.googleapis.com.evil.com/x', // suffix look-alike
      'https://evilfcm.googleapis.com/x', // not a dot-delimited subdomain
      'https://fcm.googleapis.com@evil.com/x', // userinfo host confusion
      'http://fcm.googleapis.com/x', // not https
      'https://evil.com/fcm.googleapis.com', // path, not host
      'https://internal.local/x',
      'http://169.254.169.254/latest/meta-data', // cloud metadata
      'not a url',
      '',
    ]) {
      expect(isAllowedPushEndpoint(bad), bad).toBe(false)
    }
  })
})
