// Dedicated worker: runs Argon2id off the main thread so sealing or unlocking
// a backup (a multi-second, memory-hard derivation by design) never freezes the
// UI. Same-origin module worker; allowed under the strict CSP (default-src
// 'self'). Input and output are structured-clone / transfer only.

import { argon2id } from '@noble/hashes/argon2'

interface KdfRequest {
  pass: Uint8Array
  salt: Uint8Array
  m: number
  t: number
  p: number
}

const scope = self as unknown as {
  onmessage: ((ev: MessageEvent) => void) | null
  postMessage: (msg: unknown, transfer?: Transferable[]) => void
}

scope.onmessage = (ev: MessageEvent) => {
  const { pass, salt, m, t, p } = ev.data as KdfRequest
  try {
    const out = argon2id(pass, salt, { m, t, p, dkLen: 32 })
    scope.postMessage({ ok: out.buffer }, [out.buffer])
  } catch (e) {
    scope.postMessage({ err: String(e instanceof Error ? e.message : e) })
  }
}
