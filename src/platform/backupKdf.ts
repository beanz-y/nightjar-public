// Browser-side BackupKdf: Argon2id in a dedicated worker, falling back to the
// main thread when workers are unavailable or fail to load (the derivation
// still completes; the page just freezes for its duration). The crypto layer
// (src/crypto/backup.ts) stays platform-free via the injectable kdf seam.

import { type BackupKdf, argon2idKdf } from '../crypto/backup'

export function createBackupKdf(): BackupKdf {
  return async (pass, salt, params) => {
    if (typeof Worker === 'undefined') return argon2idKdf(pass, salt, params)

    const viaWorker = () =>
      new Promise<Uint8Array>((resolve, reject) => {
        const worker = new Worker(new URL('./argon2Worker.ts', import.meta.url), { type: 'module' })
        const done = (fn: () => void) => {
          worker.terminate()
          fn()
        }
        worker.onmessage = (ev) => {
          const d = ev.data as { ok?: ArrayBuffer; err?: string }
          if (d && d.ok) done(() => resolve(new Uint8Array(d.ok as ArrayBuffer)))
          else done(() => reject(new Error(d?.err ?? 'kdf worker returned no result')))
        }
        worker.onerror = () => done(() => reject(new Error('kdf worker failed to run')))
        worker.postMessage({ pass, salt, m: params.m, t: params.t, p: params.p })
      })

    try {
      return await viaWorker()
    } catch {
      // Constructor threw, the module failed to load, or the worker errored:
      // fall back to the main thread so backup/restore still works.
      return argon2idKdf(pass, salt, params)
    }
  }
}
