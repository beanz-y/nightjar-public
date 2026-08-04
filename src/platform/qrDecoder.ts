// The seam between the scan loop and the pure-JS QR decoder.
//
// Two jobs, and the second is the one that makes the scanner work at all:
//
//  1. Run the decoder in a worker when the browser has one, falling back to the
//     main thread when it does not, so scanning degrades rather than breaks.
//  2. NEVER QUEUE. A scan loop runs on animation frames, which arrive far faster
//     than a decode completes. Awaiting a backlog would mean each answer
//     describing a frame from further and further in the past, so a busy decoder
//     reports "nothing this time" immediately and the loop simply looks again.
//     Dropping frames is free here: the code being read repeats forever.
//
// jsQR is imported STATICALLY, so the main-thread fallback lives in the single
// hash-pinned bundle (DESIGN 10.2). The worker gets its own copy in its own
// chunk, which the release hash still covers because that digests every file in
// the build.

import jsQR from 'jsqr'

let worker: Worker | null | undefined // undefined = not tried yet
let busy = false
let seq = 0
const waiting = new Map<number, (text: string | null) => void>()

function ensureWorker(): Worker | null {
  if (worker !== undefined) return worker
  if (typeof Worker === 'undefined') {
    worker = null
    return null
  }
  try {
    const w = new Worker(new URL('./qrWorker.ts', import.meta.url), { type: 'module' })
    w.onmessage = (ev: MessageEvent) => {
      const { id, text } = ev.data as { id: number; text: string | null }
      const resolve = waiting.get(id)
      waiting.delete(id)
      busy = false
      resolve?.(text)
    }
    w.onerror = () => {
      // The worker died. Fail every caller waiting on it, then fall back to the
      // main thread for the rest of the session rather than retrying forever.
      for (const resolve of waiting.values()) resolve(null)
      waiting.clear()
      busy = false
      worker = null
    }
    worker = w
  } catch {
    worker = null
  }
  return worker
}

/** True when a decode is already running, so the caller should skip this frame
 *  WITHOUT doing the capture work for it. Checked before touching the canvas,
 *  since rasterizing a frame nobody will look at is the same waste in miniature. */
export function decoderBusy(): boolean {
  return busy && worker !== null && worker !== undefined
}

/**
 * Decode one frame. `image.data.buffer` is TRANSFERRED to the worker, so the
 * caller must not reuse it afterwards; every call site hands over a freshly
 * captured frame, which is why that is safe.
 *
 * Returns null for "no code in this frame", and also for "the decoder was busy
 * or unavailable", because to a scan loop those mean the same thing: look again.
 */
export async function decodeImage(image: ImageData): Promise<string | null> {
  const w = ensureWorker()
  if (!w) return decodeOnMainThread(image)
  if (busy) return null
  busy = true
  const id = ++seq
  return new Promise<string | null>((resolve) => {
    waiting.set(id, resolve)
    try {
      w.postMessage({ id, data: image.data.buffer, width: image.width, height: image.height }, [image.data.buffer])
    } catch {
      // postMessage can throw on a detached buffer or a dead worker; treat it as
      // a miss rather than letting it escape into the scan loop.
      waiting.delete(id)
      busy = false
      resolve(null)
    }
  })
}

/** Fallback for a browser with no workers at all. The decoder is a STATIC import
 *  (see the top of this file), never a dynamic one: a dynamically imported chunk
 *  carries no integrity attribute and would be refused outright by
 *  `Integrity-Policy: blocked-destinations=(script)` (DESIGN 10.2), so the
 *  fallback has to live in the one hash-pinned bundle. It costs the very freeze
 *  this file exists to avoid, which is why it is the last resort rather than the
 *  design. */
function decodeOnMainThread(image: ImageData): string | null {
  return jsQR(image.data, image.width, image.height, { inversionAttempts: 'dontInvert' })?.data ?? null
}

/** Shut the worker down when scanning stops, so a camera screen that has been
 *  closed is not holding a thread and a megabyte of decoder state. Safe to call
 *  when none was ever started. */
export function releaseQrDecoder(): void {
  if (worker) worker.terminate()
  worker = undefined
  busy = false
  waiting.clear()
}
