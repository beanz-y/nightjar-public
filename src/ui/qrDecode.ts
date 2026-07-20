// QR decoding for the in-app camera scanner. Two backends behind one call:
//   1. the browser's native BarcodeDetector (fast, hardware-accelerated where
//      present: Chrome, most Android, newer Safari), used first when available;
//   2. a bundled pure-JS decoder (jsQR) as the fallback, so scanning also works
//      on Firefox desktop and de-Googled browsers the project steers privacy
//      users toward. jsQR is pure JavaScript with no dependencies, no network,
//      and no wasm, so it stays clean under the strict CSP.
//
// The payloads scanned here are never secret (an invite URL/code or a public
// userId is meant to be shared), so decoding leaks nothing.
//
// jsQR is a STATIC import so it lands in the one SRI-pinned app bundle rather
// than a separate runtime-loaded chunk: a dynamically imported chunk would carry
// no integrity attribute and be blocked by the Integrity-Policy header (DESIGN
// 10.2), and a security app is better served by one auditable, hash-pinned
// bundle anyway. jsQR is pure JS with no dependencies; it is only EXECUTED on
// browsers without a native BarcodeDetector (e.g. Firefox), never run otherwise.

import jsQR from 'jsqr'

type BarcodeDetectorLike = {
  detect(source: CanvasImageSource): Promise<Array<{ rawValue: string }>>
}
type BarcodeDetectorCtor = {
  new (opts?: { formats?: string[] }): BarcodeDetectorLike
  getSupportedFormats?: () => Promise<string[]>
}

let nativeDetector: BarcodeDetectorLike | null | undefined // undefined = not probed yet

/** Resolve a native QR-capable BarcodeDetector once, or null if unavailable. */
async function getNativeDetector(): Promise<BarcodeDetectorLike | null> {
  if (nativeDetector !== undefined) return nativeDetector
  const Ctor = (globalThis as { BarcodeDetector?: BarcodeDetectorCtor }).BarcodeDetector
  if (!Ctor) {
    nativeDetector = null
    return null
  }
  try {
    if (Ctor.getSupportedFormats) {
      const formats = await Ctor.getSupportedFormats()
      if (!formats.includes('qr_code')) {
        nativeDetector = null
        return null
      }
    }
    nativeDetector = new Ctor({ formats: ['qr_code'] })
  } catch {
    nativeDetector = null
  }
  return nativeDetector
}

/**
 * Decode a QR from one video frame. Returns the decoded string, or null if no
 * QR is visible (the caller keeps sampling). Never throws.
 */
export async function decodeQrFrame(video: HTMLVideoElement, canvas: HTMLCanvasElement): Promise<string | null> {
  const w = video.videoWidth
  const h = video.videoHeight
  if (!w || !h) return null

  // Native path first: hand the video element straight to the detector.
  const detector = await getNativeDetector()
  if (detector) {
    try {
      const found = await detector.detect(video)
      const hit = found.find((b) => b.rawValue)
      if (hit) return hit.rawValue
      return null // native ran but saw nothing; do NOT fall through (avoids double work)
    } catch {
      // A transient native error: fall through to jsQR for this frame.
    }
  }

  // Fallback: rasterize the frame and decode with jsQR.
  canvas.width = w
  canvas.height = h
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  if (!ctx) return null
  ctx.drawImage(video, 0, 0, w, h)
  let image: ImageData
  try {
    image = ctx.getImageData(0, 0, w, h)
  } catch {
    return null // tainted canvas etc.; give up on this frame
  }
  const result = jsQR(image.data, image.width, image.height, { inversionAttempts: 'dontInvert' })
  return result?.data ?? null
}
