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
// The pure-JS decoder runs in a WORKER (src/platform/qrDecoder.ts), because on
// the browsers that need it, which is every Firefox and Chrome on Windows, it is
// the only decoder there is and it is O(pixels) of straight-line work. On the
// main thread it starved the scan loop badly enough that an animated code could
// not be read at all. It is still imported statically there, so the fallback for
// a browser with no workers lands in the one hash-pinned bundle rather than a
// chunk that Integrity-Policy would refuse (DESIGN 10.2).

import { decodeImage, decoderBusy } from '../platform/qrDecoder'

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
 * Longest edge handed to the pure-JS decoder.
 *
 * jsQR is O(pixels) and runs on the main thread, so a full 1920x1080 frame costs
 * roughly two megapixels of work per attempt and drags the scan loop down to a
 * few attempts a second. That is fatal for reading an ANIMATED code rather than a
 * static one: the sender changes the image several times a second, so a slow loop
 * both samples rarely AND is disproportionately likely to catch an exposure that
 * spans a change, which decodes as nothing. Cutting the work down is therefore
 * not an optimization here, it is most of whether the transfer works at all.
 *
 * 1024 keeps roughly eight camera pixels per module for a code that fills the
 * view, against the three or so a decoder needs, so there is room to spare for a
 * code that only fills part of it.
 */
const JS_DECODE_MAX_EDGE = 1024

/** The source square to read and the size to read it at. Split out from the
 *  drawing so the arithmetic can be checked without a canvas: an off-centre crop
 *  or an inverted axis would not throw, it would just quietly never decode. */
export function cropRect(
  w: number,
  h: number,
  maxEdge = JS_DECODE_MAX_EDGE,
): { sx: number; sy: number; side: number; edge: number } {
  const side = Math.min(w, h)
  return {
    sx: Math.floor((w - side) / 2),
    sy: Math.floor((h - side) / 2),
    side,
    edge: Math.min(side, maxEdge),
  }
}

/**
 * Decode a QR from one video frame. Returns the decoded string, or null if no
 * QR is visible (the caller keeps sampling). Never throws.
 *
 * Only the CENTERED SQUARE of the frame is examined, which is exactly the region
 * both previews show (each is a square element with `object-fit: cover`). So this
 * looks at what the person is aiming at and ignores the strips either side that
 * they cannot see anyway.
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
      // Deliberately FALL THROUGH when it saw nothing. This used to return null
      // to avoid doing the work twice, which is the right instinct for scanning a
      // printed code that will still be there next frame, and the wrong one for a
      // moving code that will not: the two decoders fail on different marginal
      // frames, so a second opinion on a frame the first could not read is worth
      // more than the cost of asking, now that the cost is a cropped image.
    } catch {
      // A transient native error: fall through to jsQR for this frame.
    }
  }

  // Checked BEFORE the capture, not after: rasterizing a megapixel nobody is
  // going to look at is the same waste in miniature.
  if (decoderBusy()) return null

  const { sx, sy, side, edge } = cropRect(w, h)
  canvas.width = edge
  canvas.height = edge
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  if (!ctx) return null
  ctx.drawImage(video, sx, sy, side, side, 0, 0, edge, edge)
  let image: ImageData
  try {
    image = ctx.getImageData(0, 0, edge, edge)
  } catch {
    return null // tainted canvas etc.; give up on this frame
  }
  // The frame's buffer is handed over, not copied. Nothing reads `image` after
  // this, and the next call captures a fresh one.
  return decodeImage(image)
}
