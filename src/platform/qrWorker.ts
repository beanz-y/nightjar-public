// Dedicated worker: runs the pure-JS QR decoder off the main thread.
//
// This matters far more than it sounds. Browsers without a native
// `BarcodeDetector`, which includes Firefox everywhere and Chrome on Windows,
// have only this decoder, and it is O(pixels) of straight-line work. Run on the
// main thread it competes with React and with the camera's own frame delivery,
// so the scan loop drops to a handful of looks a second. That is survivable for
// a printed code sitting still and fatal for a code that CHANGES several times a
// second: the loop both looks rarely and is disproportionately likely to catch
// the instant a code is being replaced, which decodes as nothing at all.
//
// Same-origin module worker, allowed under the strict CSP by `default-src
// 'self'`, and not covered by `Integrity-Policy: blocked-destinations=(script)`
// because that names the script destination and this is a worker. Its chunk is
// still covered by the release hash, which digests every file in the build.
//
// The frame buffer arrives TRANSFERRED rather than copied, so a 1024x1024 frame
// costs no megabyte memcpy per attempt.

import jsQR from 'jsqr'

interface DecodeRequest {
  id: number
  data: ArrayBuffer
  width: number
  height: number
}

const scope = self as unknown as {
  onmessage: ((ev: MessageEvent) => void) | null
  postMessage: (msg: unknown, transfer?: Transferable[]) => void
}

scope.onmessage = (ev: MessageEvent) => {
  const { id, data, width, height } = ev.data as DecodeRequest
  try {
    const result = jsQR(new Uint8ClampedArray(data), width, height, { inversionAttempts: 'dontInvert' })
    scope.postMessage({ id, text: result?.data ?? null })
  } catch {
    // A malformed frame is not an error worth reporting: the next one repairs it.
    scope.postMessage({ id, text: null })
  }
}
