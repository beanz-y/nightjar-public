// The sending half of an optical transfer: an animated QR that loops forever.
//
// There is no acknowledgement and no end. The sender has no idea what the camera
// has caught, so it simply keeps producing frames, and the receiver stops when it
// has enough. That is what makes the whole thing tolerant of a hand that moves,
// a screen that glares, and two devices refreshing at different rates.
//
// Drawn to a CANVAS rather than the SVG the static QR codes use. A version-40
// symbol is 177 modules square, so an SVG would mean rebuilding a path with tens
// of thousands of subpaths ten times a second, and React would be reconciling it
// all. Canvas is a DOM API, not script evaluation, so it is untouched by the
// strict CSP (DESIGN 10.2).

import { useEffect, useRef, useState } from 'react'
import { FRAME_BYTES, frameCount, opticalFrame } from '../net/opticalFrames'
import { qrMatrix } from './qr'

interface OpticalSendProps {
  /** The bytes to send. Already sealed by whoever produced them: this component
   *  is a display, and everything it shows is readable by any camera in the room. */
  payload: Uint8Array
  /** Ties the frames of one transfer together. Fresh per transfer. */
  transferId: Uint8Array
  /** Largest rendered size in CSS pixels. The code fills the space it is given up
   *  to this, rather than sitting at a fixed size: the receiving camera needs
   *  roughly three of its pixels per module, so how big this is drawn is a
   *  direct input to whether the transfer can happen at all. */
  size?: number
  /**
   * Codes shown per second. Deliberately SLOW.
   *
   * A camera needs a whole code to be on screen for the length of its exposure.
   * At ten a second each code lasts 100ms, which is close enough to a typical
   * exposure that a large share of captures span a change and decode as nothing,
   * and a hand that drifts has no time to settle between them. Six gives each
   * code 167ms, so more captures land cleanly and a camera being held rather than
   * clamped has a real chance at every one.
   *
   * Going slower costs almost nothing. The fountain layer means a receiver takes
   * whatever it catches in any order, so the rate sets how fast a PERFECT capture
   * could finish, not how long the transfer actually takes, and a perfect capture
   * was never the case worth optimizing.
   */
  fps?: number
}

export function OpticalSend({ payload, transferId, size = 560, fps = 6 }: OpticalSendProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [error, setError] = useState<string | null>(null)
  /** Frames drawn so far. The other device acknowledges nothing, ever, so this is
   *  the only thing on the sending screen that separates a transfer in progress
   *  from a page that has quietly stopped. */
  const [shown, setShown] = useState(0)
  const total = frameCount(payload.length)

  useEffect(() => {
    let seq = 0
    let timer: ReturnType<typeof setInterval> | null = null
    const draw = () => {
      const canvas = canvasRef.current
      if (!canvas) return
      let matrix: boolean[][]
      try {
        matrix = qrMatrix(opticalFrame(payload, transferId, seq), 'L')
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e))
        if (timer) clearInterval(timer)
        return
      }
      seq++
      setShown(seq)
      const n = matrix.length
      const quiet = 4
      const dim = n + quiet * 2
      // One module per device pixel, scaled up by CSS, so the modules stay
      // perfectly square and crisp however large the element is drawn.
      canvas.width = dim
      canvas.height = dim
      const ctx = canvas.getContext('2d')
      if (!ctx) return
      ctx.fillStyle = '#ffffff'
      ctx.fillRect(0, 0, dim, dim)
      ctx.fillStyle = '#000000'
      for (let y = 0; y < n; y++) {
        for (let x = 0; x < n; x++) {
          if (matrix[y][x]) ctx.fillRect(x + quiet, y + quiet, 1, 1)
        }
      }
    }
    draw()
    timer = setInterval(draw, Math.max(1, Math.round(1000 / fps)))
    return () => {
      if (timer) clearInterval(timer)
    }
  }, [payload, transferId, fps])

  if (error) return <div className="small muted">could not show this transfer ({error})</div>

  return (
    <div className="optical-send">
      <canvas
        ref={canvasRef}
        className="optical-canvas"
        style={{ maxWidth: size, imageRendering: 'pixelated' }}
        role="img"
        aria-label="animated transfer code"
      />
      <p className="small muted" aria-live="off">
        {total === 1
          ? 'Point the other device at this code. This transfer is small enough that any one of these codes completes it, so it should be quick.'
          : `Point the other device at this code and hold it there. It cycles through about ${total} parts and then keeps going, so there is no need to catch them in order.`}
      </p>
      {/* Proof of life. The other device gives no acknowledgement of any kind, so
          this is the only thing on the sending screen that distinguishes a
          transfer in progress from a page that has stopped. */}
      <p className="tiny muted" role="status">
        <span className="optical-pulse" aria-hidden="true" /> sending, {shown} {shown === 1 ? 'code' : 'codes'} shown
      </p>
      <p className="tiny muted">
        Fill most of the other device's camera view with this code. If it is not being read, try moving the devices
        apart rather than together: a laptop camera usually cannot focus on something held right up against it.
      </p>
    </div>
  )
}

/** Exported for the panel that decides whether a payload is worth sending this
 *  way at all: roughly how long it will take at `fps`, in seconds. Must default
 *  to the same rate the component does, or the estimate quietly describes a
 *  different transfer than the one on screen. */
export function estimateSeconds(payloadBytes: number, fps = 6): number {
  // Allow well over one pass: a hand-held camera misses a good share of codes,
  // and promising the best case would make a normal transfer look broken.
  return Math.ceil((frameCount(payloadBytes) * 2) / fps)
}

/** Bytes carried by one frame, re-exported so a caller can size a payload. */
export { FRAME_BYTES }
