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
  /** Rendered size in CSS pixels. */
  size?: number
  /** Frames per second. Ten is a deliberate floor rather than a maximum: a camera
   *  needs a whole frame to be on screen when its shutter opens, and pushing the
   *  rate up past what the receiving device can decode simply means it catches a
   *  smaller share of them. */
  fps?: number
}

export function OpticalSend({ payload, transferId, size = 320, fps = 10 }: OpticalSendProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [error, setError] = useState<string | null>(null)
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
        width={size}
        height={size}
        style={{ width: size, height: size, imageRendering: 'pixelated' }}
        role="img"
        aria-label="animated transfer code"
      />
      <p className="small muted">
        {total === 1
          ? 'Point the other device at this code.'
          : `Point the other device at this code and hold it there. This is about ${total} frames.`}
      </p>
    </div>
  )
}

/** Exported for the panel that decides whether a payload is worth sending this
 *  way at all: roughly how long it will take at `fps`, in seconds. */
export function estimateSeconds(payloadBytes: number, fps = 10): number {
  // Allow a little over one pass, since a camera never catches every frame.
  return Math.ceil((frameCount(payloadBytes) * 1.3) / fps)
}

/** Bytes carried by one frame, re-exported so a caller can size a payload. */
export { FRAME_BYTES }
