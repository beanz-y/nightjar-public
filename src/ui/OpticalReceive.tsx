// The receiving half of an optical transfer: a camera pointed at an animated QR
// until enough frames have been caught to reassemble the payload.
//
// It is deliberately forgiving. Frames arrive out of order, repeat, and go
// missing, and none of that is an error worth telling anyone about, because the
// fountain layer is built for exactly that. The only things the user sees are
// progress and, if the camera cannot be opened at all, why.
//
// Shares the camera and decoding path with the ordinary QR scanner, so the
// native BarcodeDetector is used where it exists and the bundled pure-JS decoder
// covers the browsers that lack it.

import { useEffect, useRef, useState } from 'react'
import { FountainDecoder } from '../net/fountain'
import { parseOpticalFrame } from '../net/opticalFrames'
import { decodeQrFrame } from './qrDecode'

interface OpticalReceiveProps {
  /** Called once with the reassembled payload. Fires exactly one time. */
  onPayload: (payload: Uint8Array) => void
  onCancel: () => void
  /** What is being received, for the heading. */
  title?: string
}

type Status = 'starting' | 'scanning' | 'error'

export function OpticalReceive({ onPayload, onCancel, title = 'Receiving' }: OpticalReceiveProps) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [status, setStatus] = useState<Status>('starting')
  const [error, setError] = useState('')
  const [progress, setProgress] = useState({ have: 0, need: 0 })

  useEffect(() => {
    let stream: MediaStream | null = null
    let raf = 0
    let stopped = false
    const decoder = new FountainDecoder()

    const stop = () => {
      stopped = true
      if (raf) cancelAnimationFrame(raf)
      stream?.getTracks().forEach((t) => t.stop())
    }

    void (async () => {
      const media = globalThis.navigator?.mediaDevices
      if (!media?.getUserMedia) {
        setError('This browser cannot open the camera, so it cannot receive a transfer this way.')
        setStatus('error')
        return
      }
      try {
        stream = await media.getUserMedia({ video: { facingMode: 'environment' }, audio: false })
      } catch (e) {
        const name = e instanceof DOMException ? e.name : ''
        setError(
          name === 'NotAllowedError'
            ? 'Camera access was blocked. Allow it in your browser and try again.'
            : 'Could not start the camera.',
        )
        setStatus('error')
        return
      }
      if (stopped) {
        stream.getTracks().forEach((t) => t.stop())
        return
      }
      const video = videoRef.current
      const canvas = canvasRef.current
      if (!video || !canvas) return
      video.srcObject = stream
      await video.play().catch(() => {})
      setStatus('scanning')

      const tick = async () => {
        if (stopped) return
        try {
          const text = await decodeQrFrame(video, canvas)
          const frame = text ? parseOpticalFrame(text) : null
          if (frame) {
            // A frame from another transfer, or one this decoder cannot use, is
            // simply not progress. Only a structurally impossible frame throws,
            // and that is caught below with everything else.
            const done = decoder.push(frame)
            setProgress(decoder.progress)
            if (done) {
              stop()
              onPayload(done)
              return
            }
          }
        } catch {
          // A bad frame costs nothing: the next one repairs it.
        }
        raf = requestAnimationFrame(() => void tick())
      }
      raf = requestAnimationFrame(() => void tick())
    })()

    return stop
    // onPayload is captured once on purpose: re-running this effect would drop
    // every frame caught so far and restart the camera mid-transfer.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const pct = progress.need > 0 ? Math.round((progress.have / progress.need) * 100) : 0

  return (
    <div className="optical-receive">
      <h3>{title}</h3>
      {status === 'error' ? (
        <p className="small">{error}</p>
      ) : (
        <>
          <video ref={videoRef} playsInline muted className="scanner-video" />
          <canvas ref={canvasRef} hidden />
          <p className="small muted" aria-live="polite">
            {status === 'starting'
              ? 'Starting the camera...'
              : progress.need === 0
                ? 'Point this at the other device.'
                : `Received ${progress.have} of ${progress.need} parts (${pct}%). Keep both devices still.`}
          </p>
        </>
      )}
      <button type="button" onClick={onCancel}>
        Cancel
      </button>
    </div>
  )
}
