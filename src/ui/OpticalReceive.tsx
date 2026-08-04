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
import { releaseQrDecoder } from '../platform/qrDecoder'
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
  /** Any QR read at all, whether or not it was part of a transfer. This is what
   *  separates "the camera cannot read that code" from "it is reading something
   *  that is not a transfer", which used to look identical: both showed the same
   *  "point this at the other device" line forever. */
  const [codesSeen, setCodesSeen] = useState(0)
  /** What the camera actually gave us. A decoder needs about three pixels per
   *  module, so a camera that came up at 640x480 is the whole explanation for a
   *  transfer that never progresses, and the number belongs on screen. */
  const [resolution, setResolution] = useState<{ w: number; h: number } | null>(null)
  /** Decode attempts per second. The other number that explains a failure: the
   *  code changes several times a second, so a loop managing only two or three
   *  looks at it will miss most of them however steadily it is aimed. */
  const [scanRate, setScanRate] = useState(0)

  useEffect(() => {
    let stream: MediaStream | null = null
    let raf = 0
    let stopped = false
    const decoder = new FountainDecoder()
    let attempts = 0
    const rateTimer = setInterval(() => {
      setScanRate(attempts)
      attempts = 0
    }, 1000)

    const stop = () => {
      stopped = true
      if (raf) cancelAnimationFrame(raf)
      clearInterval(rateTimer)
      stream?.getTracks().forEach((t) => t.stop())
      // A closed camera screen should not leave a thread and a decoder's working
      // set alive behind it.
      releaseQrDecoder()
    }

    void (async () => {
      const media = globalThis.navigator?.mediaDevices
      if (!media?.getUserMedia) {
        setError('This browser cannot open the camera, so it cannot receive a transfer this way.')
        setStatus('error')
        return
      }
      try {
        // Ask for as much resolution as the camera will give. Without this a
        // laptop webcam commonly negotiates 640x480, which is not enough pixels
        // per module to decode the codes at all, and the failure is silent: the
        // scanner simply never reports progress. `ideal` rather than `exact` so a
        // camera that cannot manage it still starts rather than throwing, and
        // facingMode stays a preference so a device with only a front camera
        // (every laptop) is not excluded.
        stream = await media.getUserMedia({
          video: {
            facingMode: 'environment',
            width: { ideal: 1920 },
            height: { ideal: 1080 },
          },
          audio: false,
        })
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
        if (video.videoWidth) {
          setResolution((r) => (r?.w === video.videoWidth ? r : { w: video.videoWidth, h: video.videoHeight }))
        }
        attempts += 1
        try {
          const text = await decodeQrFrame(video, canvas)
          if (text) setCodesSeen((n) => n + 1)
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
  const receiving = progress.need > 0
  // A camera below roughly 1280 across cannot resolve these codes reliably, and
  // saying so beats leaving someone to conclude the feature is broken.
  const lowRes = resolution !== null && Math.min(resolution.w, resolution.h) < 700

  return (
    <div className="optical-receive">
      <h3>{title}</h3>
      {status === 'error' ? (
        <p className="small">{error}</p>
      ) : (
        <>
          <video ref={videoRef} playsInline muted className="scanner-video" />
          <canvas ref={canvasRef} hidden />

          {receiving && (
            <div
              className="optical-bar"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={progress.need}
              aria-valuenow={progress.have}
              aria-label="transfer progress"
            >
              <div className="optical-bar-fill" style={{ width: `${pct}%` }} />
            </div>
          )}

          <p className="small muted" aria-live="polite">
            {status === 'starting'
              ? 'Starting the camera...'
              : receiving
                ? `Received ${progress.have} of ${progress.need} parts (${pct}%). It does not have to be steady, just readable, and missed parts come round again.`
                : codesSeen > 0
                  ? 'Reading a code, but it is not a device transfer. Check the other device is showing the moving code.'
                  : 'Looking for the code. Fill most of this view with it.'}
          </p>

          {/* Three different things can be happening while nothing progresses, and
              before this they all looked the same. This says which. */}
          <p className="tiny muted" role="status">
            {codesSeen > 0 ? `codes read: ${codesSeen}` : 'no code read yet'}
            {resolution ? ` · camera ${resolution.w}x${resolution.h}` : ''}
            {scanRate > 0 ? ` · ${scanRate} looks/sec` : ''}
          </p>

          {codesSeen === 0 && status === 'scanning' && (
            <p className="tiny muted">
              If nothing is being read, try moving the other device FURTHER AWAY rather than closer. Most laptop
              cameras have a fixed focus set for a face at arm's length and cannot focus on something held right up to
              them, so a code that fills the view can be too blurred to read while a smaller, sharper one is fine.
              Failing that, tilt it slightly to kill the reflection of your own screen.
            </p>
          )}

          {lowRes && !receiving && (
            <p className="tiny muted">
              This camera is running at a low resolution, which may not be enough to read the code. Make the code
              larger on the other screen, or use a device with a better camera.
            </p>
          )}
        </>
      )}
      <button type="button" onClick={onCancel}>
        Cancel
      </button>
    </div>
  )
}
