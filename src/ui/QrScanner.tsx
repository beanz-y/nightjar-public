// Camera QR scanner. Opens the device camera, samples frames, and calls
// onDecode with the first QR it reads. Honest about failure: no camera, a
// denied permission, or an unsupported browser all surface a clear message with
// a "paste instead" way out, never a dead end.

import { useEffect, useRef, useState } from 'react'
import { decodeQrFrame } from './qrDecode'

interface Props {
  onDecode: (text: string) => void
  onCancel: () => void
}

type Status = 'starting' | 'scanning' | 'error'

export function QrScanner({ onDecode, onCancel }: Props) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [status, setStatus] = useState<Status>('starting')
  const [error, setError] = useState<string>('')

  useEffect(() => {
    let stream: MediaStream | null = null
    let raf = 0
    let stopped = false

    const stop = () => {
      stopped = true
      if (raf) cancelAnimationFrame(raf)
      stream?.getTracks().forEach((t) => t.stop())
    }

    void (async () => {
      const media = globalThis.navigator?.mediaDevices
      if (!media?.getUserMedia) {
        setError('This browser cannot open the camera. Use "enter a code" below instead.')
        setStatus('error')
        return
      }
      try {
        stream = await media.getUserMedia({ video: { facingMode: 'environment' }, audio: false })
      } catch (e) {
        const name = e instanceof DOMException ? e.name : ''
        setError(
          name === 'NotAllowedError'
            ? 'Camera access was blocked. Allow it in your browser, or use "enter a code" below.'
            : 'Could not start the camera. Use "enter a code" below instead.',
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
      try {
        await video.play()
      } catch {
        /* autoplay quirk; the scan loop still runs once frames arrive */
      }
      setStatus('scanning')

      const tick = async () => {
        if (stopped) return
        try {
          const text = await decodeQrFrame(video, canvas)
          if (text) {
            stop()
            onDecode(text)
            return
          }
        } catch {
          /* keep scanning; a single bad frame is not fatal */
        }
        raf = requestAnimationFrame(() => void tick())
      }
      raf = requestAnimationFrame(() => void tick())
    })()

    return stop
    // onDecode is stable enough for this one-shot effect; scanning must not restart.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="scanner">
      <div className="scanner-frame">
        {/* muted + playsInline are required for autoplay on iOS Safari. */}
        <video ref={videoRef} className="scanner-video" muted playsInline />
        <canvas ref={canvasRef} hidden />
        {status !== 'error' && <div className="scanner-reticle" aria-hidden="true" />}
      </div>

      {status === 'starting' && <p className="muted small">starting the camera…</p>}
      {status === 'scanning' && <p className="muted small">Point the camera at the invite QR code.</p>}
      {status === 'error' && <p className="error small">{error}</p>}

      <button className="ghost small" onClick={onCancel}>
        cancel
      </button>
    </div>
  )
}
