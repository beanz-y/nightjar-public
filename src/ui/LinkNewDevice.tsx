// Joining an account from a NEW device (Sesame B1): this device shows a code,
// the device you already use photographs it, and the transfer comes back.
//
// The code carries a fresh single-use secret, so it is the one QR in this app
// that is not safe to leave lying around: anything that can read it can open the
// transfer that follows. It is on screen for the length of the ceremony and never
// written to disk, and a reload produces a new one.
//
// Two ways for the transfer to come back, and the order they are offered in is
// the order they should be preferred. The moving code goes screen to camera and
// never touches the network at all. The relay path is for a device with no
// camera, and it is honest about what it costs: the relay carries the sealed
// bytes, live, storing nothing.

import { useEffect, useState } from 'react'
import { OpticalReceive } from './OpticalReceive'
import { QrCode } from './QrCode'
import type { LinkState } from './useNightjar'

interface Props {
  /** The code this device is showing, from startLinking(). */
  code: string
  /** This device's id, so the other device can be sure it added the right one. */
  deviceId: string
  linkState: LinkState
  /** Hand a caught transfer to the hook; returns whether it opened. */
  onTransfer: (blob: Uint8Array) => Promise<boolean>
  onCancel: () => void
}

export function LinkNewDevice({ code, deviceId, linkState, onTransfer, onCancel }: Props) {
  const [scanning, setScanning] = useState(false)
  const [copied, setCopied] = useState(false)

  // Stop showing the camera the moment the transfer lands, whichever way it came:
  // the relay path can complete while the scanner is open.
  useEffect(() => {
    if (linkState === 'joining' || linkState === 'done') setScanning(false)
  }, [linkState])

  if (linkState === 'joining') {
    return (
      <section className="onboard">
        <h2 className="small accent">joining your account</h2>
        <p className="muted">Setting this device up. Do not close this yet.</p>
      </section>
    )
  }

  if (scanning) {
    return (
      <section className="onboard">
        <h2 className="small accent">point this at the other device</h2>
        <OpticalReceive
          title="Reading the transfer"
          onPayload={(blob) => {
            setScanning(false)
            void onTransfer(blob)
          }}
          onCancel={() => setScanning(false)}
        />
        <p className="muted small">
          Hold both devices still. It is normal for this to take a few seconds, and missed frames repair themselves.
        </p>
      </section>
    )
  }

  return (
    <section className="onboard">
      <h2 className="small accent">add this device to your account</h2>

      <p className="muted">
        <strong>1.</strong> On the device you already use, open <em>Settings &rarr; Your devices &rarr; Link another
        device</em>, and point it at this code.
      </p>
      <div className="qr-wrap">
        <QrCode text={code} size={208} />
      </div>
      <p className="muted tiny">
        This code is only for the device you are standing next to. Anyone who can photograph it can join your account,
        so do not show it to a camera you do not control, and do not send it to anyone.
      </p>

      <label className="field-label small muted">or type this code there</label>
      <p className="mono break small yourid">{code}</p>
      <button
        className="ghost small"
        onClick={() => {
          void navigator.clipboard
            .writeText(code)
            .then(() => {
              setCopied(true)
              setTimeout(() => setCopied(false), 1500)
            })
            .catch(() => setCopied(false))
        }}
      >
        {copied ? 'copied' : 'copy code'}
      </button>

      <p className="muted">
        <strong>2.</strong> That device will offer to show you a moving code. Point this device at it.
      </p>
      <button className="primary block" onClick={() => setScanning(true)}>
        scan the moving code
      </button>
      <p className="muted tiny">
        Nothing about the transfer itself goes over the network this way. If this device has no camera, choose{' '}
        <em>send it over the relay</em> on the other device instead and leave this screen open; the relay carries it
        sealed and stores nothing, but it does carry it.
      </p>

      <label className="field-label small muted">this device</label>
      <p className="mono break small yourid">{deviceId}</p>

      <button className="ghost" onClick={onCancel}>
        cancel
      </button>
    </section>
  )
}
