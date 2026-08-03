// Adding a device to this account, from the device you already use (Sesame B1).
//
// Three steps, and the middle one is the one that matters: photographing the new
// device's code is what authorizes it. A device id IS the hash of the key inside
// that code, so a code altered on its way to this camera cannot name a device
// this account did not mean to add, and the relay never gets a say in who joins.
//
// Then the transfer. It is offered optically first because that way it never
// reaches the network in any form. The relay path exists because a laptop with no
// camera is a real device people own, and it is described for what it is.

import { useState } from 'react'
import { OpticalSend, estimateSeconds } from './OpticalSend'
import { QrScanner } from './QrScanner'

type Mode = 'scan' | 'choose' | 'optical' | 'sending' | 'done'

interface Props {
  onAuthorize: (codeText: string) => Promise<{ deviceId: string; secret: Uint8Array } | null>
  onSeal: (secret: Uint8Array) => Promise<Uint8Array | null>
  onSendOverRelay: (deviceId: string, secret: Uint8Array) => Promise<boolean>
  onDone: () => void
  onClose: () => void
}

export function LinkDevicePanel({ onAuthorize, onSeal, onSendOverRelay, onDone, onClose }: Props) {
  const [mode, setMode] = useState<Mode>('scan')
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [target, setTarget] = useState<{ deviceId: string; secret: Uint8Array } | null>(null)
  const [blob, setBlob] = useState<Uint8Array | null>(null)
  const [transferId] = useState(() => crypto.getRandomValues(new Uint8Array(8)))

  async function authorize(codeText: string) {
    if (!codeText.trim()) return
    setBusy(true)
    const t = await onAuthorize(codeText.trim())
    setBusy(false)
    if (!t) {
      setMode('scan')
      return
    }
    setTarget(t)
    setMode('choose')
  }

  async function showOptically() {
    if (!target) return
    setBusy(true)
    const sealed = await onSeal(target.secret)
    setBusy(false)
    if (!sealed) return
    setBlob(sealed)
    setMode('optical')
  }

  async function sendOverRelay() {
    if (!target) return
    setMode('sending')
    const ok = await onSendOverRelay(target.deviceId, target.secret)
    setMode(ok ? 'done' : 'choose')
    if (ok) onDone()
  }

  if (mode === 'scan') {
    return (
      <div className="link-panel">
        <div className="sheet-head">
          <h2 className="small accent">link another device</h2>
          <button className="link" onClick={onClose}>
            back
          </button>
        </div>
        <p className="muted small">
          On the new device, install Nightjar and choose <em>add this device to an account</em>. It will show a code.
          Point this camera at it.
        </p>
        <QrScanner
          hint="Point the camera at the code on the new device."
          fallback="Type the code from the new device into the box below."
          onDecode={(text) => void authorize(text)}
          onCancel={onClose}
        />
        <label className="field-label small muted">or type the code it is showing</label>
        <div className="row">
          <input
            className="mono"
            placeholder="paste the device code"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void authorize(typed)
            }}
          />
          <button className="ghost" disabled={busy || !typed.trim()} onClick={() => void authorize(typed)}>
            add
          </button>
        </div>
      </div>
    )
  }

  if (mode === 'optical' && blob) {
    return (
      <div className="link-panel">
        <div className="sheet-head">
          <h2 className="small accent">show this to the new device</h2>
          <button className="link" onClick={() => setMode('choose')}>
            back
          </button>
        </div>
        <OpticalSend payload={blob} transferId={transferId} />
        <p className="muted small">
          About {estimateSeconds(blob.length)} seconds with the devices held steady. It keeps looping, so there is no
          rush and nothing is lost if the camera misses part of it.
        </p>
        <button
          className="primary block"
          onClick={() => {
            setMode('done')
            onDone()
          }}
        >
          the other device says it is done
        </button>
      </div>
    )
  }

  if (mode === 'sending') {
    return (
      <div className="link-panel">
        <h2 className="small accent">sending</h2>
        <p className="muted small">Both devices have to be open at the same time for this. Keep them both awake.</p>
      </div>
    )
  }

  if (mode === 'done') {
    return (
      <div className="link-panel">
        <h2 className="small accent">device added</h2>
        <p className="muted small">
          It is on your device list now, so messages sent to you go to it as well. It starts with no messages: nothing
          you have already received is moved there, and it will show every contact as unverified until you compare
          safety numbers on that device.
        </p>
        <button className="primary block" onClick={onClose}>
          done
        </button>
      </div>
    )
  }

  return (
    <div className="link-panel">
      <div className="sheet-head">
        <h2 className="small accent">send it what it needs</h2>
        <button className="link" onClick={onClose}>
          back
        </button>
      </div>
      <p className="muted small">
        That device is on your account's list now. It still needs your account key and your contacts before it can be
        used.
      </p>
      <label className="field-label small muted">the device you just added</label>
      <p className="mono break small yourid">{target?.deviceId}</p>

      <button className="primary block" disabled={busy} onClick={() => void showOptically()}>
        show it a moving code (recommended)
      </button>
      <p className="muted tiny">
        The transfer goes from this screen to that camera and never reaches the network. The relay still learns that
        your account gained a device and when, because adding it was published; what it does not learn is any part of
        what is being handed over.
      </p>

      <button className="ghost block" disabled={busy} onClick={() => void sendOverRelay()}>
        send it over the relay instead
      </button>
      <p className="muted tiny">
        For a device with no camera. The relay carries it sealed under the code you just scanned, delivers it only
        while both devices are open, and stores nothing.
      </p>
    </div>
  )
}
