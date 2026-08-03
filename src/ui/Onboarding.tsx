// First-run onboarding (DESIGN 6.3). A device already has its identity by now
// (generated on first launch); to actually message, it must register behind a
// single-use invite. A normal invite carries the inviter's fingerprint, which the
// client pins on join; the very first user registers with a bootstrap (admin)
// code that carries no inviter. Users with an existing identity restore a
// backup instead (P8), which replaces the freshly generated throwaway identity.

import { useState } from 'react'
import { LinkNewDevice } from './LinkNewDevice'
import { QrScanner } from './QrScanner'
import { RestoreScreen } from './RestoreScreen'
import type { LinkState } from './useNightjar'

interface Props {
  userId: string
  prefill: string
  connected: boolean
  restoreBusy: boolean
  restoreError: string | null
  linkState: LinkState
  onJoin: (input: string) => void
  onRestore: (file: File, passphrase: string) => void
  /** Start showing a link code and listening for a transfer (Sesame B1). */
  onStartLinking: () => { code: string; deviceId: string } | null
  onCancelLinking: () => void
  onLinkTransfer: (blob: Uint8Array) => Promise<boolean>
  onAbout: () => void
}

export function Onboarding({
  userId,
  prefill,
  connected,
  restoreBusy,
  restoreError,
  linkState,
  onJoin,
  onRestore,
  onStartLinking,
  onCancelLinking,
  onLinkTransfer,
  onAbout,
}: Props) {
  const [input, setInput] = useState(prefill)
  const [restoring, setRestoring] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [linkCode, setLinkCode] = useState<{ code: string; deviceId: string } | null>(null)

  if (linkCode) {
    return (
      <LinkNewDevice
        code={linkCode.code}
        deviceId={linkCode.deviceId}
        linkState={linkState}
        onTransfer={onLinkTransfer}
        onCancel={() => {
          setLinkCode(null)
          onCancelLinking()
        }}
      />
    )
  }

  if (restoring) {
    return (
      <RestoreScreen
        mode="onboarding"
        busy={restoreBusy}
        error={restoreError}
        onRestore={onRestore}
        onBack={() => setRestoring(false)}
      />
    )
  }

  if (scanning) {
    return (
      <section className="onboard">
        <h2 className="small accent">scan your invite</h2>
        <QrScanner
          onDecode={(text) => {
            setScanning(false)
            onJoin(text)
          }}
          onCancel={() => setScanning(false)}
        />
      </section>
    )
  }

  return (
    <section className="onboard">
      <p className="muted">
        You have an invite-only account. Scan or paste the invite you were given to join. Nightjar has no phone numbers,
        emails, or passwords: your identity is a key on this device.
      </p>

      {/* Priority-1 control first (DESIGN 6/12): the safety-number pointer + a
          one-line residual-risk note, with the full disclosure a click away rather
          than dumped inline (P7 should-fix). */}
      <p className="small">
        The strongest thing you can do is verify each contact's safety number with them in person. Your messages are
        end to end encrypted, but the app is served by the operator, so a determined operator could target you.{' '}
        <button className="link" onClick={onAbout}>
          read how this works and how to verify the build
        </button>
        .
      </p>

      <button className="primary block" disabled={!connected} onClick={() => setScanning(true)}>
        scan invite QR
      </button>

      <label className="field-label small muted">or paste the invite</label>
      <div className="row">
        <input
          className="mono"
          placeholder="paste an invite code or link"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && input.trim()) onJoin(input)
          }}
        />
        <button className="ghost" disabled={!connected || !input.trim()} onClick={() => onJoin(input)}>
          join
        </button>
      </div>
      {!connected && <p className="muted small">connecting to the relay…</p>}

      <label className="field-label small muted">your device identity</label>
      <p className="mono break small yourid">{userId}</p>

      <p className="small">
        Already use Nightjar on another device?{' '}
        <button
          className="link"
          disabled={!connected}
          onClick={() => {
            const started = onStartLinking()
            if (started) setLinkCode(started)
          }}
        >
          add this device to that account
        </button>
        . It joins the account you already have, so people reach you on both. It needs no invite, and it starts with
        none of your existing messages.
      </p>

      <p className="small">
        Lost the device you used before?{' '}
        <button className="link" onClick={() => setRestoring(true)}>
          restore from a backup file
        </button>
      </p>
    </section>
  )
}
