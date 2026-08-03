// Moving saved messages to another of your own devices (DESIGN 8.12).
//
// A device you add starts empty, on purpose. This is the separate, deliberate act
// that carries history across afterwards, and it goes screen to camera only:
// there is no relay path for this and there is not going to be one. The bytes are
// sealed either way, but this can be everything the account has ever said, and
// handing that to the relay to carry, even sealed, is a different promise from
// the one made about what the relay ever holds.
//
// Two halves, and which device does which is the opposite of what people expect:
// the device that WANTS the messages shows the code, and the device that HAS them
// photographs it. That is the same direction as the linking ceremony, which is
// the point: it is the dance the user has already been taught once.

import { useCallback, useEffect, useState } from 'react'
import { OpticalReceive } from './OpticalReceive'
import { OpticalSend, estimateSeconds } from './OpticalSend'
import { QrCode } from './QrCode'
import { QrScanner } from './QrScanner'

const DAY_MS = 24 * 60 * 60 * 1000

/** Spans offered, longest first. The ceiling on a transfer is really a time
 *  budget, so the way through a history too big to send in one go is to send a
 *  shorter span of it rather than to truncate something silently. */
const SPANS: Array<{ label: string; days: number }> = [
  { label: 'Everything', days: 0 },
  { label: 'Last 90 days', days: 90 },
  { label: 'Last 30 days', days: 30 },
  { label: 'Last 7 days', days: 7 },
]

interface Prepared {
  count: number
  bytes: number
  tooLarge: boolean
  orphaned: number
}

interface Props {
  mode: 'send' | 'receive'
  onStartRequest: () => { code: string; deviceId: string } | null
  onCancelRequest: () => void
  onReadCode: (codeText: string) => { deviceId: string; secret: Uint8Array } | null
  onPrepare: (since: number) => Promise<Prepared | null>
  onSeal: (deviceId: string, secret: Uint8Array, since: number) => Promise<Uint8Array | null>
  onReceive: (blob: Uint8Array) => Promise<boolean>
  progress: { done: number; total: number } | null
  onClose: () => void
}

function sizeText(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function timeText(seconds: number): string {
  if (seconds < 60) return `about ${seconds} seconds`
  return `about ${Math.ceil(seconds / 60)} minutes`
}

export function HistoryTransferPanel({
  mode,
  onStartRequest,
  onCancelRequest,
  onReadCode,
  onPrepare,
  onSeal,
  onReceive,
  progress,
  onClose,
}: Props) {
  // Receiving half.
  const [code, setCode] = useState<{ code: string; deviceId: string } | null>(null)
  const [scanningTransfer, setScanningTransfer] = useState(false)
  // Sending half.
  const [target, setTarget] = useState<{ deviceId: string; secret: Uint8Array } | null>(null)
  const [typed, setTyped] = useState('')
  const [spans, setSpans] = useState<Record<number, Prepared | null>>({})
  const [blob, setBlob] = useState<Uint8Array | null>(null)
  const [busy, setBusy] = useState(false)
  const [transferId] = useState(() => crypto.getRandomValues(new Uint8Array(8)))

  useEffect(() => {
    if (mode === 'receive') {
      const started = onStartRequest()
      if (started) setCode(started)
      return () => onCancelRequest()
    }
    return undefined
    // Started once on open: re-running would issue a fresh code mid-ceremony and
    // silently invalidate the one the other device already photographed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode])

  const measure = useCallback(
    async (t: { deviceId: string; secret: Uint8Array }) => {
      setTarget(t)
      setBusy(true)
      const found: Record<number, Prepared | null> = {}
      for (const s of SPANS) found[s.days] = await onPrepare(s.days === 0 ? 0 : Date.now() - s.days * DAY_MS)
      setSpans(found)
      setBusy(false)
    },
    [onPrepare],
  )

  if (mode === 'receive') {
    if (progress) {
      return (
        <div className="link-panel">
          <h2 className="small accent">saving them</h2>
          <p className="muted small" role="status">
            Writing {progress.done} of {progress.total}. Keep this open.
          </p>
        </div>
      )
    }
    if (scanningTransfer) {
      return (
        <div className="link-panel">
          <OpticalReceive
            title="Reading the messages"
            onPayload={(b) => {
              setScanningTransfer(false)
              void onReceive(b).then((ok) => ok && onClose())
            }}
            onCancel={() => setScanningTransfer(false)}
          />
        </div>
      )
    }
    return (
      <div className="link-panel">
        <div className="sheet-head">
          <h2 className="small accent">get your saved messages</h2>
          <button className="link" onClick={onClose}>
            back
          </button>
        </div>
        <p className="muted small">
          <strong>1.</strong> On the device that already has your messages, open <em>Settings &rarr; Your devices
          &rarr; Send saved messages</em> and point it at this code.
        </p>
        {code && (
          <>
            <div className="qr-wrap">
              <QrCode text={code.code} size={208} />
            </div>
            <p className="mono break small yourid">{code.code}</p>
          </>
        )}
        <p className="muted tiny">
          This code is only for the device you are standing next to. Anyone who can photograph it can be sent your
          saved messages, so do not show it to a camera you do not control.
        </p>
        <p className="muted small">
          <strong>2.</strong> That device will show a moving code. Point this one at it.
        </p>
        <button className="primary block" onClick={() => setScanningTransfer(true)}>
          scan the moving code
        </button>
        <p className="muted tiny">
          None of this goes over the network. Messages already on this device are kept: anything sent twice simply
          lands on top of itself, so it is safe to do this again if it does not finish.
        </p>
      </div>
    )
  }

  // Sending half.
  if (blob && target) {
    return (
      <div className="link-panel">
        <div className="sheet-head">
          <h2 className="small accent">show this to the other device</h2>
          <button className="link" onClick={() => setBlob(null)}>
            back
          </button>
        </div>
        <OpticalSend payload={blob} transferId={transferId} />
        <p className="muted small">
          {timeText(estimateSeconds(blob.length))} with both devices held reasonably steady. It keeps looping, so
          missed parts come round again.
        </p>
        <button className="primary block" onClick={onClose}>
          the other device says it is done
        </button>
      </div>
    )
  }

  if (target) {
    return (
      <div className="link-panel">
        <div className="sheet-head">
          <h2 className="small accent">how much to send</h2>
          <button className="link" onClick={() => setTarget(null)}>
            back
          </button>
        </div>
        <p className="muted small">
          Sending to <span className="mono break">{target.deviceId.slice(0, 8)}…</span>. Longer spans take longer to
          hand over, because every message goes across as pictures on a screen.
        </p>
        {busy && <p className="muted small">measuring…</p>}
        {!busy &&
          SPANS.map((s) => {
            const p = spans[s.days]
            if (!p) return null
            const disabled = p.tooLarge || p.count === 0
            return (
              <button
                key={s.days}
                className="tile"
                disabled={disabled}
                onClick={() => {
                  setBusy(true)
                  void onSeal(target.deviceId, target.secret, s.days === 0 ? 0 : Date.now() - s.days * DAY_MS)
                    .then((b) => b && setBlob(b))
                    .finally(() => setBusy(false))
                }}
              >
                <span>
                  <span className="tile-title">{s.label}</span>
                  <span className="tile-sub muted small">
                    {p.count === 0
                      ? 'nothing saved in this span'
                      : p.tooLarge
                        ? `${p.count} messages, too much to hand over in one go`
                        : `${p.count} messages, ${sizeText(p.bytes)}, ${timeText(estimateSeconds(p.bytes))}`}
                  </span>
                </span>
              </button>
            )
          })}
        <p className="muted tiny">
          Messages for people this device no longer holds as contacts are left out, because the other device would
          have no key for them and so no safety number to check them against.
        </p>
      </div>
    )
  }

  return (
    <div className="link-panel">
      <div className="sheet-head">
        <h2 className="small accent">send saved messages</h2>
        <button className="link" onClick={onClose}>
          back
        </button>
      </div>
      <p className="muted small">
        On the device that wants them, open <em>Settings &rarr; Your devices &rarr; Get saved messages</em>. It will
        show a code. Point this camera at it.
      </p>
      <QrScanner
        hint="Point the camera at the code on the other device."
        fallback="Type the code from the other device into the box below."
        onDecode={(text) => {
          const t = onReadCode(text)
          if (t) void measure(t)
        }}
        onCancel={onClose}
      />
      <label className="field-label small muted">or type the code it is showing</label>
      <div className="row">
        <input
          className="mono"
          placeholder="paste the code"
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && typed.trim()) {
              const t = onReadCode(typed.trim())
              if (t) void measure(t)
            }
          }}
        />
        <button
          className="ghost"
          disabled={!typed.trim()}
          onClick={() => {
            const t = onReadCode(typed.trim())
            if (t) void measure(t)
          }}
        >
          next
        </button>
      </div>
    </div>
  )
}
