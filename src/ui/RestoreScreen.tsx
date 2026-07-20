// Restore-from-backup (P8, DESIGN 8.3). Reached two ways: the evicted screen
// (storage was cleared but this device registered before) and onboarding (a new
// device, restoring instead of joining with an invite). The flow is honest
// about what a restore does and does not bring back.

import { useRef, useState } from 'react'

interface Props {
  mode: 'evicted' | 'onboarding'
  busy: boolean
  error: string | null
  onRestore: (file: File, passphrase: string) => void
  onBack?: () => void
}

export function RestoreScreen({ mode, busy, error, onRestore, onBack }: Props) {
  const [file, setFile] = useState<File | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  return (
    <section className="onboard">
      {mode === 'evicted' ? (
        <>
          <p className="error">This device registered before, but its storage was cleared.</p>
          <p className="muted small">
            To keep your identity, contacts, and verification status, restore the backup file you created. Without a
            backup there is no recovery: that is the design (no one else, including the operator, can restore for you).
            You would need a fresh invite and would appear to your contacts as a new, unverified identity.
          </p>
        </>
      ) : (
        <p className="muted small">
          Restore replaces this device's brand-new identity with the one in your backup, along with your contacts and
          their verification status. Message history is not in backups; it stays on the device it happened on.
        </p>
      )}

      <p className="small">
        Only restore a backup <strong>you created yourself</strong>. A backup file IS an identity: restoring someone
        else's file means using an identity its creator fully controls.
      </p>

      <label className="field-label small muted">backup file (.njbk)</label>
      <div className="row">
        <input
          ref={fileRef}
          type="file"
          accept=".njbk,application/octet-stream"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          disabled={busy}
        />
      </div>

      <label className="field-label small muted">backup passphrase</label>
      <div className="row">
        <input
          className="mono"
          type="password"
          placeholder="the passphrase you saved with the backup"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          disabled={busy}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && file && passphrase) onRestore(file, passphrase)
          }}
        />
        <button className="primary" disabled={busy || !file || !passphrase} onClick={() => file && onRestore(file, passphrase)}>
          {busy ? 'unlocking…' : 'restore'}
        </button>
      </div>

      {busy && <p className="muted small">Unlocking is slow on purpose (it is what makes the file hard to crack). This can take several seconds.</p>}
      {error && <p className="error small">{error}</p>}
      {!busy && (
        <p className="muted small">
          After a restore, send each contact a message to re-establish the conversation. Anything sent to you between
          losing the device and restoring cannot be recovered.
        </p>
      )}

      {onBack && !busy && (
        <button className="link" onClick={onBack}>
          back
        </button>
      )}
    </section>
  )
}
