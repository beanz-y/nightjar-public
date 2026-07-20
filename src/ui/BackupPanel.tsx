// Backup export (P8, DESIGN 8.3). Seals the identity + contact trust under a
// passphrase-derived key and downloads the blob. The passphrase IS the backup's
// security: the panel offers a generated one (~100 bits) and holds typed ones
// to the floor in constants.ts. Honest copy over reassurance, per DESIGN 13.

import { useState } from 'react'
import { generateBackupPassphrase, passphraseIssue } from '../crypto/backup'

interface Props {
  onExport: (passphrase: string) => Promise<boolean>
  storagePersisted: boolean | null
  onClose: () => void
}

type Step = 'form' | 'sealing' | 'done'

export function BackupPanel({ onExport, storagePersisted, onClose }: Props) {
  const [step, setStep] = useState<Step>('form')
  const [passphrase, setPassphrase] = useState('')
  const [confirm, setConfirm] = useState('')
  const [generated, setGenerated] = useState<string | null>(null)
  const [issue, setIssue] = useState<string | null>(null)

  const generate = () => {
    const p = generateBackupPassphrase()
    setGenerated(p)
    setPassphrase(p)
    setConfirm(p)
    setIssue(null)
  }

  const start = async () => {
    const why = passphraseIssue(passphrase)
    if (why) {
      setIssue(why)
      return
    }
    if (passphrase !== confirm) {
      setIssue('the two passphrase fields do not match')
      return
    }
    setIssue(null)
    setStep('sealing')
    const ok = await onExport(passphrase)
    setStep(ok ? 'done' : 'form')
  }

  return (
    <section className="panel">
      <h3>Back up your identity</h3>

      {step !== 'done' && (
        <>
          <p className="muted small">
            The backup file holds your identity keys plus your contacts and their verification status, sealed under
            this passphrase. It does NOT hold message history (history stays on the device it happened on). Keep the
            file anywhere; keep the passphrase written somewhere safe and separate. Whoever has both IS you, and if you
            lose either along with this device, nobody can recover the account. That is the design.
          </p>
          {storagePersisted === false && (
            <p className="small">
              Heads up: this browser declined persistent storage, so it may silently evict this app's data after a
              stretch of disuse. A backup is what makes that survivable.
            </p>
          )}

          <div className="row">
            <button className="ghost" onClick={generate} disabled={step === 'sealing'}>
              generate a strong passphrase
            </button>
          </div>
          {generated && (
            <p className="mono break yourid" aria-label="generated passphrase">
              {generated}
            </p>
          )}
          {generated && <p className="muted small">Write it on paper now. It is shown only here, and it cannot be recovered later.</p>}

          <label className="field-label small muted">passphrase</label>
          <input
            className="mono"
            type={generated ? 'text' : 'password'}
            value={passphrase}
            onChange={(e) => {
              setPassphrase(e.target.value)
              setGenerated(null)
            }}
            disabled={step === 'sealing'}
          />
          <label className="field-label small muted">confirm passphrase</label>
          <input
            className="mono"
            type={generated ? 'text' : 'password'}
            value={confirm}
            onChange={(e) => {
              setConfirm(e.target.value)
              setGenerated(null)
            }}
            disabled={step === 'sealing'}
          />
          {issue && <p className="error small">{issue}</p>}

          <div className="row">
            <button className="primary" onClick={() => void start()} disabled={step === 'sealing' || !passphrase}>
              {step === 'sealing' ? 'sealing…' : 'create backup file'}
            </button>
            <button className="link" onClick={onClose} disabled={step === 'sealing'}>
              close
            </button>
          </div>
          {step === 'sealing' && (
            <p className="muted small">Sealing is slow on purpose (it is what makes the file hard to crack). A few seconds.</p>
          )}
        </>
      )}

      {step === 'done' && (
        <>
          <p>Backup downloaded.</p>
          <p className="muted small">
            Check the file landed somewhere durable (not just this device's downloads folder), and that the passphrase
            is written down. Re-export any time; each export is sealed fresh, and newer contacts and verifications are
            only in newer exports.
          </p>
          <button className="link" onClick={onClose}>
            close
          </button>
        </>
      )}
    </section>
  )
}
