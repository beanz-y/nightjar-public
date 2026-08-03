// Move to a new device (Phase D, DESIGN 8.3). Makes ONE encrypted file that
// carries this device's whole standing (identity, contacts and who you verified,
// nicknames, deletion markers, and every saved message) to a new device, then
// offers to erase this one. A move is a COPY, not a sync: the honest copy leads,
// not the reassurance.
//
// The passphrase is GENERATED here and shown once. It never comes from the user:
// the file holds every plaintext, and it is typed exactly once on the new device,
// so memorability buys nothing and a weak typed secret would be the only weak
// link. The panel steers hard against screenshotting it onto the device that
// holds the file.

import { useState } from 'react'
import { generateBackupPassphrase } from '../crypto/backup'

type Prepared =
  | { ok: true; messages: number; contacts: number; unreadable: number; orphaned: number; bytes: number }
  | { ok: false; blocked: 'outbox' | 'too-large'; count: number }

interface Props {
  onPrepare: () => Promise<Prepared | null>
  onCreate: (passphrase: string) => Promise<boolean>
  onErase: () => Promise<void>
  moveExported: boolean
  moveProgress: { done: number; total: number } | null
  onClose: () => void
}

type Step = 'intro' | 'ready' | 'passphrase' | 'done' | 'erase'

function sizeText(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function MovePanel({ onPrepare, onCreate, onErase, moveExported, moveProgress, onClose }: Props) {
  const [step, setStep] = useState<Step>(moveExported ? 'done' : 'intro')
  const [prepared, setPrepared] = useState<Prepared | null>(null)
  const [busy, setBusy] = useState(false)
  const [passphrase, setPassphrase] = useState('')
  const [eraseConfirm, setEraseConfirm] = useState('')

  const prepare = async () => {
    setBusy(true)
    const p = await onPrepare()
    setBusy(false)
    if (p) {
      setPrepared(p)
      setStep('ready')
    }
  }

  const create = async () => {
    setBusy(true)
    const ok = await onCreate(passphrase)
    setBusy(false)
    if (ok) setStep('done')
  }

  return (
    <section className="panel">
      <h3>Move to a new device</h3>

      {step === 'intro' && (
        <>
          <p className="muted small">
            This makes one file that carries everything this device knows: your identity, your contacts and your record
            of who you verified, your nicknames, your deleted-conversation markers, and every saved message. Anyone with
            the file and its passphrase can read all of it and can become you on another device, history and verified
            status included, and your contacts would see nothing change. The passphrase is generated for you and shown
            once: it is the file's whole security.
          </p>
          <p className="muted small">
            A move is a copy, not a sync. The file holds this moment: messages that arrive after it is made are not in
            it, and the two devices never share anything afterward. Move when your conversations are quiet. Once the new
            device takes over, anything sent to you can be lost until you message each contact from it, and the sender's
            app still shows delivered either way. Nobody is told you moved, so tell them.
          </p>
          <div className="row">
            <button className="primary" onClick={() => void prepare()} disabled={busy}>
              {busy ? 'checking…' : 'continue'}
            </button>
            <button className="link" onClick={onClose} disabled={busy}>
              close
            </button>
          </div>
        </>
      )}

      {step === 'ready' && prepared && !prepared.ok && (
        <>
          {prepared.blocked === 'outbox' ? (
            <p className="small">
              {prepared.count} message{prepared.count === 1 ? ' is' : 's are'} still waiting to send. Stay connected
              until they show sent, then try again. A message still waiting when you move will never be sent by either
              device.
            </p>
          ) : (
            <p className="small">
              This device holds more saved history than one move file can carry ({prepared.count} messages). Clear
              messages you no longer need (in a conversation: Clear messages), then try again.
            </p>
          )}
          <div className="row">
            <button className="ghost" onClick={() => void prepare()} disabled={busy}>
              check again
            </button>
            <button className="link" onClick={onClose}>
              close
            </button>
          </div>
        </>
      )}

      {step === 'ready' && prepared && prepared.ok && (
        <>
          <p className="muted small">
            This file will carry <strong>{prepared.messages}</strong> saved message{prepared.messages === 1 ? '' : 's'}{' '}
            and <strong>{prepared.contacts}</strong> contact{prepared.contacts === 1 ? '' : 's'}, about{' '}
            {sizeText(prepared.bytes)} before sealing.
          </p>
          {prepared.unreadable > 0 && (
            <p className="muted tiny">
              {prepared.unreadable} saved row{prepared.unreadable === 1 ? '' : 's'} could not be read on this device and
              will not be included.
            </p>
          )}
          <div className="row">
            <button
              className="primary"
              onClick={() => {
                setPassphrase(generateBackupPassphrase())
                setStep('passphrase')
              }}
            >
              make the move file
            </button>
            <button className="link" onClick={onClose}>
              close
            </button>
          </div>
        </>
      )}

      {step === 'passphrase' && (
        <>
          <p className="muted small">
            Write this passphrase on paper. You will type it once on the new device, and it cannot be recovered. Do not
            photograph it or paste it into notes: screenshots and notes often sync to a cloud account, and this
            passphrase opens every message you have saved. Send the file and the passphrase by different routes.
          </p>
          <p className="mono break yourid" aria-label="generated passphrase">
            {passphrase}
          </p>
          <div className="row">
            <button className="primary" onClick={() => void create()} disabled={busy}>
              {busy ? 'sealing…' : 'download the move file'}
            </button>
            <button className="link" onClick={onClose} disabled={busy}>
              cancel
            </button>
          </div>
          {busy && <p className="muted small">Sealing is slow on purpose (it is what makes the file hard to crack). A few seconds.</p>}
        </>
      )}

      {step === 'done' && (
        <>
          <p>Move file downloaded.</p>
          <p className="muted small">
            On the new device, open Nightjar, choose restore, and pick this file. When it is working there, send each
            contact a message so they can reach you again, then come back here to erase this device's copy. Delete the
            move file everywhere it landed and destroy the passphrase note; deleting is good hygiene, not a guarantee (a
            copy synced to a cloud account can outlive it).
          </p>
          <div className="row">
            <button className="ghost" onClick={() => setStep('erase')}>
              erase Nightjar from this device
            </button>
            <button className="link" onClick={onClose}>
              close
            </button>
          </div>
        </>
      )}

      {step === 'erase' && (
        <>
          <p className="small">
            This removes Nightjar's data from this browser: your identity, your contacts, and every saved message. It is
            not a forensic wipe, but this device will no longer be you. Do this only after the new device works and you
            have sent a test message from it. Type ERASE to confirm.
          </p>
          <input
            className="mono"
            value={eraseConfirm}
            onChange={(e) => setEraseConfirm(e.target.value)}
            autoCapitalize="characters"
            autoCorrect="off"
            spellCheck={false}
            aria-label="type ERASE to confirm"
          />
          <div className="row">
            <button className="danger" onClick={() => void onErase()} disabled={eraseConfirm !== 'ERASE'}>
              erase this device
            </button>
            <button className="link" onClick={() => setStep('done')}>
              back
            </button>
          </div>
        </>
      )}

      {moveProgress && (
        <p className="muted small" role="status">
          moving your messages: {moveProgress.done} / {moveProgress.total}, keep this screen open
        </p>
      )}
    </section>
  )
}
