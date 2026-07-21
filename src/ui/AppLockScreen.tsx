// The mandatory app-lock screen (P10c): enrollment on first run / restore, and
// unlock on return. The app-lock encrypts all saved messages (and your contact
// list) at rest; reading them requires unlocking here. Because Nightjar is a web
// app with no OS keychain, "encrypted at rest" necessarily means "you unlock each
// session"; this screen is that gate.

import { useState } from 'react'
import { LOCK_PASSPHRASE_MIN_LENGTH, PIN_MIN_DIGITS } from '../crypto/constants'
import type { EnrollMethod } from '../storage/appLockStore'

interface Props {
  mode: 'enroll' | 'unlock'
  restoring: boolean
  bioAvailable: boolean
  /** Methods enrolled on this device (unlock mode: whether to offer biometric). */
  lockMethods: Array<'pass' | 'pin' | 'bio'>
  onEnroll: (methods: EnrollMethod[]) => Promise<void> | void
  makeBiometric: () => Promise<EnrollMethod | null>
  onUnlock: (secret: string) => Promise<boolean>
  onUnlockBiometric: () => Promise<boolean>
  onReset: () => Promise<void> | void
}

export function AppLockScreen(props: Props) {
  return props.mode === 'enroll' ? <Enroll {...props} /> : <Unlock {...props} />
}

function Enroll({ restoring, bioAvailable, onEnroll, makeBiometric }: Props) {
  const [kind, setKind] = useState<'pass' | 'pin'>('pass')
  const [secret, setSecret] = useState('')
  const [confirm, setConfirm] = useState('')
  const [useBio, setUseBio] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const issue = (): string | null => {
    if (kind === 'pin') {
      if (!/^\d+$/.test(secret)) return 'a PIN must be digits only'
      if (secret.length < PIN_MIN_DIGITS) return `use at least ${PIN_MIN_DIGITS} digits`
    } else if (secret.trim().length < LOCK_PASSPHRASE_MIN_LENGTH) {
      return `use at least ${LOCK_PASSPHRASE_MIN_LENGTH} characters (a few random words work well)`
    }
    if (secret !== confirm) return 'the two entries do not match'
    return null
  }

  const submit = async () => {
    const problem = issue()
    if (problem) {
      setErr(problem)
      return
    }
    setErr(null)
    setBusy(true)
    try {
      const methods: EnrollMethod[] = [{ kind, secret }]
      if (useBio) {
        const bio = await makeBiometric()
        if (!bio) {
          setBusy(false)
          return // makeBiometric surfaced its own error
        }
        methods.push(bio)
      }
      await onEnroll(methods)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="lock center">
      <h2>{restoring ? 'Set an app-lock to finish restoring' : 'Set an app-lock'}</h2>
      <p className="muted small">
        Nightjar saves your messages on this device, encrypted. Your app-lock is the key: without it, no one (not even
        the operator) can read your saved messages from this device. There is no recovery if you forget it.
      </p>

      <div className="row lock-choice">
        <button className={kind === 'pass' ? 'primary small' : 'ghost small'} onClick={() => setKind('pass')}>
          Passphrase
        </button>
        <button className={kind === 'pin' ? 'primary small' : 'ghost small'} onClick={() => setKind('pin')}>
          PIN
        </button>
      </div>
      <p className="muted tiny">
        {kind === 'pass'
          ? 'Strongest at rest. A few random words are easy to remember and hard to guess.'
          : 'Convenient, but weaker: a short PIN can be brute-forced from a stolen or imaged device. Prefer a passphrase, or add biometric.'}
      </p>

      <input
        className="mono"
        type="password"
        inputMode={kind === 'pin' ? 'numeric' : 'text'}
        placeholder={kind === 'pin' ? `PIN (${PIN_MIN_DIGITS}+ digits)` : 'passphrase'}
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
      />
      <input
        className="mono"
        type="password"
        inputMode={kind === 'pin' ? 'numeric' : 'text'}
        placeholder="confirm"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
      />

      {bioAvailable && (
        <label className="row small">
          <input type="checkbox" checked={useBio} onChange={(e) => setUseBio(e.target.checked)} />
          <span>Also unlock with biometrics (Face / Touch / device unlock)</span>
        </label>
      )}

      {err && <p className="error small">{err}</p>}
      <button className="primary" disabled={busy || !secret} onClick={() => void submit()}>
        {busy ? 'setting up…' : 'set app-lock'}
      </button>
    </div>
  )
}

function Unlock({ bioAvailable, lockMethods, onUnlock, onUnlockBiometric, onReset }: Props) {
  const [secret, setSecret] = useState('')
  const [busy, setBusy] = useState(false)
  const [resetting, setResetting] = useState(false)
  const [confirmText, setConfirmText] = useState('')
  const isPin = lockMethods.includes('pin')
  const hasBio = lockMethods.includes('bio') && bioAvailable

  const submit = async () => {
    if (!secret) return
    setBusy(true)
    const ok = await onUnlock(secret)
    setBusy(false)
    if (ok) setSecret('')
  }

  return (
    <div className="lock center">
      <h2>Unlock Nightjar</h2>
      <p className="muted small">Enter your {isPin ? 'PIN' : 'passphrase'} to read your messages on this device.</p>

      {hasBio && (
        <button className="ghost" disabled={busy} onClick={() => void onUnlockBiometric()}>
          Unlock with biometrics
        </button>
      )}

      <input
        className="mono"
        type="password"
        inputMode={isPin ? 'numeric' : 'text'}
        placeholder={isPin ? 'PIN' : 'passphrase'}
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && void submit()}
        autoFocus
      />
      <button className="primary" disabled={busy || !secret} onClick={() => void submit()}>
        {busy ? 'unlocking…' : 'unlock'}
      </button>

      {!resetting ? (
        <button className="link small" onClick={() => setResetting(true)}>
          forgot your {isPin ? 'PIN' : 'passphrase'}?
        </button>
      ) : (
        <div className="lock-reset">
          <p className="small">
            Resetting the app-lock <strong>erases the saved messages on this device</strong>. Your identity and
            contacts are kept (and can also be recovered from a backup). Type <code>ERASE</code> to confirm.
          </p>
          <input className="mono" placeholder="ERASE" value={confirmText} onChange={(e) => setConfirmText(e.target.value)} />
          <div className="row">
            <button className="ghost small" onClick={() => setResetting(false)}>
              cancel
            </button>
            <button className="danger small" disabled={confirmText !== 'ERASE'} onClick={() => void onReset()}>
              erase &amp; reset
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
