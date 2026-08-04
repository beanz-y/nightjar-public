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

  // The requirements are DERIVED from the same list that is shown on screen, so the
  // rules a person reads and the rules that actually gate the button cannot drift
  // apart. Add a rule here and it appears in the list; there is no second copy.
  const rules: Array<{ label: string; met: boolean; error: string }> =
    kind === 'pin'
      ? [
          {
            label: 'digits only',
            met: /^\d+$/.test(secret),
            error: 'a PIN must be digits only',
          },
          {
            label: `at least ${PIN_MIN_DIGITS} digits`,
            met: secret.length >= PIN_MIN_DIGITS,
            error: `use at least ${PIN_MIN_DIGITS} digits`,
          },
        ]
      : [
          {
            label: `at least ${LOCK_PASSPHRASE_MIN_LENGTH} characters`,
            met: secret.trim().length >= LOCK_PASSPHRASE_MIN_LENGTH,
            error: `use at least ${LOCK_PASSPHRASE_MIN_LENGTH} characters (a few random words work well)`,
          },
        ]
  rules.push({
    label: 'both entries match',
    met: secret.length > 0 && secret === confirm,
    error: 'the two entries do not match',
  })

  const issue = (): string | null => rules.find((r) => !r.met)?.error ?? null

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

      {/* A password manager keys both saving and filling off `autocomplete` and a
          stable field identity. Without them it often never offers to save this
          at all, which quietly pushes people toward a secret they can hold in
          their head: the opposite of what this screen is asking for, since the
          only thing standing between an imaged device and everything on it is
          how hard this is to guess. */}
      <input
        className="mono"
        type="password"
        id="nightjar-applock-new"
        name="new-password"
        autoComplete="new-password"
        inputMode={kind === 'pin' ? 'numeric' : 'text'}
        placeholder={kind === 'pin' ? `PIN (${PIN_MIN_DIGITS}+ digits)` : 'passphrase'}
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
      />
      <input
        className="mono"
        type="password"
        id="nightjar-applock-confirm"
        name="confirm-password"
        autoComplete="new-password"
        inputMode={kind === 'pin' ? 'numeric' : 'text'}
        placeholder="confirm"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
      />

      {/* What is actually required, said up front rather than discovered by being
          refused. These are the same checks that gate the button (see `rules`). */}
      <ul className="lock-rules tiny" aria-label={kind === 'pin' ? 'PIN requirements' : 'passphrase requirements'}>
        {rules.map((r) => (
          <li key={r.label} className={r.met ? 'met' : ''}>
            <span aria-hidden="true">{r.met ? '✓' : '·'}</span> {r.label}
          </li>
        ))}
      </ul>
      <p className="muted tiny">
        {kind === 'pass'
          ? 'Anything else is allowed: any characters, any length above the minimum. Capitals matter, and spaces at the start or end are ignored.'
          : 'Spaces at the start or end are ignored.'}
      </p>

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
        id="nightjar-applock-unlock"
        name="password"
        autoComplete="current-password"
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
            Resetting the app-lock <strong>erases everything this device has stored</strong>: the saved messages, your
            contacts, and <strong>every conversation you have open</strong>. All of it is encrypted with the secret you
            forgot, so none of it can be kept.
          </p>
          <p className="small">
            Your <strong>identity is kept</strong>, so you are still the same person to everyone who knows you, and your
            contacts can be recovered from a backup afterwards. But each conversation has to be started again from this
            device: <strong>until you message someone, they cannot reach you</strong>. Type <code>ERASE</code> to
            confirm.
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
