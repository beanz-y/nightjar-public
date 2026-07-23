// Settings: everything that is NOT a conversation. Your identity + a scannable
// "my code" QR (so another Nightjar user can add you), notifications, identity
// backup, and the "verify this build" (About) view. Kept off the chat surface so
// the main app reads as a messenger.

import { useState } from 'react'
import type { Identity } from '../crypto/identity'
import type { CanaryResult } from '../verify/canary'
import { About } from './About'
import { BackupPanel } from './BackupPanel'
import { NotifySettings } from './NotifySettings'
import { QrCode } from './QrCode'
import { type TimeFormat, setTimeFormat, useTimeFormat } from './timePref'
import type { NotifyState } from './useNightjar'

type Mode = 'menu' | 'mycode' | 'backup' | 'about'

interface Props {
  identity: Identity
  notify: NotifyState
  storagePersisted: boolean | null
  canary: CanaryResult | null
  bioAvailable: boolean
  lockMethods: Array<'pass' | 'pin' | 'bio'>
  onExportBackup: (passphrase: string) => Promise<boolean>
  onEnableNotifications: () => void
  onDisableNotifications: () => void
  onAddBiometric: () => void
  onRemoveBiometric: () => void
  onClose: () => void
}

export function Settings({
  identity,
  notify,
  storagePersisted,
  canary,
  bioAvailable,
  lockMethods,
  onExportBackup,
  onEnableNotifications,
  onDisableNotifications,
  onAddBiometric,
  onRemoveBiometric,
  onClose,
}: Props) {
  const [mode, setMode] = useState<Mode>('menu')
  const [copied, setCopied] = useState(false)
  const timeFmt = useTimeFormat()

  async function copyId() {
    try {
      await navigator.clipboard.writeText(identity.userId)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  if (mode === 'about') return <About canary={canary} onBack={() => setMode('menu')} />
  if (mode === 'backup') {
    return (
      <section className="sheet">
        <BackupPanel onExport={onExportBackup} storagePersisted={storagePersisted} onClose={() => setMode('menu')} />
      </section>
    )
  }
  if (mode === 'mycode') {
    return (
      <section className="sheet">
        <div className="sheet-head">
          <h2 className="small accent">my code</h2>
          <button className="link" onClick={() => setMode('menu')}>
            back
          </button>
        </div>
        <p className="muted small">
          Have another Nightjar user scan this (New chat → Scan a code) to start a conversation with you. It is your
          public user id, so it is safe to show.
        </p>
        <div className="qr-wrap">
          <QrCode text={identity.userId} size={208} />
        </div>
        <p className="mono break small yourid">{identity.userId}</p>
      </section>
    )
  }

  return (
    <section className="sheet">
      <div className="sheet-head">
        <h2 className="small accent">settings</h2>
        <button className="link" onClick={onClose}>
          close
        </button>
      </div>

      <div className="field-label small muted">your identity</div>
      <p className="mono break small yourid">{identity.userId}</p>
      <div className="row">
        <button className="ghost small" onClick={() => void copyId()}>
          {copied ? 'copied' : 'copy id'}
        </button>
        <button className="ghost small" onClick={() => setMode('mycode')}>
          show my code (QR)
        </button>
      </div>

      {bioAvailable && (
        <div className="applock">
          <div className="field-label small muted">app lock</div>
          {lockMethods.includes('bio') ? (
            <button className="ghost small" onClick={onRemoveBiometric}>
              Remove fingerprint / face unlock
            </button>
          ) : (
            <button className="ghost small" onClick={onAddBiometric}>
              Add fingerprint / face unlock
            </button>
          )}
          <p className="muted tiny">
            Unlock this device with your fingerprint or face instead of typing your passphrase. It can never be your
            only lock; your passphrase or PIN always stays as a fallback.
          </p>
        </div>
      )}

      <div className="field-label small muted">time format</div>
      <div className="row seg">
        {(['auto', '12', '24'] as TimeFormat[]).map((v) => (
          <button
            key={v}
            className={`ghost small${timeFmt === v ? ' seg-on' : ''}`}
            aria-pressed={timeFmt === v}
            onClick={() => setTimeFormat(v)}
          >
            {v === 'auto' ? 'Auto' : v === '12' ? '12-hour' : '24-hour'}
          </button>
        ))}
      </div>

      <button className="tile" onClick={() => setMode('backup')}>
        <span className="tile-icon" aria-hidden="true">⭳</span>
        <span>
          <span className="tile-title">Back up identity</span>
          <span className="tile-sub muted small">Save your identity + contacts under a passphrase.</span>
        </span>
      </button>

      <button className="tile" onClick={() => setMode('about')}>
        <span className="tile-icon" aria-hidden="true">✔</span>
        <span>
          <span className="tile-title">Verify this build</span>
          <span className="tile-sub muted small">How this app works and how to check the code you are running.</span>
        </span>
      </button>

      <NotifySettings notify={notify} onEnable={onEnableNotifications} onDisable={onDisableNotifications} />
    </section>
  )
}
