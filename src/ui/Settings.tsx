// Settings: everything that is NOT a conversation. Your identity + a scannable
// "my code" QR (so another Nightjar user can add you), notifications, identity
// backup, and the "verify this build" (About) view. Kept off the chat surface so
// the main app reads as a messenger.

import { useState } from 'react'
import type { CanaryResult } from '../verify/canary'
import { About } from './About'
import { BackupPanel } from './BackupPanel'
import { type DeviceRow, DevicesPanel, type HistoryTransferProps } from './DevicesPanel'
import { MovePanel } from './MovePanel'
import { DownloadIcon, ShieldCheckIcon } from './icons'
import { NotifySettings } from './NotifySettings'
import { QrCode } from './QrCode'
import { type TimeFormat, setTimeFormat, useTimeFormat } from './timePref'
import type { NotifyState } from './useNightjar'

type Mode = 'menu' | 'mycode' | 'backup' | 'move' | 'devices' | 'about'

type Prepared =
  | { ok: true; messages: number; contacts: number; unreadable: number; orphaned: number; bytes: number }
  | { ok: false; blocked: 'outbox' | 'too-large'; count: number }

interface Props {
  /** The ACCOUNT id, which is who other people add and what a conversation is
   *  filed under. On a linked device this is NOT `identity.userId`: that is the
   *  DEVICE id, and handing it out would give somebody a chat with one device of
   *  an account rather than with the person, unverifiable against their safety
   *  number and invisible to their other devices. */
  accountId: string
  notify: NotifyState
  storagePersisted: boolean | null
  canary: CanaryResult | null
  bioAvailable: boolean
  lockMethods: Array<'pass' | 'pin' | 'bio'>
  moveExported: boolean
  moveProgress: { done: number; total: number } | null
  onExportBackup: (passphrase: string) => Promise<boolean>
  onPrepareMove: () => Promise<Prepared | null>
  onCreateMove: (passphrase: string) => Promise<boolean>
  onEraseDevice: () => Promise<void>
  onRotateAccount: () => Promise<string | null>
  onListDevices: () => Promise<DeviceRow[]>
  onRemoveDevice: (deviceId: string) => Promise<boolean>
  onAuthorizeDevice: (codeText: string) => Promise<{ deviceId: string; secret: Uint8Array } | null>
  onSealLink: (secret: Uint8Array) => Promise<Uint8Array | null>
  onSendLinkOverRelay: (deviceId: string, secret: Uint8Array) => Promise<boolean>
  history: HistoryTransferProps
  onEnableNotifications: () => void
  onDisableNotifications: () => void
  onAddBiometric: () => void
  onRemoveBiometric: () => void
  onClose: () => void
}

export function Settings({
  accountId,
  notify,
  storagePersisted,
  canary,
  bioAvailable,
  lockMethods,
  moveExported,
  moveProgress,
  onExportBackup,
  onPrepareMove,
  onCreateMove,
  onEraseDevice,
  onRotateAccount,
  onListDevices,
  onRemoveDevice,
  onAuthorizeDevice,
  onSealLink,
  onSendLinkOverRelay,
  history,
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
      await navigator.clipboard.writeText(accountId)
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
  if (mode === 'move') {
    return (
      <section className="sheet">
        <MovePanel
          onPrepare={onPrepareMove}
          onCreate={onCreateMove}
          onErase={onEraseDevice}
          moveExported={moveExported}
          moveProgress={moveProgress}
          onClose={() => setMode('menu')}
        />
      </section>
    )
  }
  if (mode === 'devices') {
    return (
      <section className="sheet">
        <DevicesPanel
          onList={onListDevices}
          onRemove={onRemoveDevice}
          onAuthorize={onAuthorizeDevice}
          onSeal={onSealLink}
          onSendOverRelay={onSendLinkOverRelay}
          onErase={onEraseDevice}
          onRotate={onRotateAccount}
          history={history}
          onClose={() => setMode('menu')}
        />
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
          <QrCode text={accountId} size={208} />
        </div>
        <p className="mono break small yourid">{accountId}</p>
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
      <p className="mono break small yourid">{accountId}</p>
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
        <span className="tile-icon" aria-hidden="true">
          <DownloadIcon />
        </span>
        <span>
          <span className="tile-title">Back up identity</span>
          <span className="tile-sub muted small">Save your identity + contacts under a passphrase.</span>
        </span>
      </button>

      <button className="tile" onClick={() => setMode('devices')}>
        <span className="tile-icon" aria-hidden="true">
          <ShieldCheckIcon />
        </span>
        <span>
          <span className="tile-title">Your devices</span>
          <span className="tile-sub muted small">See what can read your messages, and link another device.</span>
        </span>
      </button>

      <button className="tile" onClick={() => setMode('move')}>
        <span className="tile-icon" aria-hidden="true">
          <DownloadIcon />
        </span>
        <span>
          <span className="tile-title">Move to a new device</span>
          <span className="tile-sub muted small">Carry your messages and contacts to a new device, then erase this one.</span>
        </span>
      </button>

      <button className="tile" onClick={() => setMode('about')}>
        <span className="tile-icon" aria-hidden="true">
          <ShieldCheckIcon />
        </span>
        <span>
          <span className="tile-title">Verify this build</span>
          <span className="tile-sub muted small">How this app works and how to check the code you are running.</span>
        </span>
      </button>

      <NotifySettings notify={notify} onEnable={onEnableNotifications} onDisable={onDisableNotifications} />
    </section>
  )
}
