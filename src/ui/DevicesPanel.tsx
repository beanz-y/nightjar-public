// The devices on this account (Sesame B3), read from the list this account
// publishes, because that list is what everyone ELSE uses to decide where to send
// you things. A device on it receives your messages; a device off it does not.
//
// Two things this screen has to say plainly rather than bury, because both cut
// against what people expect from other apps:
//
//   - Removing a device is not taking anything away from it. It keeps every
//     message it already had, and it still holds the account key, so it could put
//     itself back on the list. For a device that is LOST rather than retired, the
//     honest answer is that the account is compromised.
//   - Verifying a contact belongs to the device that did it. A newly linked
//     device shows everyone as unverified, and that is deliberate: nothing
//     remote, not even another of your own devices, can mark a contact verified.

import { useCallback, useEffect, useState } from 'react'
import { HistoryTransferPanel } from './HistoryTransferPanel'
import { LinkDevicePanel } from './LinkDevicePanel'

export interface DeviceRow {
  deviceId: string
  addedAt: number
  isThisDevice: boolean
  /** The account's first device, which cannot be taken off its own account. */
  isFirstDevice: boolean
}

interface Props {
  onList: () => Promise<DeviceRow[]>
  onRemove: (deviceId: string) => Promise<boolean>
  onAuthorize: (codeText: string) => Promise<{ deviceId: string; secret: Uint8Array } | null>
  onSeal: (secret: Uint8Array) => Promise<Uint8Array | null>
  onSendOverRelay: (deviceId: string, secret: Uint8Array) => Promise<boolean>
  onErase: () => Promise<void>
  /** Replace this account's key. Resolves with the new account id. */
  onRotate: () => Promise<string | null>
  history: HistoryTransferProps
  onClose: () => void
}

/** The saved-messages ceremony, passed straight through: this panel decides only
 *  which half is being run. */
export interface HistoryTransferProps {
  onStartRequest: () => { code: string; deviceId: string } | null
  onCancelRequest: () => void
  onReadCode: (codeText: string) => { deviceId: string; secret: Uint8Array } | null
  onPrepare: (since: number) => Promise<{ count: number; bytes: number; tooLarge: boolean; orphaned: number } | null>
  onSeal: (deviceId: string, secret: Uint8Array, since: number) => Promise<Uint8Array | null>
  onReceive: (blob: Uint8Array) => Promise<boolean>
  progress: { done: number; total: number } | null
}

function shortId(id: string): string {
  return `${id.slice(0, 8)}…${id.slice(-4)}`
}

export function DevicesPanel({
  onList,
  onRemove,
  onAuthorize,
  onSeal,
  onSendOverRelay,
  onErase,
  onRotate,
  history,
  onClose,
}: Props) {
  const [devices, setDevices] = useState<DeviceRow[] | null>(null)
  const [linking, setLinking] = useState(false)
  const [historyMode, setHistoryMode] = useState<'send' | 'receive' | null>(null)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [startingOver, setStartingOver] = useState(false)
  const [eraseConfirm, setEraseConfirm] = useState('')
  const [rotating, setRotating] = useState(false)
  const [rotateConfirm, setRotateConfirm] = useState('')
  const [rotateBusy, setRotateBusy] = useState(false)

  const refresh = useCallback(async () => {
    setDevices(await onList())
  }, [onList])

  useEffect(() => {
    void refresh()
  }, [refresh])

  if (historyMode) {
    return (
      <HistoryTransferPanel
        mode={historyMode}
        onStartRequest={history.onStartRequest}
        onCancelRequest={history.onCancelRequest}
        onReadCode={history.onReadCode}
        onPrepare={history.onPrepare}
        onSeal={history.onSeal}
        onReceive={history.onReceive}
        progress={history.progress}
        onClose={() => setHistoryMode(null)}
      />
    )
  }

  if (linking) {
    return (
      <LinkDevicePanel
        onAuthorize={onAuthorize}
        onSeal={onSeal}
        onSendOverRelay={onSendOverRelay}
        onDone={() => void refresh()}
        onClose={() => {
          setLinking(false)
          void refresh()
        }}
      />
    )
  }

  return (
    <div className="devices-panel">
      <div className="sheet-head">
        <h2 className="small accent">your devices</h2>
        <button className="link" onClick={onClose}>
          back
        </button>
      </div>

      {devices === null && <p className="muted small">reading your device list…</p>}

      {devices?.map((d) => (
        <div className="device-row" key={d.deviceId}>
          <span>
            <span className="mono small break">{shortId(d.deviceId)}</span>
            <span className="tile-sub muted small">
              {[
                d.isThisDevice ? 'this device' : null,
                d.isFirstDevice ? 'first device' : null,
                !d.isThisDevice && d.addedAt > 0 ? `added ${new Date(d.addedAt).toLocaleDateString()}` : null,
              ]
                .filter(Boolean)
                .join(' · ')}
            </span>
          </span>
          {/* Not offered for the first device, whose key IS the account key: its id
              is the account id, so removing it would be an account taking itself
              off its own list, and the attempt is refused. Seen from a LINKED
              device that row looks like any other, which is why the list says
              which one it is rather than leaving the UI to guess. */}
          {!d.isThisDevice && !d.isFirstDevice && (
            <button className="ghost small" onClick={() => setConfirming(d.deviceId)}>
              remove
            </button>
          )}
        </div>
      ))}

      {confirming && (
        <div className="banner banner-alert" role="alert">
          <span className="small">
            Remove {shortId(confirming)}? Others will stop sending to it. It keeps the messages it already has, and
            this does not lock it out: if that device is lost rather than finished with, treat your account as
            compromised instead.
          </span>
          <span className="row">
            <button
              className="ghost small"
              onClick={() => {
                const id = confirming
                setConfirming(null)
                void onRemove(id).then(() => refresh())
              }}
            >
              remove it
            </button>
            <button className="link" onClick={() => setConfirming(null)}>
              cancel
            </button>
          </span>
        </div>
      )}

      <button className="primary block" onClick={() => setLinking(true)}>
        link another device
      </button>

      {/* The deliberate act that carries history to a device that started empty.
          Both halves live here because which one you need depends on which
          device you are holding, and only the person knows that. */}
      <div className="field-label small muted">saved messages</div>
      <div className="row">
        <button className="ghost small" onClick={() => setHistoryMode('send')}>
          Send saved messages
        </button>
        <button className="ghost small" onClick={() => setHistoryMode('receive')}>
          Get saved messages
        </button>
      </div>
      <p className="muted tiny">
        Messages are not carried across when you add a device, and they are never synced afterwards. This hands a copy
        of what one device has saved to another of yours, on screen, without any of it going over the network. Do it
        from the device that HAS the messages, and choose <em>Get</em> on the one that wants them.
      </p>

      <p className="muted tiny">
        A device you add starts empty: nothing you have already received is moved to it, and every contact shows there
        as unverified until you compare safety numbers on that device. That is on purpose. The digits are the same on
        both, so re-checking is performing the ritual again rather than new proof, but what it buys is a record on THAT
        device that nothing remote can forge, not even another of your own.
      </p>
      <p className="muted tiny">
        Your safety numbers do not change when you add a device: they cover your account, not each machine. So a
        contact who verified you stays verified, and equally, a device of yours that someone else got hold of would
        still show them a matching safety number.
      </p>

      {/* Replacing the account key. The copy here is the feature: rotation is
          routinely misread as "revoke a stolen device", and it is not that. It
          helps when the old key is GONE but not in use; it does not beat somebody
          actively using it, because they can sign a rotation exactly as validly
          as you can. So the screen says that before the button, not after. */}
      <div className="field-label small muted">replacing your account key</div>
      {!rotating ? (
        <>
          <button className="ghost small" onClick={() => setRotating(true)}>
            replace my account key
          </button>
          <p className="muted tiny">
            For a phone you lost, or a key whose storage you no longer trust. Your contacts keep this conversation and
            everything in it instead of meeting a stranger, and your messages keep flowing to the devices you already
            have.
          </p>
        </>
      ) : (
        <>
          <p className="small">
            This gives you a new account key and a new id, and tells your contacts to follow it. What it does NOT do:
            it does not lock out anyone who is <em>already using</em> your old key. They hold the same key, so they can
            make a statement exactly as valid as yours, and nothing in it tells the two apart. Treat this as useful
            when the old key is gone and not in use, and not as a way to take an account back from somebody who has it.
          </p>
          <p className="small">
            Everyone who has verified you will show as <em>unverified</em> afterwards and has to compare safety numbers
            with you again, in person. That is deliberate: carrying a verification across would hand it to whoever
            wrote the statement.
          </p>
          {/* Only worth saying when there is something to lose: the other devices
              keep the retired key and cannot act for the account afterwards. */}
          {(devices?.length ?? 0) > 1 && (
            <p className="small">
              Your other devices keep the old key and will not be able to act for this account afterwards. Add them
              again once this is done.
            </p>
          )}
          <p className="muted tiny">Type REPLACE to confirm.</p>
          <input
            className="mono"
            value={rotateConfirm}
            onChange={(e) => setRotateConfirm(e.target.value)}
            autoCapitalize="characters"
            autoCorrect="off"
            spellCheck={false}
            aria-label="type REPLACE to confirm"
          />
          <div className="row">
            <button
              className="danger"
              disabled={rotateConfirm !== 'REPLACE' || rotateBusy}
              onClick={() => {
                setRotateBusy(true)
                void onRotate()
                  .then(() => refresh())
                  .finally(() => {
                    setRotateBusy(false)
                    setRotating(false)
                    setRotateConfirm('')
                  })
              }}
            >
              {rotateBusy ? 'replacing…' : 'replace my account key'}
            </button>
            <button
              className="link"
              disabled={rotateBusy}
              onClick={() => {
                setRotating(false)
                setRotateConfirm('')
              }}
            >
              cancel
            </button>
          </div>
        </>
      )}

      {/* Adding a device THAT ALREADY HAS ITS OWN ACCOUNT is refused, because
          linking keeps what a device holds rather than replacing it, so joining
          would leave one store holding two accounts. The way through is to start
          the device over, which needs to be reachable from here: it used to sit
          behind downloading a move file, so repurposing a device meant exporting
          a file you did not want just to reach the button. */}
      <div className="field-label small muted">starting over</div>
      {!startingOver ? (
        <>
          <button className="ghost small" onClick={() => setStartingOver(true)}>
            start over on this device
          </button>
          <p className="muted tiny">
            Use this on a device that already has its own Nightjar account and that you want to add to a different
            one instead. It has to be done on the device being added, before you add it.
          </p>
        </>
      ) : (
        <>
          <p className="small">
            This removes Nightjar from this device: its identity, its contacts, and every saved message. This device
            stops being the account it is now, and the people who have that id will no longer be able to reach it.
            Nothing here is recoverable afterwards, and nothing is sent anywhere: if you want to keep what is on this
            device, close this and use <em>Move to a new device</em> first. Type ERASE to confirm.
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
            <button className="danger" disabled={eraseConfirm !== 'ERASE'} onClick={() => void onErase()}>
              erase this device
            </button>
            <button
              className="link"
              onClick={() => {
                setStartingOver(false)
                setEraseConfirm('')
              }}
            >
              cancel
            </button>
          </div>
        </>
      )}
    </div>
  )
}
