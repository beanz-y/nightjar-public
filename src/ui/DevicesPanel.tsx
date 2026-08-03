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
  onClose: () => void
}

function shortId(id: string): string {
  return `${id.slice(0, 8)}…${id.slice(-4)}`
}

export function DevicesPanel({ onList, onRemove, onAuthorize, onSeal, onSendOverRelay, onErase, onClose }: Props) {
  const [devices, setDevices] = useState<DeviceRow[] | null>(null)
  const [linking, setLinking] = useState(false)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [startingOver, setStartingOver] = useState(false)
  const [eraseConfirm, setEraseConfirm] = useState('')

  const refresh = useCallback(async () => {
    setDevices(await onList())
  }, [onList])

  useEffect(() => {
    void refresh()
  }, [refresh])

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
