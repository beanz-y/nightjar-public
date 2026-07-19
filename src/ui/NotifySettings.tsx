// Notifications control (P6). A per-device opt-in toggle plus honest disclosure.
// The toggle is only offered where it can actually work: not on an unsupported
// browser, not in an un-installed iOS Safari tab (iOS needs Home Screen first),
// and not when the relay has no push key. Enabling is always an explicit action;
// we never auto-prompt for permission.

import type { NotifyState } from './useNightjar'

interface Props {
  notify: NotifyState
  onEnable: () => void
  onDisable: () => void
}

export function NotifySettings({ notify, onEnable, onDisable }: Props) {
  const on = notify.enabled && notify.permission === 'granted'
  return (
    <div className="notify">
      <div className="field-label small muted">notifications</div>

      {!notify.supported ? (
        <p className="muted tiny">
          This browser cannot show push notifications. On de-Googled Android or Linux, a Firefox-based browser can.
        </p>
      ) : notify.needsInstall ? (
        <p className="muted tiny">
          To get notified when the app is closed, add Nightjar to your Home Screen (the Share button, then "Add to Home
          Screen"), then open it from there.
        </p>
      ) : !notify.available ? (
        <p className="muted tiny">Notifications are not set up on this relay yet.</p>
      ) : on ? (
        <>
          <button className="ghost small block" onClick={onDisable}>
            turn off notifications
          </button>
          <p className="muted tiny">On for this device.</p>
        </>
      ) : (
        <button className="primary small block" onClick={onEnable}>
          enable notifications
        </button>
      )}

      {notify.available && !on && (
        <p className="muted tiny">
          A content-free nudge ("New secure message") when something arrives while the app is closed, never the message
          itself. This shares a device token with your push provider and lets it, and the relay, see when (not what) you
          receive. Off by default, per device.
        </p>
      )}
    </div>
  )
}
