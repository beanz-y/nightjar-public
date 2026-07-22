// Mint and share an invite (DESIGN 6.3). The shared artifact carries the invite
// code AND the inviter's full-width userId, so the joiner's client can pin the
// inviter's real identity key. It must travel over a channel the recipient
// already trusts (in person, or an existing trusted chat), because the operator
// that mints and renders it could otherwise substitute it (see DESIGN 6.1/6.3).

import { useEffect, useState } from 'react'
import type { MintedInvite } from './useNightjar'
import { QrCode } from './QrCode'

/** Watch for a join at most this long while the invite is on screen. */
const POLL_WINDOW_MS = 2 * 60 * 1000
const POLL_INTERVAL_MS = 4000

interface Props {
  minted: MintedInvite | null
  onMint: () => void
  /** Pull who redeemed our invites; returns the count of newly-added contacts. */
  onSync?: (() => Promise<number>) | undefined
  onClose: () => void
}

export function InvitePanel({ minted, onMint, onSync, onClose }: Props) {
  const [copied, setCopied] = useState<string | null>(null)
  const [joined, setJoined] = useState(0)

  // While an invite is on screen, watch for the invitee to redeem it (mutual invite,
  // DESIGN 6.3): poll only while the tab is visible, and only for a couple of minutes,
  // so a user who just shared a code sees the new contact appear without needing a
  // reconnect. afterConnect is the backstop the rest of the time. The client records
  // the joiner as an UNVERIFIED (TOFU) contact, so the copy never implies it is
  // authenticated. A new mint (a new `minted` object) restarts the watch.
  useEffect(() => {
    if (!minted || !onSync) return
    setJoined(0)
    let stopped = false
    const started = Date.now()
    const poll = async () => {
      if (stopped || document.visibilityState !== 'visible') return
      try {
        const n = await onSync()
        if (!stopped && n > 0) setJoined((j) => j + n)
      } catch {
        /* best-effort; the reconnect backstop still learns them */
      }
    }
    void poll()
    const iv = setInterval(() => {
      if (Date.now() - started > POLL_WINDOW_MS) {
        clearInterval(iv)
        return
      }
      void poll()
    }, POLL_INTERVAL_MS)
    return () => {
      stopped = true
      clearInterval(iv)
    }
  }, [minted, onSync])

  async function copy(what: string, value: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(what)
      setTimeout(() => setCopied(null), 1500)
    } catch {
      setCopied(null)
    }
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h2 className="small accent">invite someone</h2>
        <button className="link" onClick={onClose}>
          close
        </button>
      </div>

      {!minted ? (
        <>
          <p className="muted small">
            Generate a single-use invite. It embeds your identity fingerprint so the person you invite pins the real
            you. Share it in person or over a channel you already trust.
          </p>
          <button className="primary" onClick={onMint}>
            generate an invite
          </button>
        </>
      ) : (
        <>
          <p className="muted small">Share this with the person you are inviting. Single use.</p>

          <div className="qr-wrap">
            <QrCode text={minted.url} size={196} />
          </div>

          <p className="muted small">
            {joined > 0
              ? 'Someone joined and was added to your chats. Verify their safety number in person before sharing anything sensitive.'
              : 'They appear in your chats automatically once they join. Keep this open.'}
          </p>

          <label className="field-label small muted">invite link</label>
          <div className="row">
            <input readOnly className="mono small" value={minted.url} onFocus={(e) => e.currentTarget.select()} />
            <button className="ghost small" onClick={() => void copy('link', minted.url)}>
              {copied === 'link' ? 'copied' : 'copy'}
            </button>
          </div>

          <label className="field-label small muted">or the code + fingerprint</label>
          <div className="row">
            <input readOnly className="mono small" value={minted.token} onFocus={(e) => e.currentTarget.select()} />
            <button className="ghost small" onClick={() => void copy('token', minted.token)}>
              {copied === 'token' ? 'copied' : 'copy'}
            </button>
          </div>

          <button className="ghost small" onClick={onMint}>
            generate another
          </button>
        </>
      )}
    </div>
  )
}
