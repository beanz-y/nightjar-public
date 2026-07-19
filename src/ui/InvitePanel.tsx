// Mint and share an invite (DESIGN 6.3). The shared artifact carries the invite
// code AND the inviter's full-width userId, so the joiner's client can pin the
// inviter's real identity key. It must travel over a channel the recipient
// already trusts (in person, or an existing trusted chat), because the operator
// that mints and renders it could otherwise substitute it (see DESIGN 6.1/6.3).

import { useState } from 'react'
import type { MintedInvite } from './useNightjar'
import { QrCode } from './QrCode'

interface Props {
  minted: MintedInvite | null
  onMint: () => void
  onClose: () => void
}

export function InvitePanel({ minted, onMint, onClose }: Props) {
  const [copied, setCopied] = useState<string | null>(null)

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
