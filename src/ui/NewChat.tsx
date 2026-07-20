// The "new chat" sheet: the one place a registered user starts a conversation.
// Three intuitive paths, matching how identity works in Nightjar (no directory,
// no phone numbers):
//   - Scan a code: point the camera at someone's invite or user-id QR.
//   - Enter a code: paste an invite link/code, or a 52-char user id.
//   - Show my invite: mint a single-use invite QR/link to bring a NEW person on.
// Scanning/entering routes through openFromCode (invite -> pin + chat; user id ->
// trust-on-first-use chat). Showing an invite reuses the existing InvitePanel.

import { useState } from 'react'
import { InvitePanel } from './InvitePanel'
import { QrScanner } from './QrScanner'
import type { MintedInvite } from './useNightjar'

type Mode = 'menu' | 'scan' | 'enter' | 'invite'

interface Props {
  minted: MintedInvite | null
  onMint: () => void
  /** Resolve a scanned/entered code to a peer id and open the chat, or null. */
  onCode: (input: string) => Promise<string | null>
  onOpened: (peer: string) => void
  onClose: () => void
}

export function NewChat({ minted, onMint, onCode, onOpened, onClose }: Props) {
  const [mode, setMode] = useState<Mode>('menu')
  const [entry, setEntry] = useState('')
  const [busy, setBusy] = useState(false)

  async function resolve(input: string) {
    if (!input.trim() || busy) return
    setBusy(true)
    const peer = await onCode(input)
    setBusy(false)
    if (peer) onOpened(peer)
  }

  if (mode === 'scan') {
    return (
      <section className="sheet">
        <div className="sheet-head">
          <h2 className="small accent">scan a code</h2>
          <button className="link" onClick={() => setMode('menu')}>
            back
          </button>
        </div>
        <QrScanner onDecode={(text) => void resolve(text)} onCancel={() => setMode('menu')} />
        <p className="muted tiny">
          Scan the invite QR someone showed you, or their "my code" QR. On a browser without camera access, use "enter a
          code" instead.
        </p>
      </section>
    )
  }

  if (mode === 'enter') {
    return (
      <section className="sheet">
        <div className="sheet-head">
          <h2 className="small accent">enter a code</h2>
          <button className="link" onClick={() => setMode('menu')}>
            back
          </button>
        </div>
        <p className="muted small">Paste an invite link or code, or a 52-character user id.</p>
        <textarea
          className="mono"
          rows={3}
          placeholder="invite link / code, or a user id"
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
        />
        <button className="primary block" disabled={busy || !entry.trim()} onClick={() => void resolve(entry)}>
          {busy ? 'opening…' : 'open chat'}
        </button>
      </section>
    )
  }

  if (mode === 'invite') {
    return (
      <section className="sheet">
        <InvitePanel minted={minted} onMint={onMint} onClose={() => setMode('menu')} />
      </section>
    )
  }

  return (
    <section className="sheet">
      <div className="sheet-head">
        <h2 className="small accent">new chat</h2>
        <button className="link" onClick={onClose}>
          close
        </button>
      </div>

      <button className="tile" onClick={() => setMode('scan')}>
        <span className="tile-icon" aria-hidden="true">⧉</span>
        <span>
          <span className="tile-title">Scan a code</span>
          <span className="tile-sub muted small">Point the camera at their invite or "my code" QR.</span>
        </span>
      </button>

      <button className="tile" onClick={() => setMode('enter')}>
        <span className="tile-icon" aria-hidden="true">⌨</span>
        <span>
          <span className="tile-title">Enter a code or user id</span>
          <span className="tile-sub muted small">Paste an invite link/code, or a 52-char user id.</span>
        </span>
      </button>

      <button
        className="tile"
        onClick={() => {
          setMode('invite')
          if (!minted) onMint()
        }}
      >
        <span className="tile-icon" aria-hidden="true">＋</span>
        <span>
          <span className="tile-title">Invite someone new</span>
          <span className="tile-sub muted small">Show a single-use invite QR to bring a new person onto Nightjar.</span>
        </span>
      </button>
    </section>
  )
}
