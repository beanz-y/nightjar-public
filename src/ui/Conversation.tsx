// A single conversation: the message log plus a compose box. Message bodies are
// rendered as TEXT (React escapes by default; never innerHTML), per DESIGN 8.4.

import { useEffect, useRef, useState } from 'react'
import type { TrustLevel } from '../trust/contactStore'
import { TrustBadge } from './SafetyNumber'
import type { Message } from './useNightjar'

interface Props {
  peer: string
  /** Local nickname for this chat, or '' if none. */
  name: string
  messages: Message[]
  trust: TrustLevel | null
  onSend: (text: string) => void
  onVerify: () => void
  onRename: (name: string) => void
  /** Narrow-screen navigation: return to the conversation list. */
  onBack?: () => void
}

export function Conversation({ peer, name, messages, trust, onSend, onVerify, onRename, onBack }: Props) {
  const [draft, setDraft] = useState('')
  const [renaming, setRenaming] = useState(false)
  const [nameDraft, setNameDraft] = useState(name)
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' })
  }, [messages.length])

  function submit() {
    const t = draft.trim()
    if (!t) return
    onSend(t)
    setDraft('')
  }

  function saveName() {
    onRename(nameDraft.trim())
    setRenaming(false)
  }

  const shortId = `${peer.slice(0, 8)}…${peer.slice(-6)}`

  return (
    <div className="convo">
      <header className="convo-head">
        <div className="convo-peer">
          {onBack && (
            <button className="icon-btn back-btn" title="back" onClick={onBack}>
              ‹
            </button>
          )}
          <div className="convo-idblock">
            {renaming ? (
              <div className="row">
                <input
                  autoFocus
                  value={nameDraft}
                  placeholder="name this chat"
                  maxLength={60}
                  onChange={(e) => setNameDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') saveName()
                    if (e.key === 'Escape') setRenaming(false)
                  }}
                />
                <button className="ghost small" onClick={saveName}>
                  save
                </button>
              </div>
            ) : (
              <div className="convo-title">
                <span className="convo-name">{name || shortId}</span>
                <button
                  className="icon-btn rename-btn"
                  title={name ? 'rename this chat' : 'name this chat'}
                  onClick={() => {
                    setNameDraft(name)
                    setRenaming(true)
                  }}
                >
                  ✎
                </button>
              </div>
            )}
            {/* The real device id stays visible so verification is always by
                identity, never by the (cosmetic, self-set) name. */}
            <div className="mono break tiny muted">{peer}</div>
            {trust && <TrustBadge trust={trust} />}
          </div>
        </div>
        <button className="ghost small" onClick={onVerify}>
          {trust === 'verified' ? 'verified ✓' : 'verify'}
        </button>
      </header>

      <div className="msgs">
        {messages.length === 0 && <p className="muted small">No messages yet. Say hello.</p>}
        {messages.map((m) => (
          <div key={m.id} className={`msg msg-${m.dir}`}>
            <span className={`bubble${m.failed ? ' bubble-failed' : ''}`}>{m.text}</span>
            {m.failed && <span className="error tiny">not sent</span>}
          </div>
        ))}
        <div ref={endRef} />
      </div>

      <div className="compose">
        <input
          value={draft}
          placeholder="message"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') submit()
          }}
        />
        <button className="primary" disabled={!draft.trim()} onClick={submit}>
          send
        </button>
      </div>
    </div>
  )
}
