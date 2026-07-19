// A single conversation: the message log plus a compose box. Message bodies are
// rendered as TEXT (React escapes by default; never innerHTML), per DESIGN 8.4.

import { useEffect, useRef, useState } from 'react'
import type { TrustLevel } from '../trust/contactStore'
import { TrustBadge } from './SafetyNumber'
import type { Message } from './useNightjar'

interface Props {
  peer: string
  messages: Message[]
  trust: TrustLevel | null
  onSend: (text: string) => void
  onVerify: () => void
}

export function Conversation({ peer, messages, trust, onSend, onVerify }: Props) {
  const [draft, setDraft] = useState('')
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

  return (
    <div className="convo">
      <header className="convo-head">
        <div>
          <div className="mono break small">{peer}</div>
          {trust && <TrustBadge trust={trust} />}
        </div>
        <button className="ghost small" onClick={onVerify}>
          {trust === 'verified' ? 'verified ✓' : 'verify'}
        </button>
      </header>

      <div className="msgs">
        {messages.length === 0 && <p className="muted small">No messages yet. Say hello.</p>}
        {messages.map((m) => (
          <div key={m.id} className={`msg msg-${m.dir}`}>
            <span className="bubble">{m.text}</span>
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
