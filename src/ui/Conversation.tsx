// A single conversation: the message log plus a compose box. Message bodies are
// rendered as TEXT (React escapes by default; never innerHTML), per DESIGN 8.4.

import { Fragment, useEffect, useRef, useState } from 'react'
import type { TrustLevel } from '../trust/contactStore'
import { TrustBadge } from './SafetyNumber'
import { type TimeFormat, hour12For, useTimeFormat } from './timePref'
import type { Message } from './useNightjar'

// Date/time helpers for the message log, mirroring common messengers: a centered
// day separator ("Today" / "Yesterday" / weekday / full date) when the day rolls
// over, and a small localized time under each message. All display-only, using
// the viewer's locale.
const DAY_MS = 24 * 60 * 60 * 1000
// Rapid messages from the same person within this window are grouped: only the last
// one in the run shows a timestamp, so a quick burst is not stamped on every line.
const GROUP_MS = 2 * 60 * 1000
function startOfDay(ts: number): number {
  const d = new Date(ts)
  d.setHours(0, 0, 0, 0)
  return d.getTime()
}
export function sameDay(a: number, b: number): boolean {
  return startOfDay(a) === startOfDay(b)
}
export function formatDaySeparator(ts: number, now: number): string {
  const days = Math.round((startOfDay(now) - startOfDay(ts)) / DAY_MS)
  if (days <= 0) return 'Today'
  if (days === 1) return 'Yesterday'
  const d = new Date(ts)
  if (days < 7) return d.toLocaleDateString(undefined, { weekday: 'long' })
  const sameYear = new Date(now).getFullYear() === d.getFullYear()
  return d.toLocaleDateString(undefined, { month: 'long', day: 'numeric', ...(sameYear ? {} : { year: 'numeric' }) })
}
function formatTime(ts: number, fmt: TimeFormat): string {
  const h12 = hour12For(fmt)
  return new Date(ts).toLocaleTimeString(undefined, {
    hour: 'numeric',
    minute: '2-digit',
    ...(h12 !== undefined ? { hour12: h12 } : {}),
  })
}
// The full date+time shown on hover/long-press, honoring the same 12/24h choice.
function formatFull(ts: number, fmt: TimeFormat): string {
  const h12 = hour12For(fmt)
  return new Date(ts).toLocaleString(undefined, h12 !== undefined ? { hour12: h12 } : undefined)
}
// On touch devices the on-screen keyboard's Enter inserts a newline (sending is an
// explicit Send tap); with a physical keyboard, Enter sends and Shift+Enter makes a
// newline. Keyed off the PRIMARY pointer, so a touchscreen laptop with a trackpad
// still behaves like a desktop.
function isTouchDevice(): boolean {
  try {
    return window.matchMedia('(pointer: coarse)').matches
  } catch {
    return typeof navigator !== 'undefined' && navigator.maxTouchPoints > 0
  }
}
// Max composer height before it scrolls internally (about five lines).
const COMPOSE_MAX_PX = 140

interface Props {
  peer: string
  /** Local nickname for this chat, or '' if none. */
  name: string
  messages: Message[]
  trust: TrustLevel | null
  onSend: (text: string, ephemeral: boolean) => void
  onVerify: () => void
  onRename: (name: string) => void
  /** Delete-for-everyone a message you sent (P10d). `failed` is true for a
   *  never-delivered message (removed locally only). */
  onDelete: (id: string, failed?: boolean) => void
  /** Narrow-screen navigation: return to the conversation list. */
  onBack?: () => void
}

export function Conversation({ peer, name, messages, trust, onSend, onVerify, onRename, onDelete, onBack }: Props) {
  const [draft, setDraft] = useState('')
  const [renaming, setRenaming] = useState(false)
  const [nameDraft, setNameDraft] = useState(name)
  // The outbound message whose delete menu is open (P10d), or null.
  const [menuFor, setMenuFor] = useState<string | null>(null)
  // Session-only (P10e) compose mode. STICKY within this open conversation, default
  // OFF. It is component-local state and this component is remounted per peer
  // (key={peer} in Messenger) AND lives only in RAM, so it resets to OFF on peer
  // switch, reload, and lock - a forgotten armed toggle can never silently follow
  // you to another chat or survive a restart.
  const [sessionOnly, setSessionOnly] = useState(false)
  const timeFmt = useTimeFormat()
  const endRef = useRef<HTMLDivElement>(null)
  const msgsRef = useRef<HTMLDivElement>(null)
  const composerRef = useRef<HTMLTextAreaElement>(null)

  const scrollToBottom = () => endRef.current?.scrollIntoView({ block: 'end' })

  // Keep the newest message in view on a new message.
  useEffect(() => {
    scrollToBottom()
  }, [messages.length])

  // The mobile keyboard shrinks the visual viewport and can hide the latest
  // messages; when it opens or resizes while the composer is focused, re-pin to the
  // bottom so what you just typed and the newest messages stay visible.
  useEffect(() => {
    const vv = window.visualViewport
    if (!vv) return
    const onResize = () => {
      if (document.activeElement === composerRef.current) scrollToBottom()
    }
    vv.addEventListener('resize', onResize)
    return () => vv.removeEventListener('resize', onResize)
  }, [])

  // Auto-grow the composer with its content, up to a cap (then it scrolls inside).
  // Growing the box shrinks the message pane, so if we were pinned to the bottom,
  // re-pin after resizing to keep the newest message visible. Measure BEFORE the
  // resize so a user scrolled up reading history while typing is not yanked down.
  useEffect(() => {
    const el = composerRef.current
    if (!el) return
    const pane = msgsRef.current
    const wasNearBottom = pane ? pane.scrollHeight - pane.scrollTop - pane.clientHeight < 80 : true
    // The composer is a flex item, and a flex item's explicit `height` is overridden
    // by the container's cross-axis sizing; `min-height` IS honored. So reset the
    // floor, let the box collapse to one row, measure the content, then set both the
    // height (for non-flex fallbacks) and the load-bearing min-height to it.
    el.style.minHeight = '0px'
    el.style.height = 'auto'
    const h = Math.min(el.scrollHeight, COMPOSE_MAX_PX)
    el.style.height = `${h}px`
    el.style.minHeight = `${h}px`
    if (wasNearBottom) scrollToBottom()
  }, [draft])

  // Close the delete menu on any outside click / Escape.
  useEffect(() => {
    if (!menuFor) return
    const close = () => setMenuFor(null)
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setMenuFor(null)
    document.addEventListener('click', close)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('click', close)
      document.removeEventListener('keydown', onKey)
    }
  }, [menuFor])

  function submit() {
    const t = draft.trim()
    if (!t) return
    onSend(t, sessionOnly)
    setDraft('')
  }

  function saveName() {
    onRename(nameDraft.trim())
    setRenaming(false)
  }

  // Reference "now" for relative day labels ("Today"/"Yesterday"), recomputed each
  // render (which happens on every new message, keeping labels fresh enough).
  const now = Date.now()

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

      <div className="msgs" ref={msgsRef}>
        {messages.length === 0 && <p className="muted small">No messages yet. Say hello.</p>}
        {messages.map((m, i) => {
          const prev = messages[i - 1]
          const next = messages[i + 1]
          const showDay = !prev || !sameDay(prev.ts, m.ts)
          // Show the time only at the END of a run of same-sender messages sent within
          // GROUP_MS of each other (the newest message therefore always shows a time).
          const showTime = !next || next.dir !== m.dir || next.ts - m.ts > GROUP_MS
          return (
            <Fragment key={m.id}>
              {showDay && (
                <div className="day-sep">
                  <span>{formatDaySeparator(m.ts, now)}</span>
                </div>
              )}
              <div className={`msg msg-${m.dir}`}>
                <div className="msg-row">
                  <span className={`bubble${m.failed ? ' bubble-failed' : ''}${m.ephemeral ? ' bubble-ephemeral' : ''}`}>
                    {m.text}
                  </span>
                  {/* Delete-for-everyone (P10d) is only meaningful for a persisted
                      message; an ephemeral one was never saved on either device, so
                      the affordance is hidden for it. */}
                  {m.dir === 'out' && !m.ephemeral && (
                    <div className="msg-actions">
                      <button
                        className="icon-btn msg-actions-btn"
                        title="message options"
                        aria-label="message options"
                        onClick={(e) => {
                          e.stopPropagation()
                          setMenuFor((cur) => (cur === m.id ? null : m.id))
                        }}
                      >
                        ⋯
                      </button>
                      {menuFor === m.id && (
                        <div className="msg-menu" onClick={(e) => e.stopPropagation()}>
                          <button
                            className="danger small"
                            onClick={() => {
                              setMenuFor(null)
                              onDelete(m.id, m.failed)
                            }}
                          >
                            {m.failed ? 'Delete' : 'Delete for everyone'}
                          </button>
                          {!m.failed && (
                            <span className="tiny muted msg-menu-note">Asks their device to remove it too. Not guaranteed.</span>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
                {(showTime || m.ephemeral || m.failed) && (
                  <span className="msg-meta tiny muted" title={formatFull(m.ts, timeFmt)}>
                    {showTime && formatTime(m.ts, timeFmt)}
                    {m.ephemeral && <span className="ephemeral-mark">{showTime ? ' · ' : ''}session-only, not saved</span>}
                    {m.failed && <span className="error">{showTime || m.ephemeral ? ' · ' : ''}not sent</span>}
                  </span>
                )}
              </div>
            </Fragment>
          )
        })}
        <div ref={endRef} />
      </div>

      {/* Compose. When session-only is armed the whole bar restyles, the placeholder
          and send label change, and every sent bubble carries a "session-only" mark -
          four redundant signals so the armed mode is unmissable (a wrong-mode send is
          the sharp footgun, DESIGN 8.7). */}
      <div className={`compose${sessionOnly ? ' compose-ephemeral' : ''}`}>
        <button
          type="button"
          className={`session-toggle${sessionOnly ? ' on' : ''}`}
          aria-pressed={sessionOnly}
          title="Session-only: shown live but not saved to history on either device, and cleared when you reload or lock. The other person can still screenshot or copy it, and a modified app could keep it. Off-the-record courtesy, not a guarantee."
          onClick={() => setSessionOnly((v) => !v)}
        >
          session-only{sessionOnly ? ' ✓' : ''}
        </button>
        <textarea
          ref={composerRef}
          className="compose-input"
          value={draft}
          rows={1}
          placeholder={sessionOnly ? 'session-only message' : 'message'}
          onChange={(e) => setDraft(e.target.value)}
          onFocus={() => window.setTimeout(scrollToBottom, 300)}
          onKeyDown={(e) => {
            // Physical keyboard: Enter sends, Shift+Enter is a newline. Touch: Enter
            // is a newline and sending is an explicit Send tap.
            if (e.key === 'Enter' && !e.shiftKey && !isTouchDevice()) {
              e.preventDefault()
              submit()
            }
          }}
        />
        <button className="primary" disabled={!draft.trim()} onClick={submit}>
          {sessionOnly ? 'send once' : 'send'}
        </button>
      </div>
    </div>
  )
}
