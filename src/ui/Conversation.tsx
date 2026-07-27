// A single conversation: the message log plus a compose box. Message bodies are
// rendered as TEXT (React escapes by default; never innerHTML), per DESIGN 8.4.

import { Fragment, useEffect, useRef, useState } from 'react'
import type { TrustLevel } from '../trust/contactStore'
import { EphemeralIcon } from './icons'
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

// The delivery indicator, shown on your own messages only.
//
// Deliberately modest, because both states are the RELAY'S word (DESIGN 8.8), not
// a signed statement by the other device: "sent" means their inbox stored it,
// "delivered" means their device picked it up. Neither says anyone read it, and a
// dishonest relay can withhold or fake either. So the tooltips say what actually
// happened, and an unknown state renders NOTHING rather than guessing.
//
// Only the last outbound message in a run carries it, next to the timestamp,
// matching how the rest of this log stays quiet.
function DeliveryMark({ status, failed }: { status: 'sent' | 'delivered' | undefined; failed: boolean | undefined }) {
  if (failed) return null // "not sent" already says it, louder
  if (status === 'delivered') {
    return (
      <span
        className="delivery delivered"
        title="The relay says their device picked this up. That is the relay's word, not theirs, and it does not mean anyone has read it."
      >
        ✓✓
      </span>
    )
  }
  if (status === 'sent') {
    return (
      <span
        className="delivery sent"
        title="The relay says it stored this for them. It has not reported that their device picked it up, which is not the same as knowing it has not."
      >
        ✓
      </span>
    )
  }
  // Unknown: render NOTHING. An absent status is not evidence of anything, and it
  // covers cases that were plainly delivered: every message stored before this
  // feature existed (nothing back-fills those rows) and every session-only message
  // (which has no row to stamp at all). A "still waiting to be sent" dot on those
  // would be an affirmative claim the app cannot support, which DESIGN 8.8 forbids
  // in as many words. A genuinely queued message simply carries no mark until the
  // relay acks it.
  return null
}

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
  /** Remove the saved messages, keeping the contact and its verification. */
  onClearMessages: () => void
  /** Remove everything this device holds for this peer. */
  onDeleteConversation: () => void
  /** Relay connection state. Shown here only when it is BAD: on a phone the global
   *  topbar steps aside for the chat, and "we are not connected" is the state worth
   *  interrupting for. A permanent green dot would just be decoration. */
  connected: boolean
  /** Narrow-screen navigation: return to the conversation list. */
  onBack?: () => void
}

export function Conversation({
  peer,
  name,
  messages,
  trust,
  connected,
  onSend,
  onVerify,
  onRename,
  onDelete,
  onClearMessages,
  onDeleteConversation,
  onBack,
}: Props) {
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
  // Whether the header shows the peer's full user id or a truncated one.
  const [idOpen, setIdOpen] = useState(false)
  // The chat menu, and which destructive action is awaiting confirmation.
  const [chatMenu, setChatMenu] = useState(false)
  const [confirmWipe, setConfirmWipe] = useState<'clear' | 'delete' | null>(null)
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
    const full = el.scrollHeight
    const h = Math.min(full, COMPOSE_MAX_PX)
    el.style.height = `${h}px`
    el.style.minHeight = `${h}px`
    // Only scroll once the box has actually hit its cap. Leaving overflow on at
    // every height renders a permanent scrollbar (with arrows on Windows) inside a
    // one-line field, which is the sort of stray chrome that makes an app look
    // unfinished.
    el.style.overflowY = full > COMPOSE_MAX_PX ? 'auto' : 'hidden'
    if (wasNearBottom) scrollToBottom()
  }, [draft])

  useEffect(() => {
    if (!chatMenu) return
    const close = () => setChatMenu(false)
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setChatMenu(false)
    document.addEventListener('click', close)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('click', close)
      document.removeEventListener('keydown', onKey)
    }
  }, [chatMenu])

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
  /** How to refer to this person in prose. */
  const who = name.trim() || shortId

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
            {/* The real device id stays REACHABLE so verification is always by
                identity, never by the (cosmetic, self-set) name. It used to wrap to
                two monospace lines and dominate the header; it is now one truncated
                line that expands in place on tap. Shortened for reading, never for
                comparing: the full value is one tap away and the verify screen shows
                it in full alongside the safety number. */}
            <button
              type="button"
              className="convo-id"
              aria-expanded={idOpen}
              title={idOpen ? 'hide the full user id' : 'show the full user id'}
              onClick={() => setIdOpen((v) => !v)}
            >
              <span className={`mono tiny muted${idOpen ? ' break' : ' convo-id-short'}`}>{peer}</span>
            </button>
          </div>
        </div>
        <div className="convo-head-right">
          {!connected && (
            <span className="offline-chip" title="Not connected to the relay. Messages you send stay queued on this device and go out when the connection returns.">
              offline
            </span>
          )}
          {trust && <TrustBadge trust={trust} />}
          <button className="ghost small" onClick={onVerify}>
            {trust === 'verified' ? 'verified ✓' : 'verify'}
          </button>
          <div className="chat-menu-wrap">
            <button
              className="icon-btn"
              title="chat options"
              aria-label="chat options"
              onClick={(e) => {
                e.stopPropagation()
                setChatMenu((v) => !v)
              }}
            >
              ⋯
            </button>
            {chatMenu && (
              <div className="chat-menu" onClick={(e) => e.stopPropagation()}>
                <button
                  className="ghost small block"
                  onClick={() => {
                    setChatMenu(false)
                    setConfirmWipe('clear')
                  }}
                >
                  Clear messages
                </button>
                <button
                  className="danger small block"
                  onClick={() => {
                    setChatMenu(false)
                    setConfirmWipe('delete')
                  }}
                >
                  Delete from this device
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Destructive actions carry their limits IN the confirmation, not in a help
          page. The one people get wrong is blocking: Nightjar has none, so a delete
          that stayed silent about it would be read as one. */}
      {confirmWipe && (
        <div className={`wipe-confirm ${confirmWipe === 'delete' ? 'wipe-delete' : ''}`} role="alertdialog">
          {confirmWipe === 'clear' ? (
            <>
              <p className="small">
                <strong>Clear the saved messages in this chat?</strong> They are removed from this device only.{' '}
                {who} is not told, keeps their copy, and this does not affect anything already on its way to them.
              </p>
              <p className="tiny muted">Your contact and any verification stay exactly as they are.</p>
            </>
          ) : (
            <>
              <p className="small">
                <strong>Delete this conversation from this device?</strong> This removes the saved messages, anything
                still waiting to send to them, the contact, and the name you gave them.
              </p>
              <p className="tiny">
                <strong>This does not block them.</strong> Nightjar has no block yet. {who} can still message you, and
                if they do the conversation comes back as a new contact with no name and no verification. Your device
                keeps the encryption session for exactly that reason, so this does not erase every trace of them from
                it.
                {trust === 'verified' && ' You verified this contact in person, and that is discarded.'}
              </p>
              <p className="tiny muted">
                {who} is not told. They keep their copy, and anything already handed to the relay still reaches them.
              </p>
            </>
          )}
          <div className="row">
            <button
              className="danger"
              onClick={() => {
                const mode = confirmWipe
                setConfirmWipe(null)
                if (mode === 'clear') onClearMessages()
                else onDeleteConversation()
              }}
            >
              {confirmWipe === 'clear' ? 'clear messages' : 'delete from this device'}
            </button>
            <button className="ghost" onClick={() => setConfirmWipe(null)}>
              cancel
            </button>
          </div>
        </div>
      )}

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
                    {/* Only on the last message of an outbound run: the one whose
                        state the sender is actually watching. */}
                    {m.dir === 'out' && showTime && <DeliveryMark status={m.status} failed={m.failed} />}
                  </span>
                )}
              </div>
            </Fragment>
          )
        })}
        <div ref={endRef} />
      </div>

      {/* Compose. When session-only is armed the whole bar restyles, a labelled strip
          appears above it, the placeholder and send label change, and every sent
          bubble carries a "session-only" mark: redundant signals so the armed mode is
          unmissable (a wrong-mode send is the sharp footgun, DESIGN 8.7).

          The toggle is a compact control rather than a wide text chip because the chip
          was taking about a third of the compose row on a phone, squeezing the message
          field. The signal that chip carried is not lost, it moved into the strip
          below, which is bigger and states the consequence in words rather than
          leaving the reader to infer it from a label. */}
      {sessionOnly && (
        <div className="ephemeral-strip" role="status">
          <span className="ephemeral-strip-dot" aria-hidden="true" />
          <span>
            <strong>Session-only.</strong> This message is not saved on either device, and it is gone when you reload
            or lock. They can still screenshot it.
          </span>
        </div>
      )}
      <div className={`compose${sessionOnly ? ' compose-ephemeral' : ''}`}>
        <button
          type="button"
          className={`session-toggle${sessionOnly ? ' on' : ''}`}
          aria-pressed={sessionOnly}
          aria-label={sessionOnly ? 'Session-only is on. Turn it off.' : 'Send session-only (not saved)'}
          title="Session-only: shown live but not saved to history on either device, and cleared when you reload or lock. The other person can still screenshot or copy it, and a modified app could keep it. Off-the-record courtesy, not a guarantee."
          onClick={() => setSessionOnly((v) => !v)}
        >
          <EphemeralIcon />
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
