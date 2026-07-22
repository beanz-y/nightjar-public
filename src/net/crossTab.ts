// Same-origin cross-tab render sync (P10e follow-up). Fans a RENDER-ONLY event to
// the other open tabs of the SAME user so a message shows live in every tab, not
// just the one that won the processInbound Web Lock. This fixes the multi-tab
// session-only miss (an ephemeral message reaches only the lock-winning tab and is
// never persisted to recover) and, as a standalone win, gives normal messages live
// multi-tab sync (today a second tab only catches up on reload).
//
// It is STRICTLY a render signal. Receivers mutate their in-RAM conversation view
// only; they NEVER re-run the ratchet, re-persist, or re-ack. Crypto stays
// single-writer under the existing Web Locks, so this changes no security or
// storage invariant. Nothing leaves the browser: BroadcastChannel is same-origin,
// so DESIGN 9 (relay-visible metadata) is unchanged. An XSS that already owns the
// page (DESIGN 8.4) could read this channel, but that is strictly within what such
// an attacker can already do (it already holds the LDK, the React state, and IDB).
//
// The channel is opened only while unlocked and closed on lock/teardown, so a
// locked tab (which holds no plaintext) never receives one.

/** A message shaped exactly like the UI's `Message`, carried across tabs so a
 *  sibling renders an identical bubble (same id => idempotent dedup on apply). */
export interface RenderMsg {
  id: string
  dir: 'in' | 'out'
  text: string
  ts: number
  ephemeral?: boolean
  failed?: boolean
}

/** Append a bubble to a conversation. */
export interface CrossTabAppend {
  kind: 'append'
  peer: string
  msg: RenderMsg
}

/** Remove a bubble (delete-for-everyone, either direction). */
export interface CrossTabDelete {
  kind: 'delete'
  peer: string
  id: string
}

/** Mark a bubble as failed-to-send (matched by id across conversations, mirroring
 *  the local onSendFailed which does not carry the peer). */
export interface CrossTabFailed {
  kind: 'failed'
  id: string
}

export type CrossTabEvent = CrossTabAppend | CrossTabDelete | CrossTabFailed

export interface CrossTab {
  /** Broadcast a render event to sibling tabs (no-op if unsupported/closed). */
  post(ev: CrossTabEvent): void
  /** Close the channel. Called on lock / teardown so a locked tab holds none. */
  close(): void
}

/** The one same-origin channel name for render events. */
export const CROSS_TAB_CHANNEL = 'nightjar-render'

function isEvent(v: unknown): v is CrossTabEvent {
  if (!v || typeof v !== 'object') return false
  const k = (v as { kind?: unknown }).kind
  return k === 'append' || k === 'delete' || k === 'failed'
}

/**
 * Create a cross-tab render channel. `onEvent` fires for events posted by OTHER
 * tabs (BroadcastChannel never echoes a tab's own posts back to it). When
 * BroadcastChannel is unavailable the returned object is an inert no-op, so callers
 * need no feature checks and single-tab behaviour is unchanged.
 */
export function createCrossTab(onEvent: (ev: CrossTabEvent) => void): CrossTab {
  if (typeof BroadcastChannel === 'undefined') {
    return { post: () => {}, close: () => {} }
  }
  const ch = new BroadcastChannel(CROSS_TAB_CHANNEL)
  ch.onmessage = (e: MessageEvent) => {
    if (isEvent(e.data)) onEvent(e.data)
  }
  return {
    post: (ev) => {
      try {
        ch.postMessage(ev)
      } catch {
        /* channel closing or serialization edge; a dropped render sync is benign */
      }
    },
    close: () => {
      try {
        ch.close()
      } catch {
        /* already closed */
      }
    },
  }
}
