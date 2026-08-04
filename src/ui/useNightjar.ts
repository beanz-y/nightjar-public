// The app's single source of truth: owns the app-lock lifecycle AND the
// NightjarClient lifecycle. The mandatory app-lock (P10c) gates everything: the
// client is NOT constructed or connected until the Local Data Key is in RAM (via
// enrollment on first run, or unlock on return), so nothing is decrypted, sent,
// or persisted while locked. Locking (idle timeout / "lock now") tears the client
// down and clears the decrypted history from memory.

import { useCallback, useEffect, useRef, useState } from 'react'
import { MOVE_MAX_PAYLOAD_BYTES, PRESENCE_HEARTBEAT_MS } from '../crypto/constants'
import { AppLockAuthError } from '../crypto/appLock'
import type { Identity } from '../crypto/identity'
import { MoveBlockedError, NightjarClient, type StoredMessage } from '../net/client'
import type { DeliveryStatus } from '../storage/historyStore'
import { CROSS_TAB_CHANNEL, type CrossTab, type CrossTabEvent, createCrossTab } from '../net/crossTab'
import { getRelayOrigin } from '../platform'
import {
  clearNotifications,
  isIos,
  isStandalone,
  notifyPermission,
  notifyPref,
  pushSupported,
  requestNotifyPermission,
  subscribePush,
  unsubscribePush,
} from '../platform/webpush'
import { biometricAvailable, enrollBiometric, unlockBiometric } from '../platform/webauthn'
import { openBackup, parseBackupHeader, sealBackup } from '../crypto/backup'
import { type LinkPayload, openLink } from '../crypto/link'
import { ed25519Public } from '../crypto/primitives'
import { newHistoryCode, newLinkCode, parseHistoryCode, parseLinkCode } from '../trust/linkCode'
import { clearAccountKey, loadAccountKey, saveAccountKey } from '../storage/accountKeyStore'
import { type OpenedMove, encodeMovePayload, openMove, parseMoveHeader, sealMove } from '../crypto/move'
import { bytesToHex } from '@noble/hashes/utils.js'
import { newMsgId } from '../crypto/message'
import { createBackupKdf } from '../platform/backupKdf'
import { AppLockStore, type EnrollMethod } from '../storage/appLockStore'
import { IdbKeyStore, type KeyStore } from '../storage/keystore'
import { HistoryStore } from '../storage/historyStore'
import { IDENTITY_KEY, bootstrapIdentity } from '../storage/identityStore'
import { IdbSessionStore } from '../storage/sessionStore'
import { SessionSealer } from '../storage/sessionSeal'
import { type Lock, createLock } from '../storage/lock'
import { type Sentinel, createSentinel, requestPersistentStorage } from '../storage/persist'
import { PREKEYS_KEY, PrekeyStore } from '../storage/prekeyStore'
import { type BackupPayload } from '../crypto/backup'
import {
  RESTORE_PENDING_KEY,
  clearPendingRestore,
  pendingRestore,
  stageLink,
  stageMove,
  stageRestoreEnrolled,
} from '../storage/restore'
import { type Contact, ContactStore } from '../trust/contactStore'
import {
  type InviteArtifact,
  decodeInviteArtifact,
  encodeInviteArtifact,
  inviteUrl,
} from '../trust/inviteArtifact'

export type Phase = 'loading' | 'evicted' | 'enroll' | 'locked' | 'onboarding' | 'ready' | 'error'

/** 'waiting' = a code is on screen and a transfer is being listened for;
 *  'joining' = one arrived and opened, and this device is joining the account. */
export type LinkState = 'idle' | 'waiting' | 'joining' | 'done'

/** Lock the app after this long hidden (idle). */
const IDLE_LOCK_MS = 5 * 60 * 1000

/** Left behind when erasing this device could not remove everything. It has to
 *  outlive the reload that erasing ends with, which is why it is not React state:
 *  the whole failure mode being reported is a device that comes back looking
 *  erased while it still holds what would not delete. */
const ERASE_INCOMPLETE_KEY = 'nightjar.eraseIncomplete'

export interface NotifyState {
  supported: boolean
  permission: NotificationPermission
  enabled: boolean
  available: boolean
  needsInstall: boolean
}

export interface Message {
  id: string
  dir: 'in' | 'out'
  text: string
  ts: number
  failed?: boolean
  /** Session-only (P10e): shown live but never written to history on either
   *  device; rendered distinctly and cleared on reload/lock. */
  ephemeral?: boolean
  /** Outbound only: how far it got, as far as the RELAY has told us. Absent means
   *  unknown (still queued, or a marker that never landed), which renders as
   *  nothing rather than as a claim. */
  status?: DeliveryStatus
}

export interface MintedInvite {
  token: string
  url: string
  inviter: string
}

interface Live {
  client: NightjarClient
  identity: Identity
}

interface Stores {
  keys: KeyStore
  lock: Lock
  sentinel: Sentinel
  sessions: IdbSessionStore
  contacts: ContactStore
  history: HistoryStore
  appLock: AppLockStore
}

const appOrigin = () => globalThis.location?.origin || getRelayOrigin()

function mergeHistory(
  hist: Record<string, StoredMessage[]>,
  prev: Record<string, Message[]>,
): Record<string, Message[]> {
  const out: Record<string, Message[]> = {}
  for (const [peer, msgs] of Object.entries(hist)) {
    out[peer] = msgs.map((m) => {
      const base: Message = { id: m.id, dir: m.dir, text: m.text, ts: m.ts }
      if (m.failed) base.failed = true
      if (m.status) base.status = m.status
      return base
    })
  }
  for (const [peer, msgs] of Object.entries(prev)) {
    if (!out[peer]) {
      out[peer] = msgs
      continue
    }
    const have = new Set(out[peer].map((m) => m.id))
    const extra = msgs.filter((m) => !have.has(m.id))
    if (extra.length) out[peer] = [...out[peer], ...extra].sort((a, b) => a.ts - b.ts)
  }
  return out
}

/** The longest message that can be sent, counted the way JavaScript counts a string
 *  (UTF-16 units), which is what the send guard below compares. Exported so the
 *  composer can warn against the SAME number it will be judged by: a counter that
 *  disagreed with the check would be worse than no counter.
 *
 *  It is deliberately generous. The relay refuses a ciphertext over 64 KiB, and this
 *  cap keeps a normal message about half that even in a three-byte-per-character
 *  script, so `too_large` is something a person never meets. */
export const MAX_MESSAGE_CHARS = 8000
const USER_ID_RE = /^[a-z2-7]{52}$/

function computeNotify(pushKey: string | null): NotifyState {
  const supported = pushSupported()
  const iosNotInstalled = isIos() && !isStandalone()
  return {
    supported,
    permission: notifyPermission(),
    enabled: notifyPref(),
    available: supported && !!pushKey && !iosNotInstalled,
    needsInstall: iosNotInstalled,
  }
}

/** Wording for history rows that would not open during a clear or a delete.
 *
 *  The count is DATABASE-WIDE and cannot be otherwise: the only thing naming a row
 *  is sealed inside the part that will not open, so an unreadable row cannot be
 *  attributed to any conversation, including the one being deleted. Saying "N
 *  messages could not be removed" inside a per-chat notice would read as a claim
 *  about that chat, which is more than we know. */
function unreadableNote(n: number): string {
  const rows = `${n} stored ${n === 1 ? 'message' : 'messages'}`
  const it = n === 1 ? 'it' : 'they'
  const was = n === 1 ? 'was' : 'were'
  return `${rows} in your saved history could not be read at all, so ${it} could not be matched to any conversation and ${was} left in place.`
}

export function useNightjar() {
  const [phase, setPhase] = useState<Phase>('loading')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [securityNotices, setSecurityNotices] = useState<string[]>([])
  const [identity, setIdentity] = useState<Identity | null>(null)
  /** This account's public signing key, which is what a safety number covers.
   *
   *  Kept separate from `identity` deliberately. `identity` is the DEVICE, and on
   *  a linked device its key is NOT the account key, so a screen that compares
   *  identities out of band has to be handed this one: a contact record always
   *  holds the peer's ACCOUNT key, so comparing a device key against it fails on
   *  every contact and reads as an attack. On a first device the two are the same
   *  key and nobody's digits move. */
  const [accountIkSigPub, setAccountIkSigPub] = useState<Uint8Array | null>(null)
  const [connected, setConnected] = useState(false)
  const [registered, setRegistered] = useState(false)
  const [contacts, setContacts] = useState<Contact[]>([])
  const [aliases, setAliases] = useState<Record<string, string>>({})
  const [conversations, setConversations] = useState<Record<string, Message[]>>({})
  const [prefillInvite, setPrefillInvite] = useState<string>('')
  const [notify, setNotify] = useState<NotifyState>(() => computeNotify(null))
  const [restoreBusy, setRestoreBusy] = useState(false)
  const [restoreError, setRestoreError] = useState<string | null>(null)
  const [storagePersisted, setStoragePersisted] = useState<boolean | null>(null)
  const [lockMethods, setLockMethods] = useState<Array<'pass' | 'pin' | 'bio'>>([])
  const [bioAvailable, setBioAvailable] = useState(false)
  const [restorePending, setRestorePending] = useState(false)
  /** Where this device is in the ceremony of joining an account (Sesame). */
  const [linkState, setLinkState] = useState<LinkState>('idle')
  /** Import progress while saved messages are being written, so a long one does
   *  not look like a hang. */
  const [historyProgress, setHistoryProgress] = useState<{ done: number; total: number } | null>(null)
  /** The peer of the most recent FULL delete, local or from a sibling tab. The
   *  conversation pane keeps its own `selected` state, which no cross-tab event can
   *  reach, so without this a sibling tab keeps the deleted chat open and typing in
   *  it re-creates the contact and a session. Carries a nonce so deleting the same
   *  peer twice still fires. */
  const [removedPeer, setRemovedPeer] = useState<{ peer: string; n: number } | null>(null)
  const removedSeqRef = useRef(0)
  const noteRemoved = useCallback((peer: string) => {
    setRemovedPeer({ peer, n: ++removedSeqRef.current })
  }, [])

  const liveRef = useRef<Live | null>(null)
  const storesRef = useRef<Stores | null>(null)
  const idRef = useRef<Identity | null>(null)
  const mountedRef = useRef(true)
  const restoreFixupRef = useRef<Promise<void> | null>(null)
  const restorePayloadRef = useRef<BackupPayload | null>(null)
  /** An opened MOVE file awaiting its staging step (Phase D). Mutually exclusive
   *  with restorePayloadRef; whichever is set, the next enroll/unlock stages it. */
  const movePayloadRef = useRef<OpenedMove | null>(null)
  const drainingMoveRef = useRef(false)
  const [moveProgress, setMoveProgress] = useState<{ done: number; total: number } | null>(null)
  const [moveExported, setMoveExported] = useState(false)
  const pushKeyRef = useRef<string | null>(null)
  /** The single-use secret from the code this device is currently showing (Sesame).
   *  RAM only, deliberately: it opens a payload carrying the account key, so a
   *  reload means showing a fresh code rather than leaving it on disk. */
  const linkSecretRef = useRef<Uint8Array | null>(null)
  const linkStopRef = useRef<(() => void) | null>(null)
  /** The single-use secret from the saved-messages code this device is showing.
   *  RAM only, for the same reason the linking one is: it opens everything this
   *  account has ever kept, and it is single-use anyway. */
  const historySecretRef = useRef<Uint8Array | null>(null)
  const teardownRef = useRef<(() => void) | null>(null)
  const lockNowRef = useRef<() => void>(() => {})
  const contactsGenRef = useRef(0)
  const crossTabRef = useRef<CrossTab | null>(null)

  const refreshNotify = useCallback(() => setNotify(computeNotify(pushKeyRef.current)), [])

  // Refresh the contact list, guarded so a slower earlier read can never clobber a
  // fresher later one: several async refreshes race at connect (onConnection, the
  // initial activate load, and the mutual-invite onContactsChanged), and a stale
  // snapshot landing last would briefly hide a just-added joiner. The newest read
  // (highest generation) always wins.
  const listContacts = useCallback(async () => {
    const live = liveRef.current
    if (!live) return
    const gen = ++contactsGenRef.current
    const list = await live.client.listContacts()
    if (mountedRef.current && gen === contactsGenRef.current) setContacts(list)
  }, [])

  const appendMessage = useCallback((peer: string, m: Message) => {
    setConversations((prev) => {
      const cur = prev[peer] ?? []
      if (cur.some((x) => x.id === m.id)) return prev
      return { ...prev, [peer]: [...cur, m] }
    })
  }, [])

  // Remove a bubble from a conversation (delete-for-everyone, either direction).
  const removeBubble = useCallback((peer: string, id: string) => {
    setConversations((prev) => {
      const cur = prev[peer]
      // Do NOT create the key for a peer we hold nothing for: this also runs as a
      // cross-tab and inbound receiver, and writing an empty array would rebuild a
      // thread row for a conversation the user just deleted.
      if (!cur) return prev
      return { ...prev, [peer]: cur.filter((m) => m.id !== id) }
    })
  }, [])

  /** Drop a whole conversation from the in-RAM view. */
  const dropConversation = useCallback((peer: string) => {
    setConversations((prev) => {
      if (!(peer in prev)) return prev
      const next = { ...prev }
      delete next[peer]
      return next
    })
  }, [])

  // Mark a bubble failed by id, matched across conversations (a send-failure id is
  // unique, so scanning all peers is equivalent to knowing the peer).
  const markFailed = useCallback((id: string) => {
    setConversations((prev) => {
      const next: Record<string, Message[]> = {}
      for (const [p, msgs] of Object.entries(prev)) next[p] = msgs.map((m) => (m.id === id ? { ...m, failed: true } : m))
      return next
    })
  }, [])

  // Move a bubble's delivery status forward. Monotonic here too, mirroring the
  // client: a late 'sent' must never walk a 'delivered' bubble backwards, and a
  // failed bubble is never relabelled (the failure is the more important fact).
  const markStatus = useCallback((peer: string, id: string, status: DeliveryStatus) => {
    setConversations((prev) => {
      const cur = prev[peer]
      if (!cur) return prev
      let changed = false
      const next = cur.map((m) => {
        if (m.id !== id || m.failed) return m
        if (m.status === status || m.status === 'delivered') return m
        changed = true
        return { ...m, status }
      })
      return changed ? { ...prev, [peer]: next } : prev
    })
  }, [])

  // Broadcast a RENDER-ONLY event to sibling tabs (no-op until a channel is open in
  // activate()). Receivers apply it to their in-RAM view only; the crypto/storage
  // write already happened once, in the tab that produced the event.
  const broadcast = useCallback((ev: CrossTabEvent) => crossTabRef.current?.post(ev), [])

  const completeRestoreIfPending = useCallback((client: NightjarClient, keys: KeyStore): Promise<void> => {
    if (restoreFixupRef.current) return restoreFixupRef.current
    restoreFixupRef.current = (async () => {
      try {
        if (!client.isRegistered || !(await pendingRestore(keys))) return
        await client.reregister()
        await clearPendingRestore(keys)
        setNotice('restore complete: fresh prekeys are published. Send each contact a message to re-establish your conversations.')
      } catch {
        setNotice('restore is not fully finished (fresh prekeys not yet published); it will retry automatically')
      } finally {
        restoreFixupRef.current = null
      }
    })()
    return restoreFixupRef.current
  }, [])

  // Drain the post-move session-refresh list (Phase D): one silent fresh-session
  // ping per imported contact, so peers stop sending on the dead pre-move
  // sessions (which this device would poison-drop while the relay reported them
  // delivered). Runs only AFTER the post-move re-registration finished (fresh
  // prekeys published, this user's stale fetcher vends cleared server-side).
  // Durable progress: the list is rewritten after every peer, so a mid-drain
  // crash resumes where it stopped. Permanent failures (peer unregistered, key
  // conflict) drop the peer; transient ones keep the rest for the next connect.
  const drainMoveRefresh = useCallback(async (client: NightjarClient, keys: KeyStore, contacts: ContactStore): Promise<void> => {
    if (drainingMoveRef.current) return
    drainingMoveRef.current = true
    try {
      let list = await contacts.getMoveRefresh()
      if (list.length === 0) return
      if (await pendingRestore(keys)) return // reregister not done; retried next connect
      while (list.length > 0) {
        const peer = list[0]
        try {
          await client.sendSessionRefresh(peer)
        } catch (e) {
          const msg = String(e instanceof Error ? e.message : e)
          const permanent =
            (e instanceof Error && e.name === 'KeyConflictError') ||
            msg.includes('not registered') ||
            msg.includes('does not match')
          if (!permanent) return // transient: keep the remainder for the next connect
        }
        list = list.slice(1)
        await contacts.setMoveRefresh(list) // empty deletes the blob
      }
    } catch {
      /* best-effort: retried on the next connect */
    } finally {
      drainingMoveRef.current = false
    }
  }, [])

  // Tear down the live client + its foreground handlers (idle-lock / "lock now" /
  // unmount). Does NOT touch the app-lock key material.
  const teardownLive = useCallback(() => {
    teardownRef.current?.()
    teardownRef.current = null
    // A ceremony in progress dies with the client that was listening for it. The
    // secret goes too: it is single-use, and the next attempt shows a fresh code.
    linkStopRef.current?.()
    linkStopRef.current = null
    linkSecretRef.current = null
    // Close the cross-tab channel BEFORE clearing the client: a locked/torn-down tab
    // must hold no plaintext and must stop receiving sibling render events.
    crossTabRef.current?.close()
    crossTabRef.current = null
    liveRef.current?.client.close()
    liveRef.current = null
  }, [])

  // Build + connect the client. Called ONLY after the app-lock is unlocked (LDK in
  // RAM), so the socket is provably never open while locked (red-team #1/#5).
  const activate = useCallback(async () => {
    const stores = storesRef.current
    const id = idRef.current
    if (!stores || !id) return
    try {
      // Sealing (P11) is wired BEFORE anything can read or write a session row, and
      // the one-time migration runs BEFORE the client exists, so there is never a
      // concurrent writer and never a half-configured store. Both need the LDK,
      // which is why they live here and not in the pre-unlock boot effect.
      stores.sessions.useSealer(new SessionSealer(stores.appLock))
      await stores.sessions.migrateToSealed()
      const prekeys = new PrekeyStore(stores.keys, stores.lock, stores.appLock)
      // The account key, on a device that was linked into an existing account
      // (Sesame). Null on a first device, which IS its own account and derives it.
      // Deliberately not caught: loadAccountKey fails CLOSED, because "no account
      // key" and "an account key this device cannot read" mean opposite things, and
      // starting up as an account of one when the truth is the second would have
      // this device signing device lists that contradict its own account.
      const accountKey = await loadAccountKey(stores.keys, stores.appLock)
      const client = new NightjarClient(
        id,
        stores.sessions,
        prekeys,
        stores.contacts,
        stores.lock,
        {
          onMessage: (from, msg) => {
            const m: Message = { id: msg.id, dir: 'in', text: msg.text, ts: msg.ts, ...(msg.ephemeral ? { ephemeral: true } : {}) }
            appendMessage(from, m)
            broadcast({ kind: 'append', peer: from, msg: m })
            void listContacts().catch(() => {})
          },
          onSyncedSent: (accountId, msg) => {
            // Something this account sent from another of its devices. It is OUR
            // message in THAT conversation, so it renders as an outbound bubble
            // rather than as a message from the device that relayed it.
            const m: Message = { id: msg.id, dir: 'out', text: msg.text, ts: msg.ts }
            appendMessage(accountId, m)
            broadcast({ kind: 'append', peer: accountId, msg: m })
          },
          onDelete: (from, id) => {
            // Delete-for-everyone from a peer (P10d): drop the bubble. The stored
            // row was already removed atomically inside the client.
            removeBubble(from, id)
            broadcast({ kind: 'delete', peer: from, id })
          },
          onError: (detail) => setNotice(detail),
          onSecurity: (detail) => setSecurityNotices((prev) => (prev.includes(detail) ? prev : [...prev, detail])),
          onSendFailed: (envId, reason) => {
            markFailed(envId)
            broadcast({ kind: 'failed', id: envId })
            setNotice(`a message could not be delivered (${reason})`)
          },
          onDelivery: (peer, id, status) => {
            markStatus(peer, id, status)
            broadcast({ kind: 'status', peer, id, status })
          },
          onUnreadableFrom: (peer) => {
            // A live contact's message was dropped as permanently unreadable: it
            // was encrypted for a session that did not ride a move. Runtime
            // honesty (Phase D): name them, so a message the relay told them was
            // delivered is not silently gone here.
            setNotice(
              `a message from ${peer.slice(0, 12)}… arrived that this device cannot read (it was sent to your old device) and has been given up on.`,
            )
          },
          onRetryRequested: (peer) => {
            // The automatic half of the same story (8.10): their device has been
            // asked to re-establish and send its recent messages again.
            setNotice(
              `a message from ${peer.slice(0, 12)}… could not be read on this device, so their device has been asked to send its recent messages again.`,
            )
          },
          onRetryExhausted: (peer) => {
            setNotice(
              `${peer.slice(0, 12)}… has been asked more than once to send messages this device cannot read, and nothing came back. Ask them to send it again themselves.`,
            )
          },
          onRetryHonored: (peer, count) => {
            // Never silent, by design: this is the only signal the user gets that
            // someone holding this contact's identity pulled recent messages (8.10).
            setNotice(
              count > 0
                ? `${peer.slice(0, 12)}… could not read some of your messages, so the last ${count} you sent them were sent again.`
                : `${peer.slice(0, 12)}… asked for recent messages to be sent again; there were none saved to send.`,
            )
          },
          onContactsChanged: () => {
            // A mutual-invite joiner was auto-learned (or deferred trust work landed)
            // after the connect-time refresh already ran; re-read so it appears now.
            if (mountedRef.current) void listContacts().catch(() => {})
          },
          onDevicesChanged: (accountId, change) => {
            // A contact's set of devices changed. This is a SECURITY notice, not a
            // status line, because an operator cannot cause it: a device list is
            // signed by the account key, so it is either a device that person
            // really linked or something already holding their account key, and
            // only they can tell which. Sticky, and never auto-dismissed.
            const mine = accountId === liveRef.current?.client.account.accountId
            const who = mine ? 'your account' : `${accountId.slice(0, 12)}…`
            const parts: string[] = []
            if (change.added.length > 0) parts.push(`added ${change.added.length} device(s)`)
            if (change.removed.length > 0) parts.push(`removed ${change.removed.length} device(s)`)
            // The first list ever seen for a CONTACT is worded as a fact rather
            // than as a change: for somebody just added it is not news that they
            // read on two devices, and calling that "added a device" would be the
            // kind of false alarm that teaches people to ignore this notice. Your
            // OWN account never gets that softening: a first list you did not
            // publish yourself is exactly what a stolen account key looks like.
            const detail =
              change.first && !mine
                ? `${who} reads on ${change.added.length + 1} devices. If you expected one, check with them in person before sending anything sensitive.`
                : `${who} ${parts.join(' and ')}. If that was not expected, check with them in person before sending anything sensitive.`
            setSecurityNotices((prev) => (prev.includes(detail) ? prev : [...prev, detail]))
          },
          onConnection: (up) => {
            if (!mountedRef.current) return
            setConnected(up)
            if (!up) return
            client.sendPresence(document.visibilityState === 'visible')
            if (client.pushKey && notifyPref() && notifyPermission() === 'granted') {
              void subscribePush(client.pushKey)
                .then((sub) => sub && client.subscribePush(sub))
                .catch(() => {})
            }
            void completeRestoreIfPending(client, stores.keys)
              .then(() => drainMoveRefresh(client, stores.keys, stores.contacts))
              // A rename interrupted part-way (a contact rotated their account key
              // and the device was closed mid-move) leaves that person split
              // across two ids. Finishing it belongs here with the rest of the
              // catch-up work a reconnecting device does, and it re-reads the
              // contact list afterwards so an open window stops showing both.
              .then(() => client.resumePendingRenames())
              .then(() => listContacts())
              .catch(() => {})
            setRegistered(client.isRegistered)
            void listContacts().catch(() => {})
            setPhase((prev) => (prev === 'error' ? (client.isRegistered ? 'ready' : 'onboarding') : prev))
          },
        },
        stores.history,
        accountKey ?? undefined,
      )
      liveRef.current = { client, identity: id }
      setIdentity(id)
      setAccountIkSigPub(client.account.accountKey.publicKey)

      // Open the cross-tab render channel now that we are unlocked. Sibling tabs of
      // this same user apply appends/deletes/failures to their in-RAM view ONLY (no
      // re-decrypt/persist/ack). Receivers call the bare mutators, never a *broadcast*
      // path, so a received event is never re-broadcast (no ping-pong).
      crossTabRef.current?.close()
      crossTabRef.current = createCrossTab((ev) => {
        if (!mountedRef.current) return
        if (ev.kind === 'append') appendMessage(ev.peer, ev.msg)
        else if (ev.kind === 'delete') removeBubble(ev.peer, ev.id)
        else if (ev.kind === 'status') markStatus(ev.peer, ev.id, ev.status)
        else if (ev.kind === 'lockReset') {
          // A sibling discarded the Local Data Key. Everything this tab would write
          // from here is sealed under a key that no longer opens anything, so stop
          // immediately rather than accumulating unreadable rows.
          lockNowRef.current?.()
        } else if (ev.kind === 'conversationRemoved') {
          dropConversation(ev.peer)
          if (!ev.keepThread) noteRemoved(ev.peer)
          // A full delete also removed the contact and the nickname, which this tab
          // still holds in state; without re-reading them the thread row would
          // linger here, empty, until something else happened to refresh it.
          if (!ev.keepThread) {
            void listContacts().catch(() => {})
            const live = liveRef.current
            if (live) void live.client.listAliases().then(setAliases).catch(() => {})
          }
        }
        else markFailed(ev.id)
      })

      const authed = await client.connect()
      if (!mountedRef.current) return
      setConnected(true)
      setRegistered(authed.registered)
      if (authed.registered) {
        await completeRestoreIfPending(client, stores.keys)
        void drainMoveRefresh(client, stores.keys, stores.contacts)
      }
      if (!mountedRef.current) return
      await listContacts()
      setAliases(await client.listAliases())
      try {
        const hist = await client.loadAllHistory()
        if (mountedRef.current) setConversations((prev) => mergeHistory(hist, prev))
      } catch {
        /* best-effort hydration */
      }
      setPhase(authed.registered ? 'ready' : 'onboarding')

      pushKeyRef.current = authed.pushKey
      refreshNotify()
      if (authed.pushKey && notifyPref() && notifyPermission() === 'granted') {
        void subscribePush(authed.pushKey)
          .then((sub) => sub && client.subscribePush(sub))
          .catch(() => {})
      }

      // Foreground presence + idle-lock. On hidden, arm an idle timer that locks;
      // on visible, cancel it, refresh presence, and reconnect (a backgrounded
      // socket often died). These handlers exist ONLY while a client is live.
      let idleTimer: number | null = null
      const beat = () => {
        if (document.visibilityState === 'visible') client.sendPresence(true)
      }
      const onVisibility = () => {
        const visible = document.visibilityState === 'visible'
        client.sendPresence(visible)
        if (visible) {
          if (idleTimer !== null) window.clearTimeout(idleTimer)
          idleTimer = null
          void clearNotifications()
          client.reconnectNow()
        } else {
          idleTimer = window.setTimeout(() => lockNowRef.current(), IDLE_LOCK_MS)
        }
      }
      const onOnline = () => client.reconnectNow()
      const heartbeat = window.setInterval(beat, PRESENCE_HEARTBEAT_MS)
      document.addEventListener('visibilitychange', onVisibility)
      window.addEventListener('online', onOnline)
      teardownRef.current = () => {
        window.clearInterval(heartbeat)
        if (idleTimer !== null) window.clearTimeout(idleTimer)
        document.removeEventListener('visibilitychange', onVisibility)
        window.removeEventListener('online', onOnline)
      }
      void clearNotifications()
    } catch (e) {
      if (!mountedRef.current) return
      setError(String(e instanceof Error ? e.message : e))
      setPhase('error')
    }
  }, [appendMessage, removeBubble, markFailed, broadcast, completeRestoreIfPending, drainMoveRefresh, refreshNotify])

  // Lock now: clear the LDK + decrypted history from RAM and tear down the socket.
  const lockNow = useCallback(() => {
    const stores = storesRef.current
    teardownLive()
    stores?.appLock.lockNow()
    setConversations({})
    setContacts([])
    setConnected(false)
    setNotice(null)
    setPhase('locked')
  }, [teardownLive])
  lockNowRef.current = lockNow

  useEffect(() => {
    mountedRef.current = true
    const hash = globalThis.location?.hash ?? ''
    const m = hash.match(/[#?&]i=([^#?&\s]+)/)
    if (m) {
      setPrefillInvite(decodeURIComponent(m[1]))
      try {
        history.replaceState(null, '', globalThis.location.pathname + globalThis.location.search)
      } catch {
        /* cosmetic only */
      }
    }

    // An erase that did not finish, reported on the far side of the reload it
    // ends with. Read and cleared here so it is said once, not on every start.
    try {
      const incomplete = localStorage.getItem(ERASE_INCOMPLETE_KEY)
      if (incomplete) {
        localStorage.removeItem(ERASE_INCOMPLETE_KEY)
        setNotice(
          `starting over on this device did not finish: ${incomplete} could not be removed, so some of what was here may still be. Try again from Settings, and if it keeps failing, clear this site's data in your browser settings.`,
        )
      }
    } catch {
      /* storage unavailable; nothing to report */
    }

    void (async () => {
      try {
        const persisted = await requestPersistentStorage()
        if (!mountedRef.current) return
        setStoragePersisted(persisted)
        const lock = createLock()
        const keys = new IdbKeyStore()
        const sentinel = createSentinel()
        const sessions = new IdbSessionStore()
        const appLock = new AppLockStore(keys, lock, createBackupKdf())
        const contactStore = new ContactStore(keys, lock, appLock)
        const historyStore = new HistoryStore(appLock)
        storesRef.current = { keys, lock, sentinel, sessions, contacts: contactStore, history: historyStore, appLock }
        void biometricAvailable().then((ok) => mountedRef.current && setBioAvailable(ok))

        const boot = await bootstrapIdentity(keys, sentinel, lock)
        if (!mountedRef.current) return
        if (boot.state === 'evicted-needs-restore' || !boot.identity) {
          setPhase('evicted')
          return
        }
        idRef.current = boot.identity
        // Gate on the app-lock: enroll on first run, unlock on return. The client
        // is built later, by activate(), only after the LDK is resident.
        const st = await appLock.status()
        if (!mountedRef.current) return
        if (st === 'unconfigured') {
          setPhase('enroll')
        } else {
          setLockMethods(await appLock.methods())
          setPhase('locked')
        }
      } catch (e) {
        if (!mountedRef.current) return
        setError(String(e instanceof Error ? e.message : e))
        setPhase('error')
      }
    })()

    return () => {
      mountedRef.current = false
      teardownLive()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // --- app-lock actions ----------------------------------------------------

  // Stage whichever opened file is pending (backup or move) now that the LDK is
  // resident (just enrolled, or just unlocked). Returns true when it staged and
  // reloaded; the caller must not continue to activate() in that case. The
  // one-shot cross-tab stop tells any sibling tab with a live client to tear
  // down FIRST: a single contact write from a still-live old tab after the
  // contacts stage would sit sealed beside the staged world and brick startup.
  const finishStagedRestore = useCallback(async (): Promise<boolean> => {
    const stores = storesRef.current
    if (!stores) return false
    const move = movePayloadRef.current
    const backup = restorePayloadRef.current
    if (!move && !backup) return false
    try {
      const ch = new BroadcastChannel(CROSS_TAB_CHANNEL)
      ch.postMessage({ kind: 'lockReset' })
      ch.close()
    } catch {
      /* unsupported: single-tab is then the only case, which is safe */
    }
    const deps = {
      keys: stores.keys,
      sessions: stores.sessions,
      contacts: stores.contacts,
      sentinel: stores.sentinel,
      lock: stores.lock,
    }
    if (move) {
      setMoveProgress({ done: 0, total: move.payload.messages.length })
      await stageMove(deps, stores.history, move.payload, (done, total) => {
        if (mountedRef.current) setMoveProgress({ done, total })
      })
      movePayloadRef.current = null
    } else if (backup) {
      await stageRestoreEnrolled(deps, backup)
      restorePayloadRef.current = null
    }
    globalThis.location.reload()
    return true
  }, [])

  // Enroll the mandatory app-lock (first run, or the final step of a restore).
  const enrollLock = useCallback(
    async (methods: EnrollMethod[]) => {
      const stores = storesRef.current
      if (!stores) return
      setNotice(null)
      try {
        await stores.appLock.enroll(methods)
        setLockMethods(await stores.appLock.methods())
        // Restore/move path: the lock now exists, so stage, then reload into
        // the unlock screen.
        if (await finishStagedRestore()) return
        await activate()
      } catch (e) {
        setMoveProgress(null)
        setNotice(`could not set the app-lock: ${String(e instanceof Error ? e.message : e)}`)
      }
    },
    [activate, finishStagedRestore],
  )

  // Enroll a biometric alongside the knowledge factor (returns the enroll method).
  const makeBiometricMethod = useCallback(async (): Promise<EnrollMethod | null> => {
    const id = idRef.current
    if (!id) return null
    try {
      const { credentialId, prfSecret } = await enrollBiometric(id.userId)
      return { kind: 'bio', credentialId, prfSecret }
    } catch (e) {
      setNotice(`biometric setup failed: ${String(e instanceof Error ? e.message : e)}`)
      return null
    }
  }, [])

  // Add biometric unlock AFTER initial setup (from Settings): enroll a WebAuthn
  // credential, wrap the Local Data Key under its PRF secret, and refresh the method
  // list. We are unlocked here (the messenger is showing), which addBiometric requires.
  const addBiometric = useCallback(async (): Promise<void> => {
    const stores = storesRef.current
    if (!stores) return
    const method = await makeBiometricMethod()
    if (!method || method.kind !== 'bio') return // makeBiometricMethod already surfaced any error
    try {
      await stores.appLock.addBiometric(method.credentialId, method.prfSecret)
      setLockMethods(await stores.appLock.methods())
      setNotice('fingerprint / face unlock is on for this device')
    } catch (e) {
      setNotice(`could not add biometric unlock: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [makeBiometricMethod])

  // Remove biometric unlock (a knowledge factor always remains, so this can never
  // orphan the data; the store enforces it).
  const removeBiometric = useCallback(async (): Promise<void> => {
    const stores = storesRef.current
    if (!stores) return
    try {
      await stores.appLock.removeBiometric()
      setLockMethods(await stores.appLock.methods())
      setNotice('fingerprint / face unlock removed for this device')
    } catch (e) {
      setNotice(`could not remove biometric unlock: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [])

  const unlock = useCallback(
    async (secret: string): Promise<boolean> => {
      const stores = storesRef.current
      if (!stores) return false
      setNotice(null)
      try {
        await stores.appLock.unlockWithSecret(secret)
        // A restore/move opened on an already-configured device finishes HERE:
        // the unlock made the LDK resident, so stage and reload instead of
        // activating (the shipped enroll-throw dead end, fixed).
        if (await finishStagedRestore()) return true
        await activate()
        return true
      } catch (e) {
        setMoveProgress(null)
        setNotice(e instanceof AppLockAuthError ? 'incorrect passphrase or PIN' : `could not unlock: ${String(e instanceof Error ? e.message : e)}`)
        return false
      }
    },
    [activate, finishStagedRestore],
  )

  const unlockWithBiometric = useCallback(async (): Promise<boolean> => {
    const stores = storesRef.current
    if (!stores) return false
    setNotice(null)
    try {
      const credId = await stores.appLock.biometricCredentialId()
      if (!credId) throw new Error('no biometric enrolled')
      const prf = await unlockBiometric(credId)
      await stores.appLock.unlockWithBiometric(prf)
      if (await finishStagedRestore()) return true
      await activate()
      return true
    } catch (e) {
      setMoveProgress(null)
      setNotice(`biometric unlock failed: ${String(e instanceof Error ? e.message : e)}`)
      return false
    }
  }, [activate, finishStagedRestore])

  // Forgot-secret escape: erase saved history + the lock, keep identity/contacts,
  // and return to enrollment.
  const resetLock = useCallback(async () => {
    const stores = storesRef.current
    if (!stores) return
    teardownLive()
    try {
      // EVERYTHING local is sealed under the Local Data Key being discarded here, so
      // it is all unrecoverable ciphertext the moment this runs and must be cleared,
      // or a re-enrolled lock's new LDK meets rows nothing can open and the app
      // cannot start. Since P11 that includes the RATCHET SESSIONS and the send
      // queue, which is why a reset now ends every conversation rather than only
      // erasing saved messages. It is not a choice: a discarded key cannot be
      // reconciled with data encrypted under it.
      //
      // The identity still survives, so people can still reach this user, but each
      // conversation has to be opened again from this side before they can.
      await stores.sessions.wipeAll()
      await stores.contacts.wipeLocalData()
      // Prekey privates go with them (sealed since P11), and the flag makes the next
      // connect re-register a fresh set, exactly as a restore does.
      await stores.keys.delete(PREKEYS_KEY)
      // The account key is sealed under the key being discarded here, so it is
      // unrecoverable ciphertext from this moment and must go with the rest. A
      // linked device that resets its lock stops being part of the account and has
      // to be linked again, which is the honest consequence of losing the secret.
      await clearAccountKey(stores.keys)
      await stores.keys.put(RESTORE_PENDING_KEY, Uint8Array.from([1]))
      // A pending move-refresh list would re-add (via first-contact recording) the
      // very contacts this reset just wiped. It dies with them inside
      // wipeLocalData above, which is where it lives now that it is sealed (8.5).
      await stores.appLock.reset()
      // Tell any sibling tab still holding the old key to stop. This tab is on the
      // lock screen with no channel open, so it posts through a one-shot one.
      try {
        const ch = new BroadcastChannel(CROSS_TAB_CHANNEL)
        ch.postMessage({ kind: 'lockReset' })
        ch.close()
      } catch {
        /* unsupported: the wipe above is what actually protects the data */
      }
    } catch (e) {
      // NOT best-effort any more. A half-finished wipe leaves rows that cannot be
      // opened and cannot be cleared, so the honest move is to stay on the lock
      // screen and say so rather than route on to enrollment over broken state.
      setNotice(`could not reset the app-lock: ${String(e instanceof Error ? e.message : e)}. Nothing was changed; try again.`)
      setPhase('locked')
      return
    }
    setConversations({})
    setContacts([])
    setAliases({})
    restorePayloadRef.current = null
    movePayloadRef.current = null
    setMoveProgress(null)
    setRestorePending(false)
    setNotice('the app-lock was reset. Every conversation on this device ended: message each contact again to reopen one, and until you do they cannot reach you.')
    setPhase('enroll')
  }, [teardownLive])

  // --- messaging actions (unchanged behaviour) -----------------------------

  const join = useCallback(async (input: string) => {
    const live = liveRef.current
    if (!live) return
    setNotice(null)
    let artifact: InviteArtifact
    try {
      artifact = decodeInviteArtifact(input)
    } catch (e) {
      setNotice(String(e instanceof Error ? e.message : e))
      return
    }
    try {
      await live.client.joinWithInvite(artifact)
      setRegistered(true)
      setContacts(await live.client.listContacts())
      setPhase('ready')
      setNotice(artifact.inviter ? 'joined and pinned your inviter' : 'registered')
    } catch (e) {
      setNotice(`could not join: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [])

  const send = useCallback(
    async (peer: string, text: string, ephemeral = false) => {
      const live = liveRef.current
      if (!live || !text.trim()) return
      if (text.length > MAX_MESSAGE_CHARS) {
        setNotice(`message is too long (limit ${MAX_MESSAGE_CHARS.toLocaleString()} characters)`)
        return
      }
      const msgId = bytesToHex(newMsgId())
      const ts = Date.now()
      // The optimistic bubble carries the ephemeral flag so it renders with the
      // session-only marker immediately (the backstop that makes a wrong-mode send
      // visible), even before delivery resolves. Mirror it to sibling tabs so the
      // sent message appears there live too.
      const m: Message = { id: msgId, dir: 'out', text, ts, ...(ephemeral ? { ephemeral: true } : {}) }
      appendMessage(peer, m)
      broadcast({ kind: 'append', peer, msg: m })
      try {
        await live.client.sendText(peer, text, msgId, ts, ephemeral)
        setContacts(await live.client.listContacts())
      } catch (e) {
        markFailed(msgId)
        broadcast({ kind: 'failed', id: msgId })
        const isConflict = e instanceof Error && e.name === 'KeyConflictError'
        if (isConflict) {
          setSecurityNotices((prev) => {
            const d = `sending to ${peer.slice(0, 12)}… was BLOCKED: the directory presented a key that conflicts with the one stored for this contact. Verify safety numbers in person.`
            return prev.includes(d) ? prev : [...prev, d]
          })
        } else {
          setNotice(`send failed: ${String(e instanceof Error ? e.message : e)}`)
        }
      }
    },
    [appendMessage, broadcast, markFailed],
  )

  // Delete-for-everyone a message YOU sent (P10d). Optimistically removes the
  // bubble, then asks the client to remove the local copy and (if delivered) ask
  // the peer to remove it too. Honest copy: never claims a guaranteed deletion.
  const deleteMessage = useCallback(async (peer: string, id: string, failed?: boolean) => {
    const live = liveRef.current
    if (!live) return
    removeBubble(peer, id)
    broadcast({ kind: 'delete', peer, id })
    try {
      if (failed) {
        // Never delivered (send failed/timed out): a local-only removal. No point
        // asking the peer to delete a message they never received.
        await live.client.removeHistory(peer, 'out', id)
        setNotice('message deleted')
        return
      }
      const { requested } = await live.client.deleteForEveryone(peer, id)
      setNotice(requested ? 'delete sent (the other device removes it if it is online and running an honest app)' : 'message deleted')
    } catch (e) {
      setNotice(`could not delete: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [removeBubble, broadcast])

  const startChat = useCallback((peer: string) => {
    setConversations((prev) => (prev[peer] ? prev : { ...prev, [peer]: [] }))
  }, [])

  const renameChat = useCallback(async (peer: string, name: string) => {
    const live = liveRef.current
    if (!live) return
    try {
      await live.client.setAlias(peer, name)
      setAliases(await live.client.listAliases())
    } catch (e) {
      setNotice(`could not rename this chat: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [])

  const openFromCode = useCallback(async (input: string): Promise<string | null> => {
    const live = liveRef.current
    if (!live) return null
    setNotice(null)
    const raw = input.trim()
    if (USER_ID_RE.test(raw.toLowerCase())) {
      const id = raw.toLowerCase()
      // Both ids, because on a linked device they differ: the account is what
      // people add, and the device id is what this device authenticates as.
      // Opening a chat with either of your own is a mistake worth catching.
      if (id === live.client.account.accountId || id === live.identity.userId) {
        setNotice('that is your own id')
        return null
      }
      setConversations((prev) => (prev[id] ? prev : { ...prev, [id]: [] }))
      // Fetch their key and record a (TOFU) contact so you can verify them right
      // away, without having to send a message first. Best-effort: if they are not
      // registered yet the chat still opens and the contact lands on first message.
      try {
        await live.client.addContact(id)
        setContacts(await live.client.listContacts())
      } catch {
        /* not registered / offline; verify will re-try, or it records on first message */
      }
      return id
    }
    let artifact: InviteArtifact
    try {
      artifact = decodeInviteArtifact(raw)
    } catch (e) {
      setNotice(`unrecognized code: ${String(e instanceof Error ? e.message : e)}`)
      return null
    }
    if (!artifact.inviter) {
      setNotice('this is a setup invite with no contact to add; ask them for their code or user id')
      return null
    }
    if (artifact.inviter === live.identity.userId) {
      setNotice('that invite is your own')
      return null
    }
    const id = artifact.inviter
    try {
      await live.client.addInviteContact(id)
      setContacts(await live.client.listContacts())
      setNotice('contact added and pinned')
    } catch (e) {
      setNotice(`opened a chat, but could not pin them yet: ${String(e instanceof Error ? e.message : e)}`)
    }
    setConversations((prev) => (prev[id] ? prev : { ...prev, [id]: [] }))
    return id
  }, [])

  const mintInvite = useCallback(async (): Promise<MintedInvite | null> => {
    const live = liveRef.current
    if (!live) return null
    try {
      const { code, inviterFingerprint } = await live.client.mintInvite()
      const artifact: InviteArtifact = { code, inviter: inviterFingerprint }
      return { token: encodeInviteArtifact(artifact), url: inviteUrl(appOrigin(), artifact), inviter: inviterFingerprint }
    } catch (e) {
      setNotice(`could not mint an invite: ${String(e instanceof Error ? e.message : e)}`)
      return null
    }
  }, [])

  // Pull who has redeemed our invites and record each new joiner as a TOFU contact
  // (mutual invite, DESIGN 6.3). Returns the count of newly-added contacts so the
  // InvitePanel can confirm a join while a user watches for it. Best-effort; the
  // client fires onContactsChanged, so the contact list refreshes on its own.
  const syncInviteContacts = useCallback(async (): Promise<number> => {
    const live = liveRef.current
    if (!live) return 0
    try {
      return await live.client.syncInviteContacts()
    } catch {
      return 0
    }
  }, [])

  const markVerified = useCallback(async (peer: string) => {
    const live = liveRef.current
    if (!live) return
    try {
      await live.client.markVerified(peer)
      setContacts(await live.client.listContacts())
    } catch (e) {
      setNotice(`could not save the verification: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [])

  /** Remove the saved messages for a chat, keeping the contact and its verification. */
  const clearMessages = useCallback(async (peer: string) => {
    const live = liveRef.current
    if (!live) return
    try {
      const { removed, unreadable } = await live.client.clearMessages(peer)
      dropConversation(peer)
      broadcast({ kind: 'conversationRemoved', peer, keepThread: true })
      const msgs = `${removed} saved ${removed === 1 ? 'message' : 'messages'}`
      setNotice(unreadable > 0 ? `removed ${msgs} from this device. ${unreadableNote(unreadable)}` : `removed ${msgs} from this device`)
    } catch (e) {
      setNotice(`could not clear the messages: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [broadcast, dropConversation])

  /** Delete everything this device holds for a peer. Not a block: see DESIGN 8.9. */
  const deleteConversation = useCallback(async (peer: string) => {
    const live = liveRef.current
    if (!live) return
    try {
      const { removed, unreadable, cancelled } = await live.client.deleteConversation(peer)
      dropConversation(peer)
      noteRemoved(peer)
      broadcast({ kind: 'conversationRemoved', peer, keepThread: false })
      await listContacts()
      setAliases(await live.client.listAliases())
      const msgs = `${removed} ${removed === 1 ? 'message' : 'messages'}`
      // NOT "cancelled N not yet sent": an outbox row survives the socket write until
      // the relay acks it, so some of these may already be at the relay and will
      // still be delivered. Say only what is provable, which is that nothing further
      // goes out from here.
      const queued = cancelled > 0 ? `, and removed ${cancelled} still queued here` : ''
      setNotice(
        unreadable > 0
          ? `deleted from this device (${msgs}${queued}). ${unreadableNote(unreadable)}`
          : `deleted from this device (${msgs}${queued})`,
      )
    } catch (e) {
      setNotice(`could not delete the conversation: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [broadcast, dropConversation, listContacts])

  // Withdraw a verification. Only ever called from an explicit, confirmed user
  // action on the verify screen: a scan result must never reach this, or anyone
  // able to put a QR code in front of a camera could strip a real verification.
  const unverify = useCallback(async (peer: string) => {
    const live = liveRef.current
    if (!live) return
    try {
      await live.client.unverify(peer)
      setContacts(await live.client.listContacts())
    } catch (e) {
      setNotice(`could not remove the verification: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [])

  // Make sure we hold a contact (with their key) for `peer` so the verify screen can
  // render a safety number. Fetches + records a TOFU contact if we do not have one
  // yet (e.g. right after adding them by code/QR, before any message). Returns
  // whether a contact is now available.
  const ensureContact = useCallback(async (peer: string): Promise<boolean> => {
    const live = liveRef.current
    if (!live) return false
    try {
      const list = await live.client.listContacts()
      if (list.some((c) => c.peerId === peer)) {
        setContacts(list)
        return true
      }
      await live.client.addContact(peer)
      setContacts(await live.client.listContacts())
      return true
    } catch (e) {
      setNotice(`could not load this contact's key to verify (${String(e instanceof Error ? e.message : e)}); send them a message first`)
      return false
    }
  }, [])

  const dismissSecurityNotice = useCallback((detail: string) => {
    setSecurityNotices((prev) => prev.filter((d) => d !== detail))
  }, [])

  const dismissNotice = useCallback(() => setNotice(null), [])

  // Restore from a backup file (P8/P10c). Opens the backup, then routes to the
  // mandatory enrollment step; enrollLock() finishes staging (encrypted contacts)
  // and reloads. This keeps contacts encrypted at rest (no plaintext window).
  const restoreFromBackup = useCallback(async (file: File, passphrase: string) => {
    const stores = storesRef.current
    if (!stores) return
    setRestoreBusy(true)
    setRestoreError(null)
    try {
      // Size gate BEFORE reading the file into memory: the in-blob cap cannot
      // protect against a mis-picked multi-gigabyte file if the whole thing is
      // buffered first. Generous bound, shared by both formats.
      if (file.size > MOVE_MAX_PAYLOAD_BYTES + 128) {
        throw new Error('that file is far too large to be a Nightjar backup or move file')
      }
      const blob = new Uint8Array(await file.arrayBuffer())
      // Route by MAGIC, never by file extension (pickers lie; names get edited).
      const isMove = blob.length >= 4 && blob[0] === 0x4e && blob[1] === 0x4a && blob[2] === 0x4d && blob[3] === 0x56
      if (isMove) {
        parseMoveHeader(blob)
        const opened = await openMove(blob, passphrase, { kdf: createBackupKdf() })
        teardownLive()
        idRef.current = opened.payload.identity
        movePayloadRef.current = opened
        restorePayloadRef.current = null
      } else {
        parseBackupHeader(blob)
        const opened = await openBackup(blob, passphrase, { kdf: createBackupKdf() })
        teardownLive()
        idRef.current = opened.payload.identity
        restorePayloadRef.current = opened.payload
        movePayloadRef.current = null
      }
      setRestorePending(true)
      setRestoreBusy(false)
      // The lock decides how staging finishes (the shipped enroll-throw dead end,
      // fixed): unconfigured enrolls; still-unlocked (onboarding: the mandatory
      // enrollment already ran this session) stages immediately; locked (a crash
      // retry, or an evicted device whose lock record survived) unlocks first.
      const st = await stores.appLock.status()
      if (st === 'unconfigured') {
        setNotice(
          isMove
            ? 'move file opened. Now set an app-lock for this device to finish the move.'
            : 'backup opened. Now set an app-lock for this device to finish restoring.',
        )
        setPhase('enroll')
      } else if (st === 'unlocked') {
        if (await finishStagedRestore()) return
      } else {
        setLockMethods(await stores.appLock.methods())
        setNotice(
          isMove
            ? 'move file opened. Unlock this device to finish the move.'
            : 'backup opened. Unlock this device to finish restoring.',
        )
        setPhase('locked')
      }
    } catch (e) {
      setMoveProgress(null)
      setRestoreError(e instanceof Error ? e.message : String(e))
      setRestoreBusy(false)
    }
  }, [teardownLive, finishStagedRestore])

  const exportBackup = useCallback(async (passphrase: string): Promise<boolean> => {
    const live = liveRef.current
    if (!live) return false
    try {
      const list = await live.client.listContacts()
      const blob = await sealBackup(live.identity, list, passphrase, { kdf: createBackupKdf() })
      const stamp = new Date().toISOString().slice(0, 10).replaceAll('-', '')
      const url = URL.createObjectURL(new Blob([blob.buffer as ArrayBuffer], { type: 'application/octet-stream' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `nightjar-backup-${stamp}.njbk`
      a.rel = 'noopener'
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 60_000)
      return true
    } catch (e) {
      setNotice(`backup failed: ${String(e instanceof Error ? e.message : e)}`)
      return false
    }
  }, [])

  // Erase Nightjar from THIS device (Phase D old-device finish step). Offered
  // only after a move file was exported this session (moveExported), behind a
  // typed confirmation in the UI. Not a forensic wipe: it removes Nightjar's
  // local data (identity, sealed stores, the eviction marker, push registration,
  // the service worker) so the device boots factory-fresh, and disconnects so it
  // stops draining mail meant for the new device. Nothing can revoke it remotely;
  // this is the honest local half of that.
  /**
   * Replace this account's key, keeping the relationships (rotation).
   *
   * The honest framing lives on the screen that offers this, not here: it helps
   * when the old key is gone but not in use, and it does not beat somebody
   * actively using it. What this does is drive the client and then re-read the
   * contact list, because every contact's trust has just been reset to unverified
   * and the UI would otherwise go on showing badges that are no longer true.
   */
  const rotateAccount = useCallback(async (): Promise<string | null> => {
    const live = liveRef.current
    const stores = storesRef.current
    if (!live || !stores) return null
    try {
      // The key is written to disk before the relay is told anything (see
      // rotateAccount): recording a rotation is irreversible and freezes the old
      // account, so a key that existed only in memory at that moment would be an
      // account a page reload could destroy.
      const { accountId } = await live.client.rotateAccount((priv) =>
        saveAccountKey(stores.keys, stores.appLock, priv),
      )
      if (!mountedRef.current) return accountId
      setAccountIkSigPub(live.client.account.accountKey.publicKey)
      await listContacts()
      setNotice(
        `your account key was replaced. Everyone you talk to now sees you as unverified and has to compare safety ` +
          `numbers with you again, in person.`,
      )
      return accountId
    } catch (e) {
      setNotice(`could not replace your account key: ${String(e instanceof Error ? e.message : e)}`)
      return null
    }
  }, [listContacts])

  const eraseThisDevice = useCallback(async (): Promise<void> => {
    const stores = storesRef.current
    if (!stores) return
    const failed: string[] = []
    const step = async (what: string, run: () => Promise<unknown>) => {
      try {
        await run()
      } catch {
        failed.push(what)
      }
    }
    try {
      const live = liveRef.current
      // Genuinely best-effort: a push registration left behind is a nuisance, not
      // a reason to abandon an erase.
      const endpoint = await unsubscribePush().catch(() => null)
      if (endpoint && live) live.client.unsubscribePush(endpoint)
      // Stop sibling tabs FIRST, before anything is destroyed. One still holding
      // the Local Data Key keeps its socket open, keeps draining the relay, and
      // writes contacts and sessions straight back into the stores wiped below,
      // which is indistinguishable from the device restoring itself from nowhere.
      // Delivery is asynchronous, so this narrows the window rather than closing
      // it, exactly as the staged-restore path does for the same reason.
      try {
        const ch = new BroadcastChannel(CROSS_TAB_CHANNEL)
        ch.postMessage({ kind: 'lockReset' })
        ch.close()
      } catch {
        /* unsupported: single-tab is then the only case, which is safe */
      }
      teardownLive()
      await step('saved messages and sessions', () => stores.sessions.wipeAll())
      await step('contacts', () => stores.contacts.wipeLocalData())
      await step('prekeys', () => stores.keys.delete(PREKEYS_KEY))
      await step('the restore flag', () => stores.keys.delete(RESTORE_PENDING_KEY))
      await step('the identity', () => stores.keys.delete(IDENTITY_KEY))
      await step('the account key', () => clearAccountKey(stores.keys))
      await step('the app-lock', () => stores.appLock.reset())
      await step('the storage marker', () => stores.sentinel.unmark())
      try {
        const regs = await navigator.serviceWorker?.getRegistrations?.()
        if (regs) for (const r of regs) await r.unregister().catch(() => {})
      } catch {
        /* best-effort */
      }
      try {
        if (failed.length > 0) {
          // A partial erase used to be indistinguishable from a complete one:
          // every step swallowed its error and the reload happened regardless, so
          // a device whose IDENTITY would not delete came back as itself,
          // re-registered, and pulled its contacts down again, looking for all the
          // world like it had restored a backup from nowhere. The reload still has
          // to happen (the client is already torn down and the stores are in an
          // unknown state), so the warning is left where a reload cannot clear it.
          localStorage.setItem(ERASE_INCOMPLETE_KEY, failed.join(', '))
        } else {
          // Per-device preferences (notification opt-in, time format) are part of
          // what this device is, so they go with the rest of it.
          localStorage.clear()
        }
      } catch {
        /* storage unavailable: the wipes above are what actually matter */
      }
      globalThis.location.reload()
    } catch (e) {
      setNotice(`could not erase this device: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [teardownLive])

  // --- move to a new device (Phase D, DESIGN 8.3) --------------------------

  /** Gather + measure what a move file would carry, WITHOUT sealing anything:
   *  the panel shows the counts and projected size (or the refusal and its
   *  remedy) BEFORE the user commits to a slow KDF. */
  const prepareMove = useCallback(async (): Promise<
    | { ok: true; messages: number; contacts: number; unreadable: number; orphaned: number; bytes: number }
    | { ok: false; blocked: 'outbox' | 'too-large'; count: number }
    | null
  > => {
    const live = liveRef.current
    if (!live) return null
    try {
      const data = await live.client.exportMoveData()
      const bytes = encodeMovePayload(live.identity, data.contacts, data.aliases, data.dismissals, data.messages, Date.now()).length
      return {
        ok: true,
        messages: data.messages.length,
        contacts: data.contacts.length,
        unreadable: data.unreadable,
        orphaned: data.orphaned,
        bytes,
      }
    } catch (e) {
      if (e instanceof MoveBlockedError) return { ok: false, blocked: e.reason, count: e.count }
      setNotice(`could not prepare the move: ${String(e instanceof Error ? e.message : e)}`)
      return null
    }
  }, [])

  /** Seal + download the move file under the (generated) passphrase. Re-gathers
   *  fresh so the guards re-check at seal time; the preview is advisory only. */
  const createMoveFile = useCallback(async (passphrase: string): Promise<boolean> => {
    const live = liveRef.current
    const stores = storesRef.current
    if (!live || !stores) return false
    try {
      const data = await live.client.exportMoveData()
      const blob = await sealMove(
        { identity: live.identity, contacts: data.contacts, aliases: data.aliases, dismissals: data.dismissals, messages: data.messages },
        passphrase,
        { kdf: createBackupKdf() },
      )
      // The idle-lock may have fired during the KDF. The file is sealed under the
      // passphrase (not the LDK), so nothing leaks either way, but a download must
      // not pop over the lock screen.
      if (!stores.appLock.isUnlocked) {
        setNotice('the app locked while exporting; unlock and try again')
        return false
      }
      const stamp = new Date().toISOString().slice(0, 10).replaceAll('-', '')
      const url = URL.createObjectURL(new Blob([blob.buffer as ArrayBuffer], { type: 'application/octet-stream' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `nightjar-move-${stamp}-v1.njmv`
      a.rel = 'noopener'
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 60_000)
      setMoveExported(true)
      return true
    } catch (e) {
      if (e instanceof MoveBlockedError) {
        setNotice(
          e.reason === 'outbox'
            ? `${e.count} message(s) are still waiting to send. Stay connected until they show sent, then try again; a message still waiting when you move will never be sent by either device.`
            : `this device holds more saved history than one move file can carry (${e.count} messages). Clear messages you no longer need (per conversation: Clear messages), then try again.`,
        )
      } else {
        setNotice(`move export failed: ${String(e instanceof Error ? e.message : e)}`)
      }
      return false
    }
  }, [])

  // --- linking another device (Sesame B1) ----------------------------------

  /**
   * Join the account the transfer came from: keep this device's own identity, take
   * the account key and the contacts, then register as a device of that account.
   *
   * The order is not interchangeable. The account key is stored first because a
   * device holding contacts of an account it cannot sign for is the one half-linked
   * state worth avoiding, and registration comes last because the relay only
   * accepts it once the account's published list names this device, which the
   * OTHER device did before it sent any of this.
   */
  const completeLink = useCallback(async (payload: LinkPayload): Promise<void> => {
    const stores = storesRef.current
    const live = liveRef.current
    if (!stores || !live) return
    linkStopRef.current?.()
    linkStopRef.current = null
    // Refused here as well as inside the client, so the reason reaches the person
    // rather than arriving as a raw error after a ceremony they just performed.
    // Nothing in the UI can reach this today (the offer lives only on the setup
    // screen), but "unreachable" is not the same as "refused".
    if (live.client.isRegistered) {
      setLinkState('idle')
      linkSecretRef.current = null
      setNotice(
        'this device already has an account of its own, so it cannot join another. Start it over first (Settings, Your devices, start over on this device), which erases everything it holds.',
      )
      return
    }
    setLinkState('joining')
    try {
      await stageLink(
        {
          lock: stores.lock,
          contacts: stores.contacts,
          saveAccountKey: (priv) => saveAccountKey(stores.keys, stores.appLock, priv),
        },
        { accountKeyPriv: payload.accountKeyPriv, contacts: payload.contacts, aliases: payload.aliases },
      )
      live.client.setAccountKey({
        privateKey: payload.accountKeyPriv,
        publicKey: ed25519Public(payload.accountKeyPriv),
      })
      // The account key just changed, so the key a safety number covers changed
      // with it. Without this the verify screen would keep comparing this
      // DEVICE's key against every contact's account key and report a mismatch.
      setAccountIkSigPub(live.client.account.accountKey.publicKey)
      await live.client.registerAsDevice(payload.accountId)
      linkSecretRef.current = null
      if (!mountedRef.current) return
      setRegistered(true)
      await listContacts()
      setAliases(await live.client.listAliases())
      setLinkState('done')
      setPhase('ready')
      // Both halves of the truth, in the order that matters to the user.
      setNotice(
        'this device is now part of your account. It starts with no messages, and every contact shows as unverified until you compare safety numbers here: a verification belongs to the device that did it.',
      )
    } catch (e) {
      // Undo the half that already committed. `stageLink` writes the account key
      // before `registerAsDevice`, which needs the network and can fail (a dropped
      // socket mid-ceremony, a relay rejection). Leaving the key behind is not a
      // harmless remnant: it is loaded on every later boot and PREFERRED over this
      // device's own, so the device would report the other account forever, sign
      // rosters as it, announce it to contacts, and copy everything it sends and
      // receives to that account's devices. The user's next move from this screen
      // is usually "linking failed, I will just join with an invite instead",
      // which never touches the key.
      //
      // Retrying the ceremony is safe either way, because stageLink overwrites.
      await clearAccountKey(stores.keys).catch(() => {})
      live.client.setAccountKey(null)
      setAccountIkSigPub(live.client.account.accountKey.publicKey)
      setLinkState('idle')
      linkSecretRef.current = null
      setNotice(`could not finish linking this device: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [listContacts])

  /**
   * The NEW device's half: show a code, and take whatever arrives that opens
   * under it.
   *
   * The secret inside the code never crosses the network, so a payload that opens
   * under it proves the sender was the device that photographed this screen. That
   * is the entire authentication of the ceremony in both directions, which is why
   * the secret lives in RAM only: a reload means showing a fresh code rather than
   * leaving a key-bearing value on disk.
   */
  const startLinking = useCallback((): { code: string; deviceId: string } | null => {
    const live = liveRef.current
    if (!live) return null
    linkStopRef.current?.()
    const { code, parsed } = newLinkCode(live.identity.ikSig.publicKey)
    linkSecretRef.current = parsed.secret
    setLinkState('waiting')
    linkStopRef.current = live.client.awaitLinkPayload(parsed.secret, (payload) => {
      void completeLink(payload)
    })
    return { code, deviceId: parsed.deviceId }
  }, [completeLink])

  const cancelLinking = useCallback(() => {
    linkStopRef.current?.()
    linkStopRef.current = null
    linkSecretRef.current = null
    setLinkState('idle')
  }, [])

  /** Open a transfer caught by the camera under the code this device is showing.
   *  Returns whether it opened; a failure is surfaced and the user starts over. */
  const openOpticalLink = useCallback(
    async (blob: Uint8Array): Promise<boolean> => {
      const secret = linkSecretRef.current
      if (!secret) return false
      let payload: LinkPayload
      try {
        payload = openLink([blob], secret)
      } catch (e) {
        // The only honest reading of this: what was on that screen was not meant
        // for this device, or was not a device transfer at all.
        setNotice(
          `that transfer did not open with this device's code (${String(e instanceof Error ? e.message : e)}). Start again with a fresh code.`,
        )
        return false
      }
      await completeLink(payload)
      return true
    },
    [completeLink],
  )

  /**
   * The EXISTING device's half: read the code, put the new device on this
   * account's published list, and hand back what it needs to send the transfer.
   *
   * Authorizing comes first because it is what lets the new device register at
   * all: it consumes no invite, and the signed list stands in for one.
   */
  const authorizeNewDevice = useCallback(
    async (codeText: string): Promise<{ deviceId: string; secret: Uint8Array } | null> => {
      const live = liveRef.current
      if (!live) return null
      setNotice(null)
      try {
        const parsed = parseLinkCode(codeText)
        if (parsed.deviceId === live.client.deviceId) {
          setNotice('that is this device\'s own code')
          return null
        }
        await live.client.authorizeDevice(parsed.deviceId, parsed.dkSigPub)
        return { deviceId: parsed.deviceId, secret: parsed.secret }
      } catch (e) {
        setNotice(`could not add that device: ${String(e instanceof Error ? e.message : e)}`)
        return null
      }
    },
    [],
  )

  /** Seal the transfer for a screen (preferred: it never reaches the network). */
  const sealLinkTransfer = useCallback(async (secret: Uint8Array): Promise<Uint8Array | null> => {
    const live = liveRef.current
    if (!live) return null
    try {
      return await live.client.sealLinkForOptical(secret)
    } catch (e) {
      setNotice(`could not prepare the transfer: ${String(e instanceof Error ? e.message : e)}`)
      return null
    }
  }, [])

  /** Send the transfer over the relay instead. Live-only and never stored, but the
   *  relay does carry it, which is why this is the fallback and not the default. */
  const sendLinkOverRelay = useCallback(async (deviceId: string, secret: Uint8Array): Promise<boolean> => {
    const live = liveRef.current
    if (!live) return false
    try {
      await live.client.sendLinkPayload(deviceId, secret)
      return true
    } catch (e) {
      const msg = String(e instanceof Error ? e.message : e)
      setNotice(
        msg.includes('not_connected')
          ? 'the other device is not connected right now. Both devices have to be open at the same time for this, so leave it on the linking screen and try again.'
          : `could not send the transfer: ${msg}`,
      )
      return false
    }
  }, [])

  const listDevices = useCallback(async () => {
    const live = liveRef.current
    if (!live) return []
    try {
      return await live.client.listDevices()
    } catch (e) {
      setNotice(`could not read your device list: ${String(e instanceof Error ? e.message : e)}`)
      return []
    }
  }, [])

  const removeDevice = useCallback(async (deviceId: string): Promise<boolean> => {
    const live = liveRef.current
    if (!live) return false
    try {
      await live.client.removeDevice(deviceId)
      setNotice(
        'that device is off your list, so nothing further will be sent to it. It keeps the messages it already had, and this is not the same as taking away what it knows: for a device you have lost, treat the account as compromised.',
      )
      return true
    } catch (e) {
      setNotice(`could not remove that device: ${String(e instanceof Error ? e.message : e)}`)
      return false
    }
  }, [])

  // --- moving saved messages between your own devices (DESIGN 8.12) ---------

  /** The device that WANTS the messages shows a code. Same shape as the linking
   *  code and a different magic, so the two ceremonies cannot be crossed. */
  const startHistoryRequest = useCallback((): { code: string; deviceId: string } | null => {
    const live = liveRef.current
    if (!live) return null
    const { code, parsed } = newHistoryCode(live.identity.ikSig.publicKey)
    historySecretRef.current = parsed.secret
    return { code, deviceId: parsed.deviceId }
  }, [])

  const cancelHistoryRequest = useCallback(() => {
    historySecretRef.current = null
  }, [])

  /** The sending device reads that code. Returns what it needs to seal for it. */
  const readHistoryCode = useCallback((codeText: string): { deviceId: string; secret: Uint8Array } | null => {
    try {
      const parsed = parseHistoryCode(codeText)
      return { deviceId: parsed.deviceId, secret: parsed.secret }
    } catch (e) {
      setNotice(String(e instanceof Error ? e.message : e))
      return null
    }
  }, [])

  /** What each span of time would cost, so the choice is made on real numbers
   *  rather than on hope. */
  const prepareHistory = useCallback(
    async (since: number): Promise<{ count: number; bytes: number; tooLarge: boolean; orphaned: number } | null> => {
      const live = liveRef.current
      if (!live) return null
      try {
        const p = await live.client.prepareHistoryTransfer(since)
        return { count: p.messages.length, bytes: p.bytes, tooLarge: p.tooLarge, orphaned: p.orphaned }
      } catch (e) {
        setNotice(`could not read your saved messages: ${String(e instanceof Error ? e.message : e)}`)
        return null
      }
    },
    [],
  )

  const sealHistoryFor = useCallback(
    async (deviceId: string, secret: Uint8Array, since: number): Promise<Uint8Array | null> => {
      const live = liveRef.current
      if (!live) return null
      try {
        return await live.client.sealHistoryFor(deviceId, secret, since)
      } catch (e) {
        setNotice(`could not prepare those messages: ${String(e instanceof Error ? e.message : e)}`)
        return null
      }
    },
    [],
  )

  /** Take in a transfer the camera caught, and say honestly what landed. */
  const receiveHistoryTransfer = useCallback(async (blob: Uint8Array): Promise<boolean> => {
    const live = liveRef.current
    const secret = historySecretRef.current
    if (!live || !secret) return false
    setHistoryProgress({ done: 0, total: 0 })
    try {
      const res = await live.client.importHistoryTransfer(blob, secret, (done, total) => {
        if (mountedRef.current) setHistoryProgress({ done, total })
      })
      historySecretRef.current = null
      setHistoryProgress(null)
      // Re-read from disk rather than appending in RAM, so what is on screen is
      // what was actually stored, in the right order.
      const hist = await live.client.loadAllHistory()
      if (mountedRef.current) setConversations((prev) => mergeHistory(hist, prev))
      const skipped: string[] = []
      if (res.skippedUnknownPeer > 0) skipped.push(`${res.skippedUnknownPeer} for people this device does not have`)
      if (res.skippedDeleted > 0) skipped.push(`${res.skippedDeleted} you had already deleted here`)
      setNotice(
        `${res.imported} saved ${res.imported === 1 ? 'message' : 'messages'} added to this device` +
          (skipped.length > 0 ? `. Left out: ${skipped.join(', ')}.` : '.'),
      )
      return true
    } catch (e) {
      setHistoryProgress(null)
      setNotice(`could not take those messages in: ${String(e instanceof Error ? e.message : e)}`)
      return false
    }
  }, [])

  const enableNotifications = useCallback(async () => {
    const live = liveRef.current
    if (!live) return
    const key = live.client.pushKey
    if (!key) {
      setNotice('this relay does not have notifications configured yet')
      return
    }
    try {
      const perm = await requestNotifyPermission()
      if (perm !== 'granted') {
        setNotice(perm === 'denied' ? 'notifications are blocked in your browser settings' : 'notification permission was not granted')
        refreshNotify()
        return
      }
      const sub = await subscribePush(key)
      if (!sub) {
        setNotice('could not subscribe this device to notifications')
        refreshNotify()
        return
      }
      live.client.subscribePush(sub)
      setNotice('notifications are on for this device')
    } catch {
      setNotice('could not turn on notifications')
    }
    refreshNotify()
  }, [refreshNotify])

  const disableNotifications = useCallback(async () => {
    const live = liveRef.current
    const endpoint = await unsubscribePush()
    if (endpoint && live) live.client.unsubscribePush(endpoint)
    refreshNotify()
  }, [refreshNotify])

  return {
    phase,
    error,
    notice,
    securityNotices,
    identity,
    accountIkSigPub,
    connected,
    registered,
    contacts,
    aliases,
    conversations,
    prefillInvite,
    notify,
    restoreBusy,
    restoreError,
    storagePersisted,
    lockMethods,
    bioAvailable,
    restorePending,
    removedPeer,
    moveProgress,
    moveExported,
    linkState,
    historyProgress,
    actions: {
      startHistoryRequest,
      cancelHistoryRequest,
      readHistoryCode,
      prepareHistory,
      sealHistoryFor,
      receiveHistoryTransfer,
      startLinking,
      cancelLinking,
      openOpticalLink,
      authorizeNewDevice,
      sealLinkTransfer,
      sendLinkOverRelay,
      listDevices,
      removeDevice,
      enrollLock,
      makeBiometricMethod,
      unlock,
      unlockWithBiometric,
      lockNow,
      resetLock,
      addBiometric,
      removeBiometric,
      prepareMove,
      createMove: createMoveFile,
      eraseThisDevice,
      rotateAccount,
      join,
      send,
      deleteMessage,
      startChat,
      openFromCode,
      renameChat,
      mintInvite,
      syncInviteContacts,
      markVerified,
      unverify,
      clearMessages,
      deleteConversation,
      ensureContact,
      dismissNotice,
      dismissSecurityNotice,
      listContacts,
      enableNotifications,
      disableNotifications,
      restoreFromBackup,
      exportBackup,
    },
  }
}
