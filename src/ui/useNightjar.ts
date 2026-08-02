// The app's single source of truth: owns the app-lock lifecycle AND the
// NightjarClient lifecycle. The mandatory app-lock (P10c) gates everything: the
// client is NOT constructed or connected until the Local Data Key is in RAM (via
// enrollment on first run, or unlock on return), so nothing is decrypted, sent,
// or persisted while locked. Locking (idle timeout / "lock now") tears the client
// down and clears the decrypted history from memory.

import { useCallback, useEffect, useRef, useState } from 'react'
import { PRESENCE_HEARTBEAT_MS } from '../crypto/constants'
import { AppLockAuthError } from '../crypto/appLock'
import type { Identity } from '../crypto/identity'
import { NightjarClient, type StoredMessage } from '../net/client'
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
import { bytesToHex } from '@noble/hashes/utils.js'
import { newMsgId } from '../crypto/message'
import { createBackupKdf } from '../platform/backupKdf'
import { AppLockStore, type EnrollMethod } from '../storage/appLockStore'
import { IdbKeyStore, type KeyStore } from '../storage/keystore'
import { HistoryStore } from '../storage/historyStore'
import { bootstrapIdentity } from '../storage/identityStore'
import { IdbSessionStore } from '../storage/sessionStore'
import { SessionSealer } from '../storage/sessionSeal'
import { type Lock, createLock } from '../storage/lock'
import { type Sentinel, createSentinel, requestPersistentStorage } from '../storage/persist'
import { PREKEYS_KEY, PrekeyStore } from '../storage/prekeyStore'
import { type BackupPayload } from '../crypto/backup'
import { RESTORE_PENDING_KEY, clearPendingRestore, pendingRestore, stageRestoreEnrolled } from '../storage/restore'
import { type Contact, ContactStore } from '../trust/contactStore'
import {
  type InviteArtifact,
  decodeInviteArtifact,
  encodeInviteArtifact,
  inviteUrl,
} from '../trust/inviteArtifact'

export type Phase = 'loading' | 'evicted' | 'enroll' | 'locked' | 'onboarding' | 'ready' | 'error'

/** Lock the app after this long hidden (idle). */
const IDLE_LOCK_MS = 5 * 60 * 1000

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
  const pushKeyRef = useRef<string | null>(null)
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

  // Tear down the live client + its foreground handlers (idle-lock / "lock now" /
  // unmount). Does NOT touch the app-lock key material.
  const teardownLive = useCallback(() => {
    teardownRef.current?.()
    teardownRef.current = null
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
          onContactsChanged: () => {
            // A mutual-invite joiner was auto-learned (or deferred trust work landed)
            // after the connect-time refresh already ran; re-read so it appears now.
            if (mountedRef.current) void listContacts().catch(() => {})
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
            setRegistered(client.isRegistered)
            void listContacts().catch(() => {})
            setPhase((prev) => (prev === 'error' ? (client.isRegistered ? 'ready' : 'onboarding') : prev))
          },
        },
        stores.history,
      )
      liveRef.current = { client, identity: id }
      setIdentity(id)

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
      if (authed.registered) await completeRestoreIfPending(client, stores.keys)
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
  }, [appendMessage, removeBubble, markFailed, broadcast, completeRestoreIfPending, refreshNotify])

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

  // Enroll the mandatory app-lock (first run, or the final step of a restore).
  const enrollLock = useCallback(
    async (methods: EnrollMethod[]) => {
      const stores = storesRef.current
      if (!stores) return
      setNotice(null)
      try {
        await stores.appLock.enroll(methods)
        setLockMethods(await stores.appLock.methods())
        const payload = restorePayloadRef.current
        if (payload) {
          // Restore path: the lock now exists, so stage the identity + encrypted
          // contacts, then reload into the unlock screen.
          await stageRestoreEnrolled(
            { keys: stores.keys, sessions: stores.sessions, contacts: stores.contacts, sentinel: stores.sentinel, lock: stores.lock },
            payload,
          )
          restorePayloadRef.current = null
          globalThis.location.reload()
          return
        }
        await activate()
      } catch (e) {
        setNotice(`could not set the app-lock: ${String(e instanceof Error ? e.message : e)}`)
      }
    },
    [activate],
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
        await activate()
        return true
      } catch (e) {
        setNotice(e instanceof AppLockAuthError ? 'incorrect passphrase or PIN' : `could not unlock: ${String(e instanceof Error ? e.message : e)}`)
        return false
      }
    },
    [activate],
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
      await activate()
      return true
    } catch (e) {
      setNotice(`biometric unlock failed: ${String(e instanceof Error ? e.message : e)}`)
      return false
    }
  }, [activate])

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
      await stores.keys.put(RESTORE_PENDING_KEY, Uint8Array.from([1]))
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
      if (id === live.identity.userId) {
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
      const blob = new Uint8Array(await file.arrayBuffer())
      parseBackupHeader(blob)
      const opened = await openBackup(blob, passphrase, { kdf: createBackupKdf() })
      teardownLive()
      idRef.current = opened.payload.identity
      restorePayloadRef.current = opened.payload
      setRestorePending(true)
      setRestoreBusy(false)
      setNotice('backup opened. Now set an app-lock for this device to finish restoring.')
      setPhase('enroll')
    } catch (e) {
      setRestoreError(e instanceof Error ? e.message : String(e))
      setRestoreBusy(false)
    }
  }, [teardownLive])

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
    actions: {
      enrollLock,
      makeBiometricMethod,
      unlock,
      unlockWithBiometric,
      lockNow,
      resetLock,
      addBiometric,
      removeBiometric,
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
