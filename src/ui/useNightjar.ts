// The app's single source of truth: owns the NightjarClient lifecycle (bootstrap
// identity -> connect -> register) and the in-session UI state (contacts,
// conversations, notices). Everything the screens do goes through the actions it
// returns. Message history is in-memory only for this session (per-device history
// is a v1 non-goal; DESIGN 1.2).

import { useCallback, useEffect, useRef, useState } from 'react'
import { PRESENCE_HEARTBEAT_MS } from '../crypto/constants'
import type { Identity } from '../crypto/identity'
import { NightjarClient } from '../net/client'
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
import { openBackup, parseBackupHeader, sealBackup } from '../crypto/backup'
import { createBackupKdf } from '../platform/backupKdf'
import { IdbKeyStore, type KeyStore } from '../storage/keystore'
import { bootstrapIdentity } from '../storage/identityStore'
import { IdbSessionStore } from '../storage/sessionStore'
import { type Lock, createLock } from '../storage/lock'
import { type Sentinel, createSentinel, requestPersistentStorage } from '../storage/persist'
import { PrekeyStore } from '../storage/prekeyStore'
import { clearPendingRestore, pendingRestore, stageRestore } from '../storage/restore'
import { type Contact, ContactStore } from '../trust/contactStore'
import {
  type InviteArtifact,
  decodeInviteArtifact,
  encodeInviteArtifact,
  inviteUrl,
} from '../trust/inviteArtifact'

export type Phase = 'loading' | 'evicted' | 'onboarding' | 'ready' | 'error'

/** Notification/push UI state (P6). `available` is whether the toggle can be
 *  used right now; `needsInstall` is the iOS "add to Home Screen first" case. */
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
  /** An outbound bubble whose send threw before it was queued: rendered as
   *  failed, never as silently delivered (P8 review fix). */
  failed?: boolean
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
}

const uid = () => (globalThis.crypto?.randomUUID?.() ?? `m-${Math.random().toString(36).slice(2)}`)
const appOrigin = () => globalThis.location?.origin || getRelayOrigin()
// Well under the relay's 64 KiB ciphertext cap; a text messenger never needs more.
const MAX_MESSAGE_CHARS = 8000
/** Full-width userId shape: lowercase unpadded base32 of a 32-byte hash. */
const USER_ID_RE = /^[a-z2-7]{52}$/

// Derive the notifications UI state from the platform + the relay's push key.
// The toggle is `available` only when the browser supports push, the relay has a
// VAPID key, and (on iOS) the app is installed to the Home Screen (iOS refuses
// permission/subscribe in a plain Safari tab).
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

export function useNightjar() {
  const [phase, setPhase] = useState<Phase>('loading')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // Security events are STICKY: each needs its own dismissal and is never
  // overwritten by later operational notices (P8 review fix).
  const [securityNotices, setSecurityNotices] = useState<string[]>([])
  const [identity, setIdentity] = useState<Identity | null>(null)
  const [connected, setConnected] = useState(false)
  const [registered, setRegistered] = useState(false)
  const [contacts, setContacts] = useState<Contact[]>([])
  const [conversations, setConversations] = useState<Record<string, Message[]>>({})
  const [prefillInvite, setPrefillInvite] = useState<string>('')
  const [notify, setNotify] = useState<NotifyState>(() => computeNotify(null))
  const [restoreBusy, setRestoreBusy] = useState(false)
  const [restoreError, setRestoreError] = useState<string | null>(null)
  const [storagePersisted, setStoragePersisted] = useState<boolean | null>(null)

  const liveRef = useRef<Live | null>(null)
  const storesRef = useRef<Stores | null>(null)
  const restoreFixupRef = useRef<Promise<void> | null>(null)
  const pushKeyRef = useRef<string | null>(null)
  const heartbeatRef = useRef<number | null>(null)
  const visHandlerRef = useRef<(() => void) | null>(null)

  const refreshNotify = useCallback(() => setNotify(computeNotify(pushKeyRef.current)), [])

  // The client owns the ContactStore privately; expose a listing through it.
  const listContacts = useCallback(async () => {
    const live = liveRef.current
    if (!live) return
    setContacts(await live.client.listContacts())
  }, [])

  const appendMessage = useCallback((peer: string, m: Message) => {
    setConversations((prev) => ({ ...prev, [peer]: [...(prev[peer] ?? []), m] }))
  }, [])

  // Consume a pending-restore flag (P8): the forced fresh-prekey publish that
  // completes a restore (DESIGN 8.3). Deduplicated through a ref because it is
  // triggered from both the boot path and every onConnection(true), which can
  // overlap on the first connect; reregister must never run twice concurrently.
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

  useEffect(() => {
    let cancelled = false
    // Prefill the invite box from a deep link (…/#i=CODE.inviter), then strip
    // it from the URL so the invite token does not linger in browser history.
    const hash = globalThis.location?.hash ?? ''
    const m = hash.match(/[#?&]i=([^#?&\s]+)/)
    if (m) {
      setPrefillInvite(decodeURIComponent(m[1]))
      try {
        history.replaceState(null, '', globalThis.location.pathname + globalThis.location.search)
      } catch {
        /* history API unavailable: cosmetic only */
      }
    }

    void (async () => {
      try {
        const persisted = await requestPersistentStorage()
        if (!cancelled) setStoragePersisted(persisted)
        const lock = createLock()
        const keys = new IdbKeyStore()
        const sentinel = createSentinel()
        const sessions = new IdbSessionStore()
        const contactStore = new ContactStore(keys, lock)
        storesRef.current = { keys, lock, sentinel, sessions, contacts: contactStore }
        const boot = await bootstrapIdentity(keys, sentinel, lock)
        if (cancelled) return
        if (boot.state === 'evicted-needs-restore' || !boot.identity) {
          setPhase('evicted')
          return
        }
        const id = boot.identity
        const prekeys = new PrekeyStore(keys, lock)
        const client = new NightjarClient(id, sessions, prekeys, contactStore, lock, {
          onMessage: (from, text) => {
            appendMessage(from, { id: uid(), dir: 'in', text, ts: Date.now() })
            void client.listContacts().then(setContacts)
          },
          onError: (detail) => setNotice(detail),
          onSecurity: (detail) => setSecurityNotices((prev) => (prev.includes(detail) ? prev : [...prev, detail])),
          // A queued message was permanently rejected: mark that exact bubble
          // failed (envelope id == message id) so it never reads as delivered.
          onSendFailed: (envId, reason) => {
            setConversations((prev) => {
              const next: Record<string, Message[]> = {}
              for (const [p, msgs] of Object.entries(prev)) {
                next[p] = msgs.map((m) => (m.id === envId ? { ...m, failed: true } : m))
              }
              return next
            })
            setNotice(`a message could not be delivered (${reason})`)
          },
          // Fires on every drop AND every automatic reconnect: keep the UI's
          // connected dot honest, and re-run the connect-time side band
          // (presence, push freshness, a still-pending restore) after a heal.
          onConnection: (up) => {
            if (cancelled) return
            setConnected(up)
            if (!up) return
            client.sendPresence(document.visibilityState === 'visible')
            if (client.pushKey && notifyPref() && notifyPermission() === 'granted') {
              void subscribePush(client.pushKey)
                .then((sub) => sub && client.subscribePush(sub))
                .catch(() => {})
            }
            void completeRestoreIfPending(client, keys)
            // Recover a stale terminal 'error' phase: if the FIRST connect failed
            // (boot catch set phase='error') but a later reconnect succeeded, the
            // client is live and must not be stranded behind the error screen.
            setRegistered(client.isRegistered)
            void client.listContacts().then(setContacts).catch(() => {})
            setPhase((prev) => (prev === 'error' ? (client.isRegistered ? 'ready' : 'onboarding') : prev))
          },
        })
        liveRef.current = { client, identity: id }
        setIdentity(id)

        const authed = await client.connect()
        if (cancelled) return
        setConnected(true)
        setRegistered(authed.registered)

        // Await the pending-restore fixup BEFORE 'ready' so the window where
        // the Directory still serves dead prekeys stays as small as one
        // round-trip. onConnection(true) already started it during connect();
        // this joins the same deduplicated promise.
        if (authed.registered) await completeRestoreIfPending(client, keys)
        if (cancelled) return
        setContacts(await client.listContacts())
        setPhase(authed.registered ? 'ready' : 'onboarding')

        // Web Push (P6). Record the relay's key for the UI, and if this device
        // already opted in (and still holds permission), silently re-subscribe so
        // the relay's stored subscription stays fresh across reconnects.
        pushKeyRef.current = authed.pushKey
        refreshNotify()
        if (authed.pushKey && notifyPref() && notifyPermission() === 'granted') {
          void subscribePush(authed.pushKey)
            .then((sub) => sub && client.subscribePush(sub))
            .catch(() => {})
        }

        // Presence: re-affirm foreground state while visible (a heartbeat so a
        // slept/backgrounded socket goes stale and the relay pushes instead), and
        // clear stale nudges when the app is brought to the foreground.
        const beat = () => {
          if (document.visibilityState === 'visible') client.sendPresence(true)
        }
        const onVisibility = () => {
          const visible = document.visibilityState === 'visible'
          client.sendPresence(visible)
          if (visible) {
            void clearNotifications()
            client.reconnectNow() // a backgrounded tab's socket often died quietly
          }
        }
        const onOnline = () => client.reconnectNow()
        heartbeatRef.current = window.setInterval(beat, PRESENCE_HEARTBEAT_MS)
        document.addEventListener('visibilitychange', onVisibility)
        window.addEventListener('online', onOnline)
        visHandlerRef.current = () => {
          document.removeEventListener('visibilitychange', onVisibility)
          window.removeEventListener('online', onOnline)
        }
        void clearNotifications() // the app is open now; drop any prior nudge
      } catch (e) {
        if (cancelled) return
        setError(String(e instanceof Error ? e.message : e))
        setPhase('error')
      }
    })()

    return () => {
      cancelled = true
      if (heartbeatRef.current !== null) window.clearInterval(heartbeatRef.current)
      heartbeatRef.current = null
      visHandlerRef.current?.()
      visHandlerRef.current = null
      liveRef.current?.client.close()
      liveRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const join = useCallback(
    async (input: string) => {
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
    },
    [],
  )

  const send = useCallback(
    async (peer: string, text: string) => {
      const live = liveRef.current
      if (!live || !text.trim()) return
      // Reject over-long text up front: the relay caps ciphertext at 64 KiB, and
      // a rejection there advances the ratchet before failing. This keeps a
      // normal user well under that with a clear message instead of a silent drop.
      if (text.length > MAX_MESSAGE_CHARS) {
        setNotice(`message is too long (limit ${MAX_MESSAGE_CHARS.toLocaleString()} characters)`)
        return
      }
      const msgId = uid()
      appendMessage(peer, { id: msgId, dir: 'out', text, ts: Date.now() })
      try {
        // Pass msgId so the envelope id equals this bubble's id; a later async
        // permanent rejection (onSendFailed) can then mark this exact bubble.
        await live.client.sendText(peer, text, msgId)
        setContacts(await live.client.listContacts())
      } catch (e) {
        // The optimistic bubble must never read as delivered: flag it failed.
        setConversations((prev) => ({
          ...prev,
          [peer]: (prev[peer] ?? []).map((m) => (m.id === msgId ? { ...m, failed: true } : m)),
        }))
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
    [appendMessage],
  )

  const startChat = useCallback((peer: string) => {
    setConversations((prev) => (prev[peer] ? prev : { ...prev, [peer]: [] }))
  }, [])

  // Open a chat from a scanned/pasted value (registered user). Accepts either a
  // bare userId (start a trust-on-first-use chat) or an invite artifact (pin the
  // inviter, then chat with them). Returns the peer id to select, or null.
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
      // Pin the inviter as an invite-trusted contact (6.3), then open the chat.
      await live.client.addInviteContact(id)
      setContacts(await live.client.listContacts())
      setNotice('contact added and pinned')
    } catch (e) {
      // The contact can still be messaged (TOFU) even if the pin fetch failed.
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

  const markVerified = useCallback(async (peer: string) => {
    const live = liveRef.current
    if (!live) return
    try {
      await live.client.markVerified(peer)
      setContacts(await live.client.listContacts())
    } catch (e) {
      // Never let a failed trust upgrade look like it silently succeeded.
      setNotice(`could not save the verification: ${String(e instanceof Error ? e.message : e)}`)
    }
  }, [])

  const dismissSecurityNotice = useCallback((detail: string) => {
    setSecurityNotices((prev) => prev.filter((d) => d !== detail))
  }, [])

  const dismissNotice = useCallback(() => setNotice(null), [])

  // Restore this device from a backup file (P8). Available from the evicted
  // screen and from onboarding (where it replaces the freshly generated,
  // never-registered identity). Ends in a full reload: a clean re-bootstrap is
  // the only supported path into a restored identity.
  const restoreFromBackup = useCallback(async (file: File, passphrase: string) => {
    const stores = storesRef.current
    if (!stores) return
    setRestoreBusy(true)
    setRestoreError(null)
    try {
      const blob = new Uint8Array(await file.arrayBuffer())
      parseBackupHeader(blob) // cheap format/bounds errors surface before the slow KDF
      const opened = await openBackup(blob, passphrase, { kdf: createBackupKdf() })
      liveRef.current?.client.close()
      await stageRestore(
        { keys: stores.keys, sessions: stores.sessions, contacts: stores.contacts, sentinel: stores.sentinel, lock: stores.lock },
        opened.payload,
      )
      globalThis.location.reload()
    } catch (e) {
      setRestoreError(e instanceof Error ? e.message : String(e))
      setRestoreBusy(false)
    }
  }, [])

  // Seal and download a backup of the identity + contact trust (P8). Returns
  // true on success so the panel can show its written-down confirmation step.
  const exportBackup = useCallback(async (passphrase: string): Promise<boolean> => {
    const live = liveRef.current
    if (!live) return false
    try {
      const contacts = await live.client.listContacts()
      const blob = await sealBackup(live.identity, contacts, passphrase, { kdf: createBackupKdf() })
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

  // Turn notifications ON for this device: request permission (only here, never
  // automatically), subscribe with the relay's VAPID key, and register the
  // subscription with the relay over the authed socket.
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
      // subscribePush honours a null-on-failure contract, so this is only a
      // defensive backstop; never leave the tap as a silent unhandled rejection.
      setNotice('could not turn on notifications')
    }
    refreshNotify()
  }, [refreshNotify])

  // Turn notifications OFF: unsubscribe the browser and drop it from the relay.
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
    conversations,
    prefillInvite,
    notify,
    restoreBusy,
    restoreError,
    storagePersisted,
    actions: {
      join,
      send,
      startChat,
      openFromCode,
      mintInvite,
      markVerified,
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
