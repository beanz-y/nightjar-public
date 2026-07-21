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
import { bytesToHex } from '@noble/hashes/utils'
import { newMsgId } from '../crypto/message'
import { createBackupKdf } from '../platform/backupKdf'
import { AppLockStore, type EnrollMethod } from '../storage/appLockStore'
import { IdbKeyStore, type KeyStore } from '../storage/keystore'
import { HistoryStore } from '../storage/historyStore'
import { bootstrapIdentity } from '../storage/identityStore'
import { IdbSessionStore } from '../storage/sessionStore'
import { type Lock, createLock } from '../storage/lock'
import { type Sentinel, createSentinel, requestPersistentStorage } from '../storage/persist'
import { PrekeyStore } from '../storage/prekeyStore'
import { type BackupPayload } from '../crypto/backup'
import { clearPendingRestore, pendingRestore, stageRestoreEnrolled } from '../storage/restore'
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
    out[peer] = msgs.map((m) =>
      m.failed ? { id: m.id, dir: m.dir, text: m.text, ts: m.ts, failed: true } : { id: m.id, dir: m.dir, text: m.text, ts: m.ts },
    )
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

const MAX_MESSAGE_CHARS = 8000
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

  const liveRef = useRef<Live | null>(null)
  const storesRef = useRef<Stores | null>(null)
  const idRef = useRef<Identity | null>(null)
  const mountedRef = useRef(true)
  const restoreFixupRef = useRef<Promise<void> | null>(null)
  const restorePayloadRef = useRef<BackupPayload | null>(null)
  const pushKeyRef = useRef<string | null>(null)
  const teardownRef = useRef<(() => void) | null>(null)
  const lockNowRef = useRef<() => void>(() => {})

  const refreshNotify = useCallback(() => setNotify(computeNotify(pushKeyRef.current)), [])

  const listContacts = useCallback(async () => {
    const live = liveRef.current
    if (!live) return
    setContacts(await live.client.listContacts())
  }, [])

  const appendMessage = useCallback((peer: string, m: Message) => {
    setConversations((prev) => {
      const cur = prev[peer] ?? []
      if (cur.some((x) => x.id === m.id)) return prev
      return { ...prev, [peer]: [...cur, m] }
    })
  }, [])

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
      const prekeys = new PrekeyStore(stores.keys, stores.lock)
      const client = new NightjarClient(
        id,
        stores.sessions,
        prekeys,
        stores.contacts,
        stores.lock,
        {
          onMessage: (from, msg) => {
            appendMessage(from, { id: msg.id, dir: 'in', text: msg.text, ts: msg.ts, ...(msg.ephemeral ? { ephemeral: true } : {}) })
            void client.listContacts().then(setContacts).catch(() => {})
          },
          onDelete: (from, id) => {
            // Delete-for-everyone from a peer (P10d): drop the bubble. The stored
            // row was already removed atomically inside the client.
            setConversations((prev) => ({ ...prev, [from]: (prev[from] ?? []).filter((m) => m.id !== id) }))
          },
          onError: (detail) => setNotice(detail),
          onSecurity: (detail) => setSecurityNotices((prev) => (prev.includes(detail) ? prev : [...prev, detail])),
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
            void client.listContacts().then(setContacts).catch(() => {})
            setPhase((prev) => (prev === 'error' ? (client.isRegistered ? 'ready' : 'onboarding') : prev))
          },
        },
        stores.history,
      )
      liveRef.current = { client, identity: id }
      setIdentity(id)

      const authed = await client.connect()
      if (!mountedRef.current) return
      setConnected(true)
      setRegistered(authed.registered)
      if (authed.registered) await completeRestoreIfPending(client, stores.keys)
      if (!mountedRef.current) return
      setContacts(await client.listContacts())
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
  }, [appendMessage, completeRestoreIfPending, refreshNotify])

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
      // History AND contacts/pending/aliases are sealed under the Local Data Key
      // being discarded here, so they are unrecoverable ciphertext now and must be
      // cleared (else a re-enrolled lock's new LDK cannot open them and the app
      // fails to start). The identity survives (it is not under the lock); contacts
      // can be recovered from a backup.
      await stores.sessions.historyClear()
      await stores.contacts.wipeLocalData()
      await stores.appLock.reset()
    } catch {
      /* best-effort */
    }
    setConversations({})
    setContacts([])
    setAliases({})
    restorePayloadRef.current = null
    setRestorePending(false)
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
      // visible), even before delivery resolves.
      appendMessage(peer, { id: msgId, dir: 'out', text, ts, ...(ephemeral ? { ephemeral: true } : {}) })
      try {
        await live.client.sendText(peer, text, msgId, ts, ephemeral)
        setContacts(await live.client.listContacts())
      } catch (e) {
        setConversations((prev) => ({
          ...prev,
          [peer]: (prev[peer] ?? []).map((mm) => (mm.id === msgId ? { ...mm, failed: true } : mm)),
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

  // Delete-for-everyone a message YOU sent (P10d). Optimistically removes the
  // bubble, then asks the client to remove the local copy and (if delivered) ask
  // the peer to remove it too. Honest copy: never claims a guaranteed deletion.
  const deleteMessage = useCallback(async (peer: string, id: string, failed?: boolean) => {
    const live = liveRef.current
    if (!live) return
    setConversations((prev) => ({ ...prev, [peer]: (prev[peer] ?? []).filter((m) => m.id !== id) }))
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
  }, [])

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
    actions: {
      enrollLock,
      makeBiometricMethod,
      unlock,
      unlockWithBiometric,
      lockNow,
      resetLock,
      join,
      send,
      deleteMessage,
      startChat,
      openFromCode,
      renameChat,
      mintInvite,
      markVerified,
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
