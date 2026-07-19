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
import { IdbKeyStore } from '../storage/keystore'
import { bootstrapIdentity } from '../storage/identityStore'
import { IdbSessionStore } from '../storage/sessionStore'
import { createLock } from '../storage/lock'
import { createSentinel, requestPersistentStorage } from '../storage/persist'
import { PrekeyStore } from '../storage/prekeyStore'
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

const uid = () => (globalThis.crypto?.randomUUID?.() ?? `m-${Math.random().toString(36).slice(2)}`)
const appOrigin = () => globalThis.location?.origin || getRelayOrigin()

// Derive the notifications UI state from the platform + the relay's push key.
// The toggle is `available` only when the browser supports push, the relay has a
// VAPID key, and (on iOS) the app is installed to the Home Screen (iOS refuses
// permission/subscribe in a plain Safari tab; red-team H5).
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
  const [identity, setIdentity] = useState<Identity | null>(null)
  const [connected, setConnected] = useState(false)
  const [registered, setRegistered] = useState(false)
  const [contacts, setContacts] = useState<Contact[]>([])
  const [conversations, setConversations] = useState<Record<string, Message[]>>({})
  const [prefillInvite, setPrefillInvite] = useState<string>('')
  const [notify, setNotify] = useState<NotifyState>(() => computeNotify(null))

  const liveRef = useRef<Live | null>(null)
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

  useEffect(() => {
    let cancelled = false
    // Prefill the invite box from a deep link (…/#i=CODE.inviter).
    const hash = globalThis.location?.hash ?? ''
    const m = hash.match(/[#?&]i=([^#?&\s]+)/)
    if (m) setPrefillInvite(decodeURIComponent(m[1]))

    void (async () => {
      try {
        await requestPersistentStorage()
        const lock = createLock()
        const keys = new IdbKeyStore()
        const boot = await bootstrapIdentity(keys, createSentinel(), lock)
        if (cancelled) return
        if (boot.state === 'evicted-needs-restore' || !boot.identity) {
          setPhase('evicted')
          return
        }
        const id = boot.identity
        const prekeys = new PrekeyStore(keys, lock)
        const contacts = new ContactStore(keys, lock)
        const client = new NightjarClient(id, new IdbSessionStore(), prekeys, contacts, lock, {
          onMessage: (from, text) => {
            appendMessage(from, { id: uid(), dir: 'in', text, ts: Date.now() })
            void client.listContacts().then(setContacts)
          },
          onError: (detail) => setNotice(detail),
        })
        liveRef.current = { client, identity: id }
        setIdentity(id)

        const authed = await client.connect()
        if (cancelled) return
        setConnected(true)
        setRegistered(authed.registered)
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
          if (visible) void clearNotifications()
        }
        heartbeatRef.current = window.setInterval(beat, PRESENCE_HEARTBEAT_MS)
        document.addEventListener('visibilitychange', onVisibility)
        visHandlerRef.current = onVisibility
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
      if (visHandlerRef.current) document.removeEventListener('visibilitychange', visHandlerRef.current)
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
      appendMessage(peer, { id: uid(), dir: 'out', text, ts: Date.now() })
      try {
        await live.client.sendText(peer, text)
        setContacts(await live.client.listContacts())
      } catch (e) {
        setNotice(`send failed: ${String(e instanceof Error ? e.message : e)}`)
      }
    },
    [appendMessage],
  )

  const startChat = useCallback((peer: string) => {
    setConversations((prev) => (prev[peer] ? prev : { ...prev, [peer]: [] }))
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
    await live.client.markVerified(peer)
    setContacts(await live.client.listContacts())
  }, [])

  const dismissNotice = useCallback(() => setNotice(null), [])

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
    identity,
    connected,
    registered,
    contacts,
    conversations,
    prefillInvite,
    notify,
    actions: {
      join,
      send,
      startChat,
      mintInvite,
      markVerified,
      dismissNotice,
      listContacts,
      enableNotifications,
      disableNotifications,
    },
  }
}
