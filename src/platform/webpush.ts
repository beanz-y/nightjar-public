// Web Push implementation of the platform notification seam (P6, DESIGN 7.4).
// The native (Tauri/UnifiedPush) door in platform/index.ts stays open; this is
// the PWA half. It owns the browser-side subscription lifecycle only: the actual
// content-free push is sent by the relay (worker/push.ts), and the notification
// is shown by the service worker (public/sw.js), which never reads the payload.
//
// Opt-in is per device, stored locally (a UI preference, not a secret), and push
// is never enabled without an explicit user action (we never auto-prompt for
// notification permission).

import type { PushSubscriptionInfo } from './index'

const NOTIFY_PREF_KEY = 'nightjar.notify'
const SW_URL = '/sw.js'
const NOTIF_TAG = 'nightjar-msg'

/** Does this browser support the Web Push stack at all? */
export function pushSupported(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    'serviceWorker' in navigator &&
    typeof window !== 'undefined' &&
    'PushManager' in window &&
    'Notification' in window
  )
}

/** True when running as an installed (Home Screen / standalone) app. iOS only
 *  permits Notification permission + push subscription inside the installed
 *  instance, so the UI gates the toggle on this for iOS (red-team H5). */
export function isStandalone(): boolean {
  if (typeof window === 'undefined') return false
  const displayMode = window.matchMedia?.('(display-mode: standalone)').matches ?? false
  const iosStandalone = (navigator as unknown as { standalone?: boolean }).standalone === true
  return displayMode || iosStandalone
}

/** Rough iOS/iPadOS detection, for the install-first onboarding copy. */
export function isIos(): boolean {
  if (typeof navigator === 'undefined') return false
  const ua = navigator.userAgent || ''
  return /iphone|ipad|ipod/i.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)
}

export function notifyPermission(): NotificationPermission {
  return typeof Notification !== 'undefined' ? Notification.permission : 'denied'
}

/** The per-device opt-in flag (a UI preference). */
export function notifyPref(): boolean {
  try {
    return localStorage.getItem(NOTIFY_PREF_KEY) === '1'
  } catch {
    return false
  }
}
function setNotifyPref(on: boolean): void {
  try {
    if (on) localStorage.setItem(NOTIFY_PREF_KEY, '1')
    else localStorage.removeItem(NOTIFY_PREF_KEY)
  } catch {
    /* storage disabled (private mode); push just won't persist its opt-in */
  }
}

/** Register the service worker (needed for install + push). Safe to call on
 *  every load; the browser dedupes. Returns null if unsupported or it failed. */
export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return null
  try {
    return await navigator.serviceWorker.register(SW_URL)
  } catch {
    return null
  }
}

/** Ask for notification permission, only when the user explicitly opted in. */
export async function requestNotifyPermission(): Promise<NotificationPermission> {
  if (typeof Notification === 'undefined') return 'denied'
  if (Notification.permission !== 'default') return Notification.permission
  try {
    return await Notification.requestPermission()
  } catch {
    return 'denied'
  }
}

function urlB64ToBytes(b64url: string): Uint8Array<ArrayBuffer> {
  const pad = '='.repeat((4 - (b64url.length % 4)) % 4)
  const base = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/')
  const raw = atob(base)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out
}

function keyToB64url(buf: ArrayBuffer | null): string {
  if (!buf) return ''
  let s = ''
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// navigator.serviceWorker.ready never rejects and waits INDEFINITELY for an
// active worker, so a failed/absent registration would otherwise hang the enable
// flow forever. Bound it: return null past the timeout.
function swReady(timeoutMs = 5000): Promise<ServiceWorkerRegistration | null> {
  const timeout = new Promise<null>((resolve) => window.setTimeout(() => resolve(null), timeoutMs))
  return Promise.race([navigator.serviceWorker.ready, timeout])
}

/** Subscribe this device for push with the relay's VAPID application-server key.
 *  Re-subscribes only if an existing subscription reports a DIFFERENT key (a
 *  rotated VAPID secret). Returns the subscription split into the fields the
 *  relay stores, or null on failure / missing permission (never rejects, so the
 *  caller can show its own "could not subscribe" notice). Records the opt-in. */
export async function subscribePush(pushKey: string): Promise<PushSubscriptionInfo | null> {
  if (!pushSupported() || notifyPermission() !== 'granted') return null
  try {
    const reg = await swReady()
    if (!reg) return null
    const desired = urlB64ToBytes(pushKey)
    let sub = await reg.pushManager.getSubscription()
    if (sub) {
      // A browser may report null for applicationServerKey (spec-permitted); that
      // is NOT a key change, so keep the existing subscription rather than churn a
      // needless unsubscribe/resubscribe (which would also strand a stale row on
      // the relay) on every reconnect. Only a DIFFERENT non-null key is a rotation.
      const raw = sub.options.applicationServerKey
      const cur = raw ? new Uint8Array(raw) : null
      const same = !cur || (cur.length === desired.length && cur.every((b, i) => b === desired[i]))
      if (!same) {
        try {
          await sub.unsubscribe()
        } catch {
          /* already gone */
        }
        sub = null
      }
    }
    if (!sub) {
      sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: desired })
    }
    const p256dh = keyToB64url(sub.getKey('p256dh'))
    const auth = keyToB64url(sub.getKey('auth'))
    if (!p256dh || !auth) return null
    setNotifyPref(true)
    return { transport: 'webpush', endpoint: sub.endpoint, p256dh, auth }
  } catch {
    // pushManager.subscribe() can reject (permission race, push service
    // unreachable, malformed key). Honour the null-on-failure contract.
    return null
  }
}

/** Unsubscribe this device (also clears the opt-in). Returns the endpoint that
 *  was removed, so the caller can drop it from the relay too, or null. */
export async function unsubscribePush(): Promise<string | null> {
  setNotifyPref(false)
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return null
  try {
    const reg = await navigator.serviceWorker.getRegistration()
    const sub = reg ? await reg.pushManager.getSubscription() : null
    if (!sub) return null
    const endpoint = sub.endpoint
    await sub.unsubscribe()
    return endpoint
  } catch {
    return null
  }
}

/** Clear any outstanding content-free nudges. Called when the app becomes
 *  visible: the message is now on screen or draining, so the nudge is moot, and
 *  clearing only on visibility avoids racing an in-flight push (red-team M3). */
export async function clearNotifications(): Promise<void> {
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return
  try {
    const reg = await navigator.serviceWorker.getRegistration()
    if (reg?.getNotifications) {
      const notes = await reg.getNotifications({ tag: NOTIF_TAG })
      for (const n of notes) n.close()
    }
  } catch {
    /* best-effort */
  }
}
