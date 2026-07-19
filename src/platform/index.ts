// Platform seams (DESIGN 10.5). To keep the native (Tauri) door open for near
// zero cost later, the three things that diverge between a web PWA and a native
// build are kept behind interfaces from day one:
//   1. push / notifications
//   2. key / secret storage (see ../storage/keystore.ts: KeyStore)
//   3. the network / transport origin (below)
// No absolute origin is hardcoded anywhere else in the app.

/** The relay origin, from config, defaulting to the page's own origin. A native
 *  build injects its configured relay here instead. */
export function getRelayOrigin(): string {
  const configured = import.meta.env.VITE_RELAY_ORIGIN
  if (configured && configured.length > 0) return configured
  return globalThis.location?.origin ?? ''
}

/** Notification/push seam. The web PWA implements this with the Web Push +
 *  service-worker path (P6); a native build implements it with UnifiedPush or
 *  OS notifications. Only the interface exists at P0. */
export interface Notifier {
  /** Ask the platform for permission to show notifications. */
  requestPermission(): Promise<'granted' | 'denied' | 'default'>
  /** Show a content-free "new secure message" nudge (DESIGN 7.4). */
  notifyNewMessage(): Promise<void>
}

/** Push-subscription transport seam (DESIGN 7.4). Implemented at P6. */
export interface PushTransport {
  /** Register for push and return an opaque subscription to hand the relay. */
  register(): Promise<PushSubscriptionInfo | null>
  unregister(): Promise<void>
}

export interface PushSubscriptionInfo {
  readonly transport: 'webpush' | 'unifiedpush' | 'apns'
  readonly endpoint: string
  readonly p256dh: string
  readonly auth: string
}
