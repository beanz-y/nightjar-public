// Nightjar service worker (P6, DESIGN 7.4). Two jobs: make the app installable
// (Home Screen, which iOS REQUIRES for Web Push) and show a CONTENT-FREE nudge
// when a push arrives for a closed or backgrounded app.
//
// It deliberately does NOT cache app assets. A security app must always run the
// latest deployed bundle: a stale cached client is exactly what the
// reproducible-build + release-hash hardening (DESIGN 10) exists to make loud,
// and the app is live-only anyway (a WebSocket to a Durable Object; a stale
// client could not talk to the current relay). The navigate-passthrough fetch
// handler exists only so browsers recognise a functional service worker.
//
// CSP: the strict policy in public/_headers has no worker-src, so the service
// worker is permitted by `default-src 'self'` (the terminal fallback); the sw.js
// script and every asset it references are same-origin.

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()))

self.addEventListener('fetch', (event) => {
  if (event.request.mode === 'navigate') event.respondWith(fetch(event.request))
})

// A push from the relay: the app is closed or backgrounded, so this service
// worker is the only thing of ours still running. event.data is IGNORED
// entirely: the notification is a fixed, content-free nudge, so nothing
// message-derived (plaintext, ciphertext, sender id, envelope id) can ever reach
// a lockscreen, regardless of what any server sent. userVisibleOnly is the
// subscription contract, so every push MUST show a notification (iOS cancels a
// subscription after three silent pushes). A shared tag + renotify coalesces a
// burst of pushes into one notification that still re-alerts.
self.addEventListener('push', (event) => {
  event.waitUntil(
    self.registration.showNotification('Nightjar', {
      body: 'New secure message',
      tag: 'nightjar-msg',
      renotify: true,
      icon: '/icon-192.png',
      badge: '/badge-96.png',
      data: { url: '/' },
    }),
  )
})

// Tapping the nudge focuses the app, or opens it if nothing is running.
self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) if ('focus' in c) return c.focus()
      return self.clients.openWindow('/')
    }),
  )
})
