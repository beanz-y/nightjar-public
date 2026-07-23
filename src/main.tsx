import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { registerServiceWorker } from './platform/webpush'
import './styles.css'

// Keep the app exactly as tall as the VISIBLE viewport, so the compose bar is
// always on screen on mobile. `visualViewport.height` shrinks when the on-screen
// keyboard opens (and excludes the browser chrome), which `100vh`/`100dvh` do
// not, so a CSS-only height leaves the compose bar behind the keyboard. The root
// reads this via `height: var(--app-height)`. Desktop just tracks innerHeight.
function trackAppHeight(): void {
  const vv = globalThis.visualViewport
  const set = () => {
    const h = Math.round(vv?.height ?? globalThis.innerHeight)
    document.documentElement.style.setProperty('--app-height', `${h}px`)
  }
  set()
  vv?.addEventListener('resize', set)
  vv?.addEventListener('scroll', set)
  globalThis.addEventListener('orientationchange', set)
}
trackAppHeight()

// Best-effort portrait lock for the installed PWA. The manifest `orientation` field
// only binds when the install created a WebAPK, which needs Google Play Services; on
// de-Googled Android (e.g. GrapheneOS with Vanadium) an install is a home-screen
// shortcut with no WebAPK, so the OS never enforces the manifest orientation. The
// Screen Orientation API locks it at runtime in standalone display mode instead. It
// rejects in a plain browser tab and is unsupported on iOS (Apple exposes no web
// orientation lock at all), so it is fully guarded and best-effort. Re-asserted on
// return to the foreground in case the lock is dropped while backgrounded.
function lockPortrait(): void {
  try {
    const orientation = globalThis.screen?.orientation as
      | (ScreenOrientation & { lock?: (o: string) => Promise<void> })
      | undefined
    if (!orientation || typeof orientation.lock !== 'function') return
    void orientation.lock('portrait').catch(() => {
      /* not a lockable context (browser tab), or unsupported (iOS) */
    })
  } catch {
    /* older engines throw synchronously outside a lockable context */
  }
}
lockPortrait()
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') lockPortrait()
})

const root = document.getElementById('root')
if (!root) throw new Error('missing #root')
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

// Register the service worker for PWA install + Web Push (P6). Idempotent and
// independent of whether the user has opted into notifications.
void registerServiceWorker()
