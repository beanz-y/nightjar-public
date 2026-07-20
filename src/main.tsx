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
