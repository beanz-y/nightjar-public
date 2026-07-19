import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { registerServiceWorker } from './platform/webpush'
import './styles.css'

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
