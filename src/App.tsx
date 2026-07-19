// Nightjar app shell (P5/P7). A minimal but real messenger surface over
// NightjarClient: bootstrap identity -> connect -> onboarding (invite) -> the
// registered screen. P7 adds an About/"verify this build" view (reachable from the
// footer) and a dismissible warrant-canary banner. The old proof-of-life self-tests
// live behind a diagnostics toggle.

import { useState } from 'react'
import { About } from './ui/About'
import { Diagnostics } from './ui/Diagnostics'
import { MainApp } from './ui/MainApp'
import { Onboarding } from './ui/Onboarding'
import { useCanary } from './ui/useCanary'
import { useNightjar } from './ui/useNightjar'

export function App() {
  const { phase, error, notice, identity, connected, registered, contacts, conversations, prefillInvite, notify, actions } =
    useNightjar()
  const canary = useCanary()
  const [diag, setDiag] = useState(false)
  const [about, setAbout] = useState(false)
  const [canaryDismissed, setCanaryDismissed] = useState(false)

  const showCanaryBanner = !!canary?.alarming && !canaryDismissed && !about

  return (
    <div className="root">
      <header className="topbar">
        <span className="wordmark">Nightjar</span>
        <span className={`dot ${connected ? 'dot-on' : 'dot-off'}`} title={connected ? 'connected' : 'offline'} />
      </header>

      {notice && (
        <div className="banner" role="status">
          <span className="small">{notice}</span>
          <button className="link" onClick={actions.dismissNotice}>
            dismiss
          </button>
        </div>
      )}

      {showCanaryBanner && (
        <div className="banner" role="status">
          <span className="small">{canary?.detail}</span>
          <span className="row">
            <button className="link" onClick={() => setAbout(true)}>
              verify build
            </button>
            <button className="link" onClick={() => setCanaryDismissed(true)}>
              dismiss
            </button>
          </span>
        </div>
      )}

      <div className="content">
        {about ? (
          <About canary={canary} onBack={() => setAbout(false)} />
        ) : (
          <>
            {phase === 'loading' && <p className="muted center">starting up…</p>}

            {phase === 'error' && (
              <div className="center">
                <p className="error">could not start: {error}</p>
                <button className="ghost" onClick={() => globalThis.location?.reload()}>
                  retry
                </button>
              </div>
            )}

            {phase === 'evicted' && (
              <div className="center">
                <p className="error">This device's storage was cleared, but it registered before.</p>
                <p className="muted small">
                  Restoring your identity from a passphrase backup is coming in a later build (DESIGN 8.3). Until then, a
                  cleared device needs a fresh invite.
                </p>
              </div>
            )}

            {phase === 'onboarding' && identity && (
              <Onboarding
                userId={identity.userId}
                prefill={prefillInvite}
                connected={connected}
                onJoin={actions.join}
                onAbout={() => setAbout(true)}
              />
            )}

            {phase === 'ready' && identity && registered && (
              <MainApp
                identity={identity}
                contacts={contacts}
                conversations={conversations}
                notify={notify}
                actions={actions}
              />
            )}
          </>
        )}
      </div>

      <footer className="foot muted small">
        <span>Nightjar {__APP_VERSION__} · P7 · verifiability</span>
        <span className="row">
          <button className="link" onClick={() => setAbout((a) => !a)}>
            {about ? 'close about' : 'verify build'}
          </button>
          <button className="link" onClick={() => setDiag((d) => !d)}>
            {diag ? 'hide diagnostics' : 'diagnostics'}
          </button>
        </span>
      </footer>
      {diag && <Diagnostics />}
    </div>
  )
}
