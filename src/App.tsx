// Nightjar app shell. Bootstrap identity -> connect -> onboarding (invite/scan or
// restore) -> the messenger. When registered, the whole surface is the chat app
// (Messenger owns the list, conversations, new-chat, and settings). A dismissible
// warrant-canary banner appears on an alarming canary state; the compact footer
// (version + verify-build + diagnostics) is only shown before the messenger takes
// over, so it never clutters the chat surface.

import { useState } from 'react'
import { About } from './ui/About'
import { AppLockScreen } from './ui/AppLockScreen'
import { Diagnostics } from './ui/Diagnostics'
import { Messenger } from './ui/Messenger'
import { Onboarding } from './ui/Onboarding'
import { RestoreScreen } from './ui/RestoreScreen'
import { useCanary } from './ui/useCanary'
import { useNightjar } from './ui/useNightjar'

export function App() {
  const {
    phase,
    error,
    notice,
    securityNotices,
    identity,
    accountIkSigPub,
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
    removedPeer,
    moveExported,
    moveProgress,
    linkState,
    historyProgress,
    actions,
  } = useNightjar()
  const canary = useCanary()
  const [diag, setDiag] = useState(false)
  const [about, setAbout] = useState(false)
  const [canaryDismissed, setCanaryDismissed] = useState(false)

  // The self-tests register throwaway identities against the LIVE directory and
  // burn a real invite each run, so they are dev-only unless explicitly asked
  // for with #diag (e.g. when verifying a production deploy on purpose).
  const diagAvailable = import.meta.env.DEV || (globalThis.location?.hash ?? '').includes('diag')

  const isReady = phase === 'ready' && !!identity && registered
  /** Nothing that could name a contact renders while the app is behind its lock. */
  const locked = phase === 'locked' || phase === 'enroll'
  const showCanaryBanner = !!canary?.alarming && !canaryDismissed && !about

  return (
    <div className="root">
      <header className="topbar">
        <span className="wordmark">Nightjar</span>
        <span className={`dot ${connected ? 'dot-on' : 'dot-off'}`} title={connected ? 'connected' : 'offline'} />
      </header>

      {/* Not on the lock or enroll screens. A security notice names a peer by the
          first 12 characters of their user id, which is plenty to confirm a guess,
          and these banners are sticky. Rendering them above a LOCKED app puts that
          identifier on the screen of a device someone just picked up, without the
          unlock secret: the exact at-rest exposure the app-lock exists to prevent.
          They stay in state and reappear after unlock. */}
      {!locked &&
        securityNotices.map((d) => (
          <div className="banner banner-alert" role="alert" key={d}>
            <span className="small">
              <strong>security: </strong>
              {d}
            </span>
            <button className="link" onClick={() => actions.dismissSecurityNotice(d)}>
              dismiss
            </button>
          </div>
        ))}

      {/* `notice` is deliberately NOT gated: it never carries a peer id (the two
          inbound paths that once did had them removed), and the app-lock reset says
          what a reset just cost on the enroll screen that follows it. */}
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

      <div className={`content ${isReady && !about ? 'content-app' : ''}`}>
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
              <RestoreScreen mode="evicted" busy={restoreBusy} error={restoreError} onRestore={actions.restoreFromBackup} />
            )}

            {(phase === 'enroll' || phase === 'locked') && (
              <AppLockScreen
                mode={phase === 'enroll' ? 'enroll' : 'unlock'}
                restoring={restorePending}
                bioAvailable={bioAvailable}
                lockMethods={lockMethods}
                onEnroll={actions.enrollLock}
                makeBiometric={actions.makeBiometricMethod}
                onUnlock={actions.unlock}
                onUnlockBiometric={actions.unlockWithBiometric}
                onReset={actions.resetLock}
              />
            )}

            {phase === 'onboarding' && identity && (
              <Onboarding
                userId={identity.userId}
                prefill={prefillInvite}
                connected={connected}
                restoreBusy={restoreBusy}
                restoreError={restoreError}
                linkState={linkState}
                onJoin={actions.join}
                onRestore={actions.restoreFromBackup}
                onStartLinking={actions.startLinking}
                onCancelLinking={actions.cancelLinking}
                onLinkTransfer={actions.openOpticalLink}
                onAbout={() => setAbout(true)}
              />
            )}

            {isReady && identity && (
              <Messenger
                accountIkSigPub={accountIkSigPub ?? identity.ikSig.publicKey}
                connected={connected}
                removedPeer={removedPeer}
                contacts={contacts}
                aliases={aliases}
                conversations={conversations}
                notify={notify}
                storagePersisted={storagePersisted}
                canary={canary}
                bioAvailable={bioAvailable}
                lockMethods={lockMethods}
                moveExported={moveExported}
                moveProgress={moveProgress}
                historyProgress={historyProgress}
                actions={actions}
              />
            )}
          </>
        )}
      </div>

      {/* The chat app owns its own chrome (settings holds verify-build); the
          footer is only for the pre-messenger phases and #diag tooling. */}
      {(!isReady || about) && (
        <footer className="foot muted small">
          <span>Nightjar {__APP_VERSION__}</span>
          <span className="row">
            <button className="link" onClick={() => setAbout((a) => !a)}>
              {about ? 'close about' : 'verify build'}
            </button>
            {diagAvailable && (
              <button className="link" onClick={() => setDiag((d) => !d)}>
                {diag ? 'hide diagnostics' : 'diagnostics'}
              </button>
            )}
          </span>
        </footer>
      )}
      {diag && diagAvailable && <Diagnostics />}
    </div>
  )
}
