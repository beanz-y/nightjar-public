// About + "verify this build" (P7, DESIGN 10.3/10.4). Surfaces the release version
// and the warrant-canary status, explains how a technical friend actually verifies
// the build, and carries the plain-language disclosure. Text only, never innerHTML.
//
// Honesty rules baked in (MF4, do not soften):
//  - No SafetyNumber-style green check for any canary state. Each state is a
//    freshness/authorship FACT, not a build-integrity verdict.
//  - State plainly that this indicator cannot detect backdoored code and buys
//    nothing against an attack aimed at one person; the real protection is
//    verifying safety numbers in person.

import type { CanaryResult, CanaryStatus } from '../verify/canary'

// A short neutral label + a visual tone per status. Deliberately NOT a checkmark.
const LABEL: Record<CanaryStatus, string> = {
  ok: 'signed recently',
  aging: 'signed a while ago',
  stale: 'not refreshed lately',
  absent: 'removed',
  invalid: 'did not verify',
  'version-mismatch': 'for a different release',
  unreachable: 'could not check',
  unconfigured: 'not configured yet',
}
const TONE: Record<CanaryStatus, 'warn' | 'note' | 'quiet'> = {
  ok: 'note',
  aging: 'note',
  stale: 'warn',
  absent: 'warn',
  invalid: 'warn',
  'version-mismatch': 'note',
  unreachable: 'quiet',
  unconfigured: 'quiet',
}

// The canary demonstrably exists (a signature verified) in these states, so the
// present-tense "reproducible + logged" claim is honest; otherwise the copy says
// the machinery is being brought online (runtime-gated hedge, a P7 should-fix).
const LIVE: CanaryStatus[] = ['ok', 'aging', 'stale']

interface Props {
  canary: CanaryResult | null
  onBack: () => void
}

export function About({ canary, onBack }: Props) {
  const live = !!canary && LIVE.includes(canary.status)

  return (
    <section className="about">
      <button className="link" onClick={onBack}>
        ← back
      </button>
      <h2 className="accent">About &amp; verify this build</h2>

      <div className="field-label small muted">this build</div>
      <p className="mono break">{__APP_VERSION__}</p>

      <div className="field-label small muted">operator canary</div>
      {canary ? (
        <div className={`canary canary-${TONE[canary.status]}`}>
          <div className="canary-label small">{LABEL[canary.status]}</div>
          <p className="small">{canary.detail}</p>
          {canary.attestsHash && (
            <p className="tiny muted mono break">
              vouches for {canary.attestsVersion} · {canary.attestsHash.slice(0, 16)}…
            </p>
          )}
        </div>
      ) : (
        <p className="muted small">checking…</p>
      )}
      <p className="tiny muted">
        This canary only catches a bad build served to everyone. It catches nothing served to just you, and it cannot
        detect backdoored code (the code that checks it is itself served by the operator). The strongest thing you can do
        is verify your contacts' safety numbers in person.
      </p>

      <div className="field-label small muted">how to verify this build</div>
      <ol className="verify-steps small muted">
        <li>Get the public source at the signed release tag {live && canary?.attestsVersion ? canary.attestsVersion : __APP_VERSION__}.</li>
        <li>Rebuild it in the pinned container and compute the release hash with the documented recipe (see the runbook).</li>
        <li>
          Compare that hash to the one in the public transparency log (Rekor){canary?.attestsHash ? ` and to the hash this build's canary vouches for (${canary.attestsHash.slice(0, 16)}…)` : ''}.
        </li>
        <li>
          If they match, the build served to everyone matches public source. This does not prove the build served to just
          you is honest, and it does not prove the source itself is honest.
        </li>
      </ol>

      <div className="field-label small muted">the honest disclosure</div>
      <div className="disclosure small">
        <p>
          Nightjar's code is served by me, from my server, on every load. If someone compromises or compels me, I can
          serve you modified code and your browser will run it. No web app can prevent this, not Proton's, not
          Bitwarden's, not WhatsApp Web's.
        </p>
        <p>
          {live
            ? 'What I do: every release is reproducible from public source, and its hash is signed into a public append-only log I cannot delete from or backdate, so anyone can rebuild and check. That makes a change served to everyone provable after the fact.'
            : 'What I am bringing online: every release will be reproducible from public source, with its hash signed into a public append-only log I cannot delete from or backdate, so anyone can rebuild and check.'}{' '}
          It does not stop a change aimed at one person, and a determined me could serve bad code to just you.
        </p>
        <p>
          The strongest thing you can do is verify your contacts' safety numbers in person, though note even that check
          runs on code I serve. Also know: your messages' contents are private, but I can see who you talk to and when
          (not what you say). And keep a backup of your identity key, because if you lose your device without one, your
          account and history are gone.
        </p>
        <p>If your threat model includes being targeted by me, by anyone who can compel me, or by a state, use Signal.</p>
      </div>
    </section>
  )
}
