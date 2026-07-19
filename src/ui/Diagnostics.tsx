// Developer diagnostics: drives the in-page self-tests (two full clients through
// the real relay) for the relay round-trip and the P5 session-glare scenario.
// Needs a bootstrap (admin) invite, minted out of band via POST /admin/invite.

import { useState } from 'react'
import { type P4SelfTestResult, runGlareSelfTest, runP4SelfTest } from '../net/p4SelfTest'

type Kind = 'relay' | 'glare'

export function Diagnostics() {
  const [invite, setInvite] = useState('')
  const [running, setRunning] = useState<Kind | null>(null)
  const [result, setResult] = useState<{ kind: Kind; res: P4SelfTestResult } | null>(null)

  async function run(kind: Kind) {
    setRunning(kind)
    setResult(null)
    try {
      const res = kind === 'relay' ? await runP4SelfTest(invite) : await runGlareSelfTest(invite)
      setResult({ kind, res })
    } catch (e) {
      setResult({ kind, res: { ok: false, log: [String(e instanceof Error ? e.message : e)] } })
    } finally {
      setRunning(null)
    }
  }

  return (
    <section className="diag">
      <h2 className="small accent">diagnostics</h2>
      <p className="muted small">
        Runs two clients through the real relay. Paste a bootstrap invite minted with POST /admin/invite.
      </p>
      <div className="row">
        <input
          className="mono small"
          placeholder="bootstrap invite code"
          value={invite}
          onChange={(e) => setInvite(e.target.value)}
        />
        <button className="ghost small" disabled={!!running || !invite.trim()} onClick={() => void run('relay')}>
          {running === 'relay' ? 'running…' : 'relay test'}
        </button>
        <button className="ghost small" disabled={!!running || !invite.trim()} onClick={() => void run('glare')}>
          {running === 'glare' ? 'running…' : 'glare test'}
        </button>
      </div>
      {result && (
        <div>
          <p className={result.res.ok ? 'mono' : 'error'}>
            {result.kind} test: {result.res.ok ? 'PASS' : 'FAIL'}
          </p>
          <ol className="muted small log">
            {result.res.log.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ol>
        </div>
      )}
    </section>
  )
}
