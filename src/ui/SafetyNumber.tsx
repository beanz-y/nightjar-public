// The out-of-band verification screen (DESIGN 6.2/6.3) : the single
// highest-value control in Nightjar. It renders the safety number (a symmetric
// function of both identity keys) as digit groups plus a QR, lets you SCAN the
// other person's code instead of comparing 40 digits by eye, shows the
// PER-DIRECTION trust we hold for this contact, and lets the user mark them
// verified or withdraw that verification.
//
// The safety number covers IK_sig only, and confirms the userId <-> person
// binding (the residual attack a substituted-key binding check cannot catch: a
// WRONG userId handed to us in the first place). Comparing it over a channel the
// operator does not control is what upgrades trust to 'verified'.
//
// Two rules shape the scanning flow, and neither is negotiable:
//
//  1. A scan never verifies on its own. The camera can prove the two codes agree;
//     it cannot prove where the image came from. A photograph of a genuine code,
//     forwarded over any channel, produces exactly the same green result as
//     holding a real phone. So a match unlocks the confirm, and the human still
//     attests to the channel. What the scan replaces is the digit comparison
//     (which a machine does better), not the human judgement.
//  2. A scan never DOWNGRADES trust either. A mismatch is displayed loudly but
//     writes nothing: the scanned bytes are attacker-chosen, so an automatic
//     downgrade would let anyone who can hold a QR up to a camera strip a real
//     verification. Withdrawing is a separate, deliberate action.

import { useMemo, useState } from 'react'
import { renderSafetyNumber, safetyNumberDigest } from '../crypto/safetyNumber'
import { compareScannedSafetyNumber, encodeSafetyNumberQr, type ScanVerdict } from '../crypto/safetyNumberQr'
import type { Contact, TrustLevel } from '../trust/contactStore'
import { b64decode } from '../wire/codec'
import { QrCode } from './QrCode'
import { QrScanner } from './QrScanner'

const TRUST_LABEL: Record<TrustLevel, string> = {
  unverified: 'unverified (trust on first use)',
  invite: 'invite-trusted (they invited you)',
  // Not "verified in person": a live call is an accepted channel (6.2), so the
  // durable label must not assert something the app cannot know happened.
  verified: 'verified (safety number confirmed)',
}

export function TrustBadge({ trust }: { trust: TrustLevel }) {
  return <span className={`badge badge-${trust}`}>{trust}</span>
}

/** What each refusal means, in the user's terms. Distinct messages matter: telling
 *  someone "that did not match" when they actually scanned their invite code sends
 *  them hunting for an attack that is not there. */
const REJECTION_TEXT: Record<string, string> = {
  'unreadable-nightjar-code':
    'That looks like a Nightjar safety-number code, but this device cannot read it. Their app may be a newer version, or the code may be damaged. Compare the digits by eye instead.',
  'legacy-digits': 'Their app is an older version whose code cannot be checked for who displayed it. Ask them to update, or compare the digits by eye.',
  'other-nightjar-code': 'That is an invite code or a user id, not a safety-number code. Ask them to open this contact and show the code on their verify screen.',
  unreadable: 'That is not a Nightjar safety-number code.',
}

interface Props {
  myIkSigPub: Uint8Array
  contact: Contact
  /** Local nickname for this contact, or '' if none. Display only. */
  name?: string
  onVerify: () => void
  onUnverify: () => void
  onBack: () => void
}

export function SafetyNumberView({ myIkSigPub, contact, name, onVerify, onUnverify, onBack }: Props) {
  const [confirming, setConfirming] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [verdict, setVerdict] = useState<ScanVerdict | null>(null)

  // Memoized on the two keys: the safety number is 5200 iterated SHA-512 rounds and
  // computing the digest separately doubles that, so doing it in the render body
  // put roughly 20ms of synchronous main-thread work (several times that on a
  // phone) into every single re-render of this screen, including every keystroke in
  // the rename box. It depends on nothing but the pair, so it is computed once.
  const { number, digest, qrPayload } = useMemo(() => {
    try {
      const peerKey = b64decode(contact.ikSig)
      const d = safetyNumberDigest(myIkSigPub, peerKey)
      const n = renderSafetyNumber(d)
      // The QR carries the same digits the eye compares, plus a tag identifying THIS
      // device as the one displaying it, so the other side can tell a real scan of
      // our screen from a scan of their own. Derived entirely from public keys.
      return { number: n, digest: d, qrPayload: encodeSafetyNumberQr(n, d, myIkSigPub) }
    } catch {
      return { number: '', digest: null as Uint8Array | null, qrPayload: '' }
    }
  }, [contact.ikSig, myIkSigPub])
  const groups = number.split(' ')

  const who = name?.trim() || `${contact.peerId.slice(0, 8)}…`

  function onScan(text: string) {
    setScanning(false)
    if (!digest) return
    setVerdict(
      compareScannedSafetyNumber(text, {
        digits: number,
        digest,
        myIkSigPub,
        peerIkSigPub: b64decode(contact.ikSig),
      }),
    )
    setConfirming(false)
  }

  return (
    <section className="verify">
      <button className="link" onClick={onBack}>
        ← back
      </button>
      <h2 className="small accent">verify {contact.peerId.slice(0, 12)}…</h2>

      <p className="muted small">
        Your trust in this contact: <TrustBadge trust={contact.trust} /> ({TRUST_LABEL[contact.trust]}). Trust is per
        direction: they must compare this same number on their device to verify you back.
      </p>

      {number ? (
        <>
          {scanning ? (
            <div className="scan-panel">
              <QrScanner
                onDecode={onScan}
                onCancel={() => setScanning(false)}
                hint={`Point the camera at the code on ${who}'s verify screen.`}
                fallback="Compare the digits by eye instead, they are just as good."
              />
            </div>
          ) : (
            <>
              <div className="safety-grid mono" aria-label="safety number">
                {groups.map((g, i) => (
                  <span key={i} className="safety-group">
                    {g}
                  </span>
                ))}
              </div>

              <div className="qr-wrap">
                <QrCode text={qrPayload} size={196} />
              </div>

              {verdict && <ScanResult verdict={verdict} who={who} />}

              <p className="muted small">
                Compare every digit with {who} in person, or scan the code on their screen. If they match, this contact
                is who you think it is.
              </p>

              {/* Offered whatever the current trust is. Re-checking an ALREADY
                  verified contact is a thing people do after a scare, and it is
                  exactly what DESIGN 6.4 wants them to do, so the instruction above
                  must not point at a button that is not there. */}
              <button className="ghost" onClick={() => { setVerdict(null); setScanning(true) }}>
                scan their code
              </button>
            </>
          )}

          {!scanning && (contact.trust === 'verified' ? (
            <div className="verified-block">
              <p className="verified-note">
                ✓ safety number confirmed{contact.verifiedAt ? ` on ${new Date(contact.verifiedAt).toLocaleDateString()}` : ''}
              </p>
              {removing ? (
                <div className="row">
                  <button
                    className="danger"
                    onClick={() => {
                      onUnverify()
                      setRemoving(false)
                      setVerdict(null)
                    }}
                  >
                    yes, remove the verification
                  </button>
                  <button className="ghost" onClick={() => setRemoving(false)}>
                    cancel
                  </button>
                </div>
              ) : (
                <>
                  <button className="ghost small" onClick={() => setRemoving(true)}>
                    remove verification
                  </button>
                  <p className="tiny muted">
                    Use this if you learn you confirmed the wrong person. It keeps the contact and your messages, and
                    puts them back to unverified so you can check again.
                  </p>
                </>
              )}
            </div>
          ) : confirming ? (
            <div className="confirm-block">
              {/* The attestation is about the CHANNEL, because that is the only part
                  the device cannot check for itself. */}
              <p className="small">
                Only confirm if you are with {who} in person, or on a live call where you recognise them, and you are
                looking at their device.
              </p>
              <p className="tiny muted">
                A code someone sent you as an image or a screenshot proves nothing: anyone can forward a picture of a
                real code, and anyone holding both public keys can make one that matches.
              </p>
              {/* A scan that did NOT match stays on screen while this block is open,
                  so the button must never ask the user to attest to a match the app
                  just contradicted. Verifying by eye after a failed scan is still
                  allowed (a mismatch must not lock anyone out, and it writes no
                  state), but the words have to describe what they actually did. */}
              {verdict && verdict.kind !== 'match' && (
                <p className="tiny scan-contradiction">
                  Note: the code you scanned did not check out. Only confirm if you have since compared the digits
                  yourself.
                </p>
              )}
              <div className="row">
                <button
                  className="danger"
                  onClick={() => {
                    onVerify()
                    setConfirming(false)
                  }}
                >
                  {verdict?.kind === 'match' ? 'yes, I scanned their device' : 'yes, I compared the digits'}
                </button>
                <button className="ghost" onClick={() => setConfirming(false)}>
                  cancel
                </button>
              </div>
            </div>
          ) : (
            <button className="primary" onClick={() => setConfirming(true)}>
              mark as verified
            </button>
          ))}
        </>
      ) : (
        <p className="error">could not compute a safety number for this contact</p>
      )}
    </section>
  )
}

/** The outcome panel. Only 'match' is presented as a step forward; everything
 *  else refuses, and the mismatch case is the loud one. */
function ScanResult({ verdict, who }: { verdict: ScanVerdict; who: string }) {
  if (verdict.kind === 'match') {
    return (
      <div className="scan-result scan-ok">
        <p className="small">
          <strong>The codes match.</strong> That code carries the same safety number this device computed, and it names{' '}
          {who}&apos;s device as the one displaying it rather than this one.
        </p>
        <p className="tiny muted">
          That is all a code can show. It is built from public keys, so it cannot prove the image came from {who}
          &apos;s screen just now, or that it was made by their device at all. The last step is yours.
        </p>
      </div>
    )
  }
  if (verdict.kind === 'mismatch') {
    return (
      <div className="scan-result scan-bad">
        <p className="small">
          <strong>These do not match.</strong> The code you scanned carries a different safety number from the one this
          device computed for {who}.
        </p>
        <p className="tiny">
          Do not mark this contact verified. Check you are on the right contact, then compare the digits by eye. If it
          still differs, the key one of you holds is not the key the other holds, which is exactly what this check
          exists to catch. Talk to {who} through another channel.
        </p>
      </div>
    )
  }
  if (verdict.kind === 'self') {
    return (
      <div className="scan-result scan-warn">
        <p className="small">
          <strong>That is this device&apos;s own code.</strong> Both of you see the same digits, so scanning your own
          screen (or a photo of it) would otherwise look like a match.
        </p>
        <p className="tiny muted">Point the camera at the code on {who}&apos;s screen instead.</p>
      </div>
    )
  }
  if (verdict.kind === 'indeterminate') {
    return (
      <div className="scan-result scan-warn">
        <p className="small">
          <strong>Could not tell whose code that is.</strong> The digits match, but the code does not identify either of
          your devices as the one displaying it.
        </p>
        <p className="tiny muted">Compare the digits by eye instead, and do not confirm unless you are with {who}.</p>
      </div>
    )
  }
  return (
    <div className="scan-result scan-warn">
      <p className="small">{REJECTION_TEXT[verdict.reason] ?? REJECTION_TEXT.unreadable}</p>
    </div>
  )
}
