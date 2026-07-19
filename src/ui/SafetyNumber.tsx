// The out-of-band verification screen (DESIGN 6.2/6.3) : the single
// highest-value control in Nightjar. It renders the safety number (a symmetric
// function of both identity keys) as digit groups plus a QR, shows the
// PER-DIRECTION trust we hold for this contact, and lets the user mark them
// verified after comparing in person.
//
// The safety number covers IK_sig only, and confirms the userId <-> person
// binding (the residual attack a substituted-key binding check cannot catch: a
// WRONG userId handed to us in the first place). Comparing it in person, over a
// channel the operator does not control, is what upgrades trust to 'verified'.

import { useState } from 'react'
import { safetyNumber } from '../crypto/safetyNumber'
import type { Contact, TrustLevel } from '../trust/contactStore'
import { b64decode } from '../wire/codec'
import { QrCode } from './QrCode'

const TRUST_LABEL: Record<TrustLevel, string> = {
  unverified: 'unverified (trust on first use)',
  invite: 'invite-trusted (they invited you)',
  verified: 'verified in person',
}

export function TrustBadge({ trust }: { trust: TrustLevel }) {
  return <span className={`badge badge-${trust}`}>{trust}</span>
}

interface Props {
  myIkSigPub: Uint8Array
  contact: Contact
  onVerify: () => void
  onBack: () => void
}

export function SafetyNumberView({ myIkSigPub, contact, onVerify, onBack }: Props) {
  const [confirming, setConfirming] = useState(false)

  let number: string
  try {
    number = safetyNumber(myIkSigPub, b64decode(contact.ikSig))
  } catch {
    number = ''
  }
  const groups = number.split(' ')
  // The QR carries the same digits (no spaces) so a scan compares to the peer's
  // locally-computed number. It is derived from public keys and leaks nothing.
  const qrPayload = number.replace(/ /g, '')

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

          <p className="muted small">
            Compare every digit with {contact.peerId.slice(0, 8)}… in person, or over a call you already trust. If they
            match, this contact is who you think it is.
          </p>

          {contact.trust === 'verified' ? (
            <p className="verified-note">✓ verified in person{contact.verifiedAt ? ` on ${new Date(contact.verifiedAt).toLocaleDateString()}` : ''}</p>
          ) : confirming ? (
            <div className="row">
              <button
                className="danger"
                onClick={() => {
                  onVerify()
                  setConfirming(false)
                }}
              >
                yes, every digit matched
              </button>
              <button className="ghost" onClick={() => setConfirming(false)}>
                cancel
              </button>
            </div>
          ) : (
            <button className="primary" onClick={() => setConfirming(true)}>
              mark as verified
            </button>
          )}
        </>
      ) : (
        <p className="error">could not compute a safety number for this contact</p>
      )}
    </section>
  )
}
