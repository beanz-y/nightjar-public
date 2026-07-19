// Wire codec (P4). The single place bytes cross the network as JSON. Every
// protocol struct that rides the WebSocket is encoded here to a JSON-safe shape
// (Uint8Array -> unpadded base64url) and decoded back, fail-closed on any
// malformed input (bad base64, wrong byte length, out-of-range integer).
//
// This module is SHARED by the client (src/net) and the server (worker/), so
// there is exactly one definition of the wire format and the two sides cannot
// disagree. It performs STRUCTURAL validation only; cryptographic verification
// (signatures, bindings) stays in src/crypto and runs after decode.

import { base64urlnopad } from '@scure/base'
import type { FetchedBundle, OneTimePrekey, SignedPrekey } from '../crypto/prekeys'
import type { InitialHeader } from '../crypto/x3dh'
import type { MessageHeader } from '../crypto/ratchet'

// --- byte <-> base64url helpers ------------------------------------------

const U32_MAX = 0xffffffff

export function b64encode(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes)
}

/** Decode base64url, optionally asserting an exact byte length. Throws on
 *  invalid base64 or a length mismatch (fail-closed). */
export function b64decode(s: string, expectLen?: number): Uint8Array {
  if (typeof s !== 'string') throw new Error('wire: expected a base64 string')
  const bytes = base64urlnopad.decode(s) // throws on a non-alphabet character
  if (expectLen !== undefined && bytes.length !== expectLen) {
    throw new Error(`wire: expected ${expectLen} bytes, got ${bytes.length}`)
  }
  return bytes
}

function uint(n: unknown, max: number, what: string): number {
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 0 || n > max) {
    throw new Error(`wire: ${what} is not a uint in [0, ${max}]`)
  }
  return n
}

// Fixed byte widths (see src/crypto). A wrong width is rejected structurally
// before any value reaches noble.
const ED_PUB = 32
const ED_SIG = 64
const X_PUB = 32

// --- signed / one-time prekeys -------------------------------------------

export interface WireSignedPrekey {
  id: number
  createdAt: number
  expiry: number
  pub: string
  sig: string
}

export interface WireOneTimePrekey {
  id: number
  pub: string
}

export function encodeSignedPrekey(spk: SignedPrekey): WireSignedPrekey {
  return {
    id: spk.id,
    createdAt: spk.createdAt,
    expiry: spk.expiry,
    pub: b64encode(spk.pub),
    sig: b64encode(spk.sig),
  }
}

export function decodeSignedPrekey(w: WireSignedPrekey): SignedPrekey {
  return {
    id: uint(w.id, U32_MAX, 'spk.id'),
    createdAt: uint(w.createdAt, Number.MAX_SAFE_INTEGER, 'spk.createdAt'),
    expiry: uint(w.expiry, Number.MAX_SAFE_INTEGER, 'spk.expiry'),
    pub: b64decode(w.pub, X_PUB),
    sig: b64decode(w.sig, ED_SIG),
  }
}

export function encodeOneTimePrekey(opk: OneTimePrekey): WireOneTimePrekey {
  return { id: opk.id, pub: b64encode(opk.pub) }
}

export function decodeOneTimePrekey(w: WireOneTimePrekey): OneTimePrekey {
  return { id: uint(w.id, U32_MAX, 'opk.id'), pub: b64decode(w.pub, X_PUB) }
}

// --- fetched bundle (initiator side: exactly one OPK, or none) -----------

export interface WireFetchedBundle {
  version: number
  ikSigPub: string
  ikDhPub: string
  idkbindSig: string
  spk: WireSignedPrekey
  opk: WireOneTimePrekey | null
}

export function encodeFetchedBundle(b: FetchedBundle): WireFetchedBundle {
  return {
    version: b.version,
    ikSigPub: b64encode(b.ikSigPub),
    ikDhPub: b64encode(b.ikDhPub),
    idkbindSig: b64encode(b.idkbindSig),
    spk: encodeSignedPrekey(b.spk),
    opk: b.opk ? encodeOneTimePrekey(b.opk) : null,
  }
}

export function decodeFetchedBundle(w: WireFetchedBundle): FetchedBundle {
  return {
    version: uint(w.version, 0xff, 'bundle.version'),
    ikSigPub: b64decode(w.ikSigPub, ED_PUB),
    ikDhPub: b64decode(w.ikDhPub, X_PUB),
    idkbindSig: b64decode(w.idkbindSig, ED_SIG),
    spk: decodeSignedPrekey(w.spk),
    opk: w.opk == null ? null : decodeOneTimePrekey(w.opk),
  }
}

// --- published bundle (registration: identity + SPK + full OPK batch) -----

export interface WirePublishedBundle {
  version: number
  ikSigPub: string
  ikDhPub: string
  idkbindSig: string
  spk: WireSignedPrekey
  opks: WireOneTimePrekey[]
}

export interface PublishedBundle {
  version: number
  ikSigPub: Uint8Array
  ikDhPub: Uint8Array
  idkbindSig: Uint8Array
  spk: SignedPrekey
  opks: OneTimePrekey[]
}

export function encodePublishedBundle(b: PublishedBundle): WirePublishedBundle {
  return {
    version: b.version,
    ikSigPub: b64encode(b.ikSigPub),
    ikDhPub: b64encode(b.ikDhPub),
    idkbindSig: b64encode(b.idkbindSig),
    spk: encodeSignedPrekey(b.spk),
    opks: b.opks.map(encodeOneTimePrekey),
  }
}

export function decodePublishedBundle(w: WirePublishedBundle): PublishedBundle {
  if (!Array.isArray(w.opks)) throw new Error('wire: published bundle opks not an array')
  return {
    version: uint(w.version, 0xff, 'bundle.version'),
    ikSigPub: b64decode(w.ikSigPub, ED_PUB),
    ikDhPub: b64decode(w.ikDhPub, X_PUB),
    idkbindSig: b64decode(w.idkbindSig, ED_SIG),
    spk: decodeSignedPrekey(w.spk),
    opks: w.opks.map(decodeOneTimePrekey),
  }
}

// --- headers -------------------------------------------------------------

export interface WireInitialHeader {
  version: number
  ikSigPub: string
  ikDhPub: string
  idkbindSig: string
  ekPub: string
  spkId: number
  opkId: number | null
}

export function encodeInitialHeader(h: InitialHeader): WireInitialHeader {
  return {
    version: h.version,
    ikSigPub: b64encode(h.ikSigPub),
    ikDhPub: b64encode(h.ikDhPub),
    idkbindSig: b64encode(h.idkbindSig),
    ekPub: b64encode(h.ekPub),
    spkId: h.spkId,
    opkId: h.opkId,
  }
}

export function decodeInitialHeader(w: WireInitialHeader): InitialHeader {
  return {
    version: uint(w.version, 0xff, 'initial.version'),
    ikSigPub: b64decode(w.ikSigPub, ED_PUB),
    ikDhPub: b64decode(w.ikDhPub, X_PUB),
    idkbindSig: b64decode(w.idkbindSig, ED_SIG),
    ekPub: b64decode(w.ekPub, X_PUB),
    spkId: uint(w.spkId, U32_MAX, 'initial.spkId'),
    opkId: w.opkId == null ? null : uint(w.opkId, U32_MAX, 'initial.opkId'),
  }
}

export interface WireMessageHeader {
  version: number
  dhPub: string
  pn: number
  n: number
}

export function encodeMessageHeaderWire(h: MessageHeader): WireMessageHeader {
  return { version: h.version, dhPub: b64encode(h.dhPub), pn: h.pn, n: h.n }
}

export function decodeMessageHeaderWire(w: WireMessageHeader): MessageHeader {
  return {
    version: uint(w.version, 0xff, 'header.version'),
    dhPub: b64decode(w.dhPub, X_PUB),
    pn: uint(w.pn, U32_MAX, 'header.pn'),
    n: uint(w.n, U32_MAX, 'header.n'),
  }
}

// --- message envelope (what the relay stores and forwards) ----------------
// kind 'initial' carries the X3DH InitialHeader alongside the first ratchet
// message; kind 'normal' is a ratchet message on an established session. The id
// is the sender's outbox id, used for at-least-once delivery and dedup at both
// ends. `ciphertext` is the ratchet AEAD output (relay never sees a key).

export interface WireEnvelope {
  id: string
  kind: 'initial' | 'normal'
  header: WireMessageHeader
  ciphertext: string
  initialHeader?: WireInitialHeader
}

export interface Envelope {
  id: string
  kind: 'initial' | 'normal'
  header: MessageHeader
  ciphertext: Uint8Array
  initialHeader?: InitialHeader
}

/** Max id length (defensive: ids are UUID-ish, ~36 chars; cap well above). */
const MAX_ID_LEN = 128

function checkId(id: unknown): string {
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_ID_LEN) {
    throw new Error('wire: bad envelope id')
  }
  return id
}

export function encodeEnvelope(e: Envelope): WireEnvelope {
  const w: WireEnvelope = {
    id: e.id,
    kind: e.kind,
    header: encodeMessageHeaderWire(e.header),
    ciphertext: b64encode(e.ciphertext),
  }
  if (e.kind === 'initial') {
    if (!e.initialHeader) throw new Error('wire: initial envelope missing initialHeader')
    w.initialHeader = encodeInitialHeader(e.initialHeader)
  }
  return w
}

export function decodeEnvelope(w: WireEnvelope): Envelope {
  if (w.kind !== 'initial' && w.kind !== 'normal') throw new Error('wire: bad envelope kind')
  const e: Envelope = {
    id: checkId(w.id),
    kind: w.kind,
    header: decodeMessageHeaderWire(w.header),
    ciphertext: b64decode(w.ciphertext),
  }
  if (w.kind === 'initial') {
    if (!w.initialHeader) throw new Error('wire: initial envelope missing initialHeader')
    e.initialHeader = decodeInitialHeader(w.initialHeader)
  }
  return e
}
