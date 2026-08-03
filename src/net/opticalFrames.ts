// Turning a payload into the strings an animated QR shows, and back.
//
// Frames are TEXT, not the raw bytes the fountain layer produces, and that is a
// constraint of the decoders rather than a preference. A camera-side QR decoder
// hands back a string: the browser's native BarcodeDetector exposes only
// `rawValue`, with no standard way to reach the underlying bytes, and it reads
// byte mode as UTF-8, which destroys anything that is not valid UTF-8. So a
// binary frame would survive the pure-JS fallback and be mangled by the fast
// native path, which is the worse of the two failure modes: it would work in
// testing and fail on exactly the phones people use.
//
// base64url costs a third of each frame, and the trade is still overwhelmingly
// worth it: a version-40 symbol at EC level L holds 2953 characters, so a frame
// still carries about 2.1 KB against the ~180 bytes this project's encoder could
// manage before. It is also the encoding already used everywhere else here.

import { base64urlnopad } from '@scure/base'
import { qrCapacityBytes } from '../ui/qr'
import { FRAME_HEADER_LEN, encodeFrame, readFrameHeader } from './fountain'

/**
 * Symbol version the stream uses.
 *
 * This was version 40, the densest there is, on the reasoning that the ceremony
 * is a phone held close to a screen. That reasoning was wrong about the hardware
 * people actually have: a version-40 symbol is 177 modules across, 185 with its
 * quiet zone, and a decoder needs roughly three camera pixels per module. A
 * laptop webcam left to its own devices commonly negotiates 640x480, which gives
 * under two pixels per module even when the code fills the view, so it could
 * never decode and there was no way for anyone to tell that from a code that had
 * simply not been aimed at properly.
 *
 * Version 25 is 117 modules, 125 with the quiet zone, which is comfortable at
 * 720p and easy at 1080p. It costs frames: about 930 payload bytes each instead
 * of about 2190, so a transfer takes rather more than twice as many. That is the
 * right trade every time here, because frames are nearly free (the fountain
 * layer means a receiver takes whatever it catches, and a clean pass at ten
 * frames a second is a fraction of a second either way) while a symbol nobody can
 * read costs the whole ceremony.
 *
 * Nothing needs to agree on this. The block size travels in each frame's own
 * header, so a receiver adapts to whatever a sender chose, and the two builds
 * either side of this change interoperate in both directions.
 */
const STREAM_VERSION = 25
const STREAM_LEVEL = 'L' as const

/** Bytes of fountain frame that fit in one symbol once base64 has taken its
 *  third. Derived from the encoder rather than guessed, so raising the symbol
 *  version cannot silently start producing frames nothing can hold. */
export const FRAME_BYTES = Math.floor((qrCapacityBytes(STREAM_LEVEL, STREAM_VERSION) * 3) / 4)
/** Payload bytes per frame, after the fountain header. */
export const BLOCK_BYTES = FRAME_BYTES - FRAME_HEADER_LEN

/** How many frames a payload needs before any repair frames. Shown to the user
 *  as a rough idea of how long to hold the devices together. */
export function frameCount(payloadBytes: number): number {
  return Math.max(1, Math.ceil(payloadBytes / BLOCK_BYTES))
}

/** The text for frame `seq` of this payload, ready to render as a QR. */
export function opticalFrame(payload: Uint8Array, transferId: Uint8Array, seq: number): string {
  return base64urlnopad.encode(encodeFrame(payload, transferId, BLOCK_BYTES, seq))
}

/** Parse a scanned string back into a frame, or null if it is not one of ours.
 *  Returns null rather than throwing because a camera pointed at a room sees all
 *  sorts of things, and none of them are errors worth surfacing. */
export function parseOpticalFrame(text: string): Uint8Array | null {
  let bytes: Uint8Array
  try {
    bytes = base64urlnopad.decode(text)
  } catch {
    return null
  }
  try {
    readFrameHeader(bytes)
  } catch {
    return null
  }
  return bytes
}
