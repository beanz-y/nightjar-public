// Moving saved messages to a device already on the account (DESIGN 8.12).
//
// This carries the most of anything in the app: potentially every message the
// account has ever kept, in one blob, across a channel any camera in the room can
// read. So the tests are about what the seal is worth, what a receiver refuses,
// and the two ways a transfer could quietly become a lie (a truncated history
// that looks whole, and somebody else's messages written in as yours).

import { describe, expect, it } from 'vitest'
import {
  HISTORY_XFER_HEADER_LEN,
  HistoryTransferAuthError,
  HistoryTransferError,
  openHistoryTransfer,
  sealHistoryTransfer,
} from './historyTransfer'
import {
  HISTORY_XFER_MAGIC,
  HISTORY_XFER_MAX_BYTES,
  HISTORY_XFER_SALT_BYTES,
  HISTORY_XFER_VERSION,
  INFO_HISTORY_XFER,
  LINK_SECRET_BYTES,
} from './constants'
import type { HistoryUnitMessage } from './historyUnit'
import { aeadSeal, concatBytes, hkdfSha256, randomBytes, utf8 } from './primitives'
import { generateIdentity } from './identity'

const NOW = 1_800_000_000_000
const account = () => generateIdentity().userId

function rows(n: number, peer: string, textLen = 20): HistoryUnitMessage[] {
  return Array.from({ length: n }, (_, i) => ({
    id: i.toString(16).padStart(32, '0'),
    peer,
    dir: (i % 2 === 0 ? 'out' : 'in') as 'in' | 'out',
    ts: NOW - (n - i) * 1000,
    text: 'x'.repeat(textLen),
  }))
}

describe('sealing saved messages for another device', () => {
  it('round-trips every row, and only under the code that was on screen', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const accountId = account()
    const peer = account()
    const messages = rows(25, peer)

    const blob = sealHistoryTransfer({ accountId, messages, createdAt: NOW }, secret)
    const opened = openHistoryTransfer(blob, secret, NOW)
    expect(opened.accountId).toBe(accountId)
    expect(opened.messages).toHaveLength(25)
    expect(opened.messages.map((m) => m.id)).toEqual(messages.map((m) => m.id))
    expect(opened.messages[0].text).toBe(messages[0].text)

    // The whole authentication of the ceremony: the secret went screen to camera,
    // so only the device that photographed it can open this.
    expect(() => openHistoryTransfer(blob, randomBytes(LINK_SECRET_BYTES), NOW)).toThrow(HistoryTransferAuthError)
  })

  it('keeps outbound delivery marks and drops them from inbound rows', () => {
    // Carried as data, and an inbound row wearing one would render a message
    // somebody sent US as one we sent them.
    const secret = randomBytes(LINK_SECRET_BYTES)
    const peer = account()
    const messages: HistoryUnitMessage[] = [
      { id: 'a'.repeat(32), peer, dir: 'out', ts: NOW - 2000, text: 'mine', status: 'delivered' },
      { id: 'b'.repeat(32), peer, dir: 'in', ts: NOW - 1000, text: 'theirs', status: 'delivered' },
    ]
    const opened = openHistoryTransfer(
      sealHistoryTransfer({ accountId: account(), messages, createdAt: NOW }, secret),
      secret,
      NOW,
    )
    expect(opened.messages[0].status).toBe('delivered')
    expect(opened.messages[1].status).toBeUndefined()
  })

  it('refuses to carry more than a transfer can, rather than truncating it', () => {
    // A truncated history is worse than none: it arrives looking complete, with
    // an arbitrary slice missing from the middle of a conversation and nothing on
    // either device to say so.
    const secret = randomBytes(LINK_SECRET_BYTES)
    const peer = account()
    const huge = rows(Math.ceil(HISTORY_XFER_MAX_BYTES / 400) + 50, peer, 400)
    expect(() => sealHistoryTransfer({ accountId: account(), messages: huge, createdAt: NOW }, secret)).toThrow(
      HistoryTransferError,
    )
  })

  it('authenticates its own header, so the salt cannot be swapped', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const blob = sealHistoryTransfer({ accountId: account(), messages: rows(3, account()), createdAt: NOW }, secret)
    const tampered = Uint8Array.from(blob)
    tampered[6] ^= 0xff // a salt byte, which is inside the AAD
    expect(() => openHistoryTransfer(tampered, secret, NOW)).toThrow(HistoryTransferAuthError)
  })

  it('refuses anything that is not one of ours, before deriving any key', () => {
    const secret = randomBytes(LINK_SECRET_BYTES)
    const good = sealHistoryTransfer({ accountId: account(), messages: rows(2, account()), createdAt: NOW }, secret)

    const wrongMagic = Uint8Array.from(good)
    wrongMagic[0] = 'X'.charCodeAt(0)
    expect(() => openHistoryTransfer(wrongMagic, secret, NOW)).toThrow(/not a saved-messages transfer/)

    const wrongVersion = Uint8Array.from(good)
    wrongVersion[4] = 0x02
    expect(() => openHistoryTransfer(wrongVersion, secret, NOW)).toThrow(/unsupported transfer version/)

    expect(() => openHistoryTransfer(new Uint8Array(HISTORY_XFER_HEADER_LEN), secret, NOW)).toThrow(/too short/)
  })

  it('will not open a LINK payload, or any other v1 blob, as saved messages', () => {
    // Every sealed format in this project is `v: 1` JSON, so the discriminator is
    // checked before a single field is read. Without that, one cross-parses as
    // another: a link payload has an accountId too, and probing for fields would
    // happily accept it. Forged by hand here, because the real sealer can only
    // ever write the right discriminator and so cannot produce this case.
    const secret = randomBytes(LINK_SECRET_BYTES)
    const forge = (body: unknown): Uint8Array => {
      const salt = randomBytes(HISTORY_XFER_SALT_BYTES)
      const header = concatBytes(utf8(HISTORY_XFER_MAGIC), Uint8Array.from([HISTORY_XFER_VERSION]), salt)
      const kn = hkdfSha256(secret, salt, utf8(INFO_HISTORY_XFER), 32 + 24)
      return concatBytes(header, aeadSeal(kn.slice(0, 32), kn.slice(32), utf8(JSON.stringify(body)), header))
    }

    // A link payload, correctly sealed under the right key, in the right envelope.
    const asLink = forge({ t: 'njlink', v: 1, accountId: account(), accountKey: 'x', contacts: [], aliases: {} })
    expect(() => openHistoryTransfer(asLink, secret, NOW)).toThrow(/not a saved-messages payload/)

    // Right discriminator, wrong version.
    expect(() => openHistoryTransfer(forge({ t: 'njhx', v: 2, accountId: account() }), secret, NOW)).toThrow(
      /not a saved-messages payload/,
    )

    // Ours, but naming no account: the receiver's own-account check would have
    // nothing to compare, so it is refused here rather than passed along empty.
    expect(() => openHistoryTransfer(forge({ t: 'njhx', v: 1, accountId: 'nope' }), secret, NOW)).toThrow(
      /names no account/,
    )

    // Proof the forgery itself is sound, so the refusals above are about the
    // payload rather than a broken envelope.
    const valid = forge({ t: 'njhx', v: 1, accountId: account(), createdAt: NOW, unit: { t: 'njhist', hv: 1, messages: [] } })
    expect(openHistoryTransfer(valid, secret, NOW).messages).toEqual([])
  })

  it('bounds timestamps, so one wild row cannot pin the conversation list forever', () => {
    // The row is sealed on disk where no UI can repair it, and the sort and every
    // day separator read from it.
    const secret = randomBytes(LINK_SECRET_BYTES)
    const peer = account()
    const messages: HistoryUnitMessage[] = [
      { id: 'c'.repeat(32), peer, dir: 'in', ts: NOW + 10 * 365 * 24 * 3600 * 1000, text: 'from the future' },
      { id: 'd'.repeat(32), peer, dir: 'in', ts: NOW - 1000, text: 'ordinary' },
    ]
    const opened = openHistoryTransfer(
      sealHistoryTransfer({ accountId: account(), messages, createdAt: NOW }, secret),
      secret,
      NOW,
    )
    expect(opened.messages.map((m) => m.text)).toEqual(['ordinary'])
  })
})
