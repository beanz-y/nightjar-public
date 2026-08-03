// History-unit tests (Phase D). The unit must bound and validate ITSELF: its
// safety is not allowed to lean on the move envelope's byte cap, because the
// unit is the piece a future multi-device link reuses without that envelope.

import { describe, expect, it } from 'vitest'
import { generateIdentity } from './identity'
import { CLOCK_SKEW_MS } from './constants'
import {
  HISTORY_UNIT_MAX_MESSAGES,
  type HistoryUnitMessage,
  HistoryUnitError,
  decodeHistoryUnit,
  encodeHistoryUnit,
} from './historyUnit'

const NOW = 1_700_000_000_000
const PEER = generateIdentity().userId

function row(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { kind: 'msg', id: 'a'.repeat(32), peer: PEER, dir: 'in', ts: NOW - 1000, text: 'hello', ...over }
}

describe('history unit (Phase D)', () => {
  it('round-trips valid messages', () => {
    const messages: HistoryUnitMessage[] = [
      { id: '00ff'.repeat(8), peer: PEER, dir: 'in', ts: NOW - 5000, text: 'hi' },
      { id: 'b'.repeat(32), peer: PEER, dir: 'out', ts: NOW - 4000, text: 'yo', status: 'delivered' },
      { id: 'c'.repeat(32), peer: PEER, dir: 'out', ts: NOW - 3000, text: 'lost', failed: true },
    ]
    const decoded = decodeHistoryUnit(encodeHistoryUnit(messages), NOW)
    expect(decoded.messages).toEqual(messages)
    expect(decoded.dropped).toBe(0)
    expect(decoded.collapsed).toBe(0)
  })

  it('requires the discriminator and version, checked before any field', () => {
    expect(() => decodeHistoryUnit({ hv: 1, messages: [] }, NOW)).toThrow(HistoryUnitError)
    expect(() => decodeHistoryUnit({ t: 'njmv', hv: 1, messages: [] }, NOW)).toThrow('not a history unit')
    expect(() => decodeHistoryUnit({ t: 'njhist', hv: 2, messages: [] }, NOW)).toThrow('version unsupported')
    expect(() => decodeHistoryUnit({ t: 'njhist', hv: 1 }, NOW)).toThrow('no message list')
    expect(() => decodeHistoryUnit(null, NOW)).toThrow(HistoryUnitError)
  })

  it('drops invalid rows and counts them, keeping the rest', () => {
    const legacyUuid = row({ id: '4c0e2f1a-8a5e-4c9e-9d3a-1b2c3d4e5f60', dir: 'out' })
    const bad = [
      row({ id: '' }),
      row({ id: 'x'.repeat(65) }),
      row({ id: '\ud800' }), // lone surrogate: would collide in the HMAC key
      row({ peer: 'not-a-user-id' }),
      row({ dir: 'sideways' }),
      row({ ts: NOW + CLOCK_SKEW_MS + 1 }), // future beyond skew pins the sidebar sort
      row({ ts: -5 }),
      row({ ts: 1.5 }),
      row({ ts: Number.MAX_SAFE_INTEGER + 2 }),
      row({ text: 7 }),
      row({ kind: 'reaction' }), // reserved future kind: clean drop
      'not-an-object',
    ]
    const decoded = decodeHistoryUnit({ t: 'njhist', hv: 1, messages: [row(), legacyUuid, ...bad] }, NOW)
    expect(decoded.messages).toHaveLength(2)
    expect(decoded.messages[1].id).toBe('4c0e2f1a-8a5e-4c9e-9d3a-1b2c3d4e5f60')
    expect(decoded.dropped).toBe(bad.length)
  })

  it('strips delivery marks and the failed flag from inbound rows', () => {
    const decoded = decodeHistoryUnit(
      { t: 'njhist', hv: 1, messages: [row({ dir: 'in', status: 'delivered', failed: true })] },
      NOW,
    )
    expect(decoded.messages[0].status).toBeUndefined()
    expect(decoded.messages[0].failed).toBeUndefined()
  })

  it('honors only the two known delivery marks on outbound rows', () => {
    const decoded = decodeHistoryUnit(
      {
        t: 'njhist',
        hv: 1,
        messages: [row({ id: 'd'.repeat(32), dir: 'out', status: 'teleported' }), row({ id: 'e'.repeat(32), dir: 'out', status: 'sent' })],
      },
      NOW,
    )
    expect(decoded.messages[0].status).toBeUndefined()
    expect(decoded.messages[1].status).toBe('sent')
  })

  it('collapses duplicate (peer, dir, id) rows, first occurrence winning', () => {
    const decoded = decodeHistoryUnit(
      {
        t: 'njhist',
        hv: 1,
        messages: [row({ text: 'first' }), row({ text: 'second' }), row({ dir: 'out', text: 'other-slot' })],
      },
      NOW,
    )
    expect(decoded.messages).toHaveLength(2)
    expect(decoded.messages[0].text).toBe('first')
    expect(decoded.collapsed).toBe(1)
  })

  it('refuses (never truncates) past the row budget', () => {
    const messages = new Array(HISTORY_UNIT_MAX_MESSAGES + 1).fill(row())
    expect(() => decodeHistoryUnit({ t: 'njhist', hv: 1, messages }, NOW)).toThrow('more than')
  })

  it('refuses past its own text-byte budget, independent of any envelope', () => {
    // 241 distinct max-size rows total just over 15 MiB of text.
    const big = 'a'.repeat(64 * 1024)
    const messages = Array.from({ length: 241 }, (_, i) => row({ id: i.toString(16).padStart(32, '0'), text: big }))
    expect(() => decodeHistoryUnit({ t: 'njhist', hv: 1, messages }, NOW)).toThrow('size budget')
  })

  it('drops a single over-size text row rather than refusing the unit', () => {
    const decoded = decodeHistoryUnit(
      { t: 'njhist', hv: 1, messages: [row({ text: 'a'.repeat(64 * 1024 + 1) }), row({ id: 'f'.repeat(32) })] },
      NOW,
    )
    expect(decoded.messages).toHaveLength(1)
    expect(decoded.dropped).toBe(1)
  })
})
