import { describe, expect, it } from 'vitest'
import { generateIdentity } from '../crypto/identity'
import { formatInviteCode, newInviteCode } from '../server/invites'
import { decodeInviteArtifact, encodeInviteArtifact, inviteUrl } from './inviteArtifact'

describe('inviteArtifact', () => {
  const code = newInviteCode()
  const inviter = generateIdentity().userId

  it('round-trips a code + inviter artifact', () => {
    const token = encodeInviteArtifact({ code, inviter })
    expect(token).toBe(`${code}.${inviter}`)
    expect(decodeInviteArtifact(token)).toEqual({ code, inviter })
  })

  it('encodes a bare code (bootstrap invite, no inviter to pin)', () => {
    const token = encodeInviteArtifact({ code, inviter: null })
    expect(token).toBe(code)
    expect(decodeInviteArtifact(token)).toEqual({ code, inviter: null })
  })

  it('parses an artifact out of a nightjar invite URL', () => {
    const url = inviteUrl('https://nightjar.example', { code, inviter })
    expect(url).toBe(`https://nightjar.example/#i=${code}.${inviter}`)
    expect(decodeInviteArtifact(url)).toEqual({ code, inviter })
  })

  it('accepts a display-formatted (dashed) code and normalizes it', () => {
    const token = `${formatInviteCode(code)}.${inviter}`
    expect(decodeInviteArtifact(token)).toEqual({ code, inviter })
  })

  it('rejects a malformed code', () => {
    expect(() => decodeInviteArtifact('too-short')).toThrow(/valid invite code/)
    expect(() => decodeInviteArtifact(`${code}.not-a-user-id`)).toThrow(/inviter/)
  })
})
