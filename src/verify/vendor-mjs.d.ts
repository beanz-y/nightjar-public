// Ambient types for the two plain-.mjs tools imported by the P7 tests. The tools
// are authored as bare-node ESM (run by CI/auditors without a TS toolchain), so
// they ship no .d.ts; these declarations let tsc type-check the round-trip/KAT
// tests that import them. Kept in lockstep with scripts/release-hash.mjs and
// tools/canary-sign.mjs.

declare module '*/scripts/release-hash.mjs' {
  interface Entry {
    path: string
    sha256: string
  }
  export function sha256hex(bytes: Uint8Array | Buffer): string
  export function manifestFromEntries(entries: Entry[]): string
  export function releaseHash(manifest: string): string
  export function hashDir(dir: string): Entry[]
}

declare module '*/tools/canary-sign.mjs' {
  interface BuildCanaryOpts {
    version: string
    releaseHash: string
    statement?: string
    signedAt?: string
    privateKeyB64: string
    now?: number
    allowBackdate?: boolean
  }
  export function buildCanary(opts: BuildCanaryOpts): {
    v: number
    version: string
    releaseHash: string
    statement: string
    signedAt: string
    sig: string
  }
}
