// Persistent-storage request + eviction detection (DESIGN 8.2).
//
// Safari's ITP wipes script-writable storage after 7 days of non-use, which
// would silently destroy the identity and every session. We (a) ask the browser
// to keep storage persistent, and (b) keep a SENTINEL outside the main store so
// that an empty store WITH a prior-registration signal is recognised as an
// eviction, and routed to restore rather than silently generating a new identity
// (which would fire key-change alarms at every contact). The strongest sentinel
// is server-side ("this identity registered"), which arrives with the server in
// P4; the Cache Storage marker here is the best-effort client-only signal.

/** Ask the browser to keep our origin's storage persistent. Best-effort. */
export async function requestPersistentStorage(): Promise<boolean> {
  const nav = globalThis.navigator
  if (!nav?.storage?.persist) return false
  try {
    return await nav.storage.persist()
  } catch {
    return false
  }
}

export interface Sentinel {
  mark(): Promise<void>
  exists(): Promise<boolean>
}

const SENTINEL_CACHE = 'nightjar-sentinel'
const SENTINEL_KEY = 'https://nightjar.invalid/registered'

/** Marker kept in Cache Storage. This helps only against a SELECTIVE clear of
 *  IndexedDB (Cache Storage surviving); a full Safari ITP wipe clears Cache
 *  Storage too, so the authoritative eviction signal is the P4 server-side flag.
 *  All calls are wrapped so a locked-down context (Safari private browsing, where
 *  Cache Storage rejects) can never crash startup at the eviction check. */
export class CacheStorageSentinel implements Sentinel {
  async mark(): Promise<void> {
    try {
      const cache = await caches.open(SENTINEL_CACHE)
      await cache.put(SENTINEL_KEY, new Response('1'))
    } catch {
      // Best-effort: never let sentinel marking crash startup.
    }
  }

  async exists(): Promise<boolean> {
    try {
      const cache = await caches.open(SENTINEL_CACHE)
      return (await cache.match(SENTINEL_KEY)) !== undefined
    } catch {
      // Cannot determine; best-effort client sentinel returns false. A false on
      // an evicted store degrades to 'first-run'; P4's durable server-side flag
      // closes this before an empty store is ever treated as first-run.
      return false
    }
  }
}

export class MemorySentinel implements Sentinel {
  private marked = false
  async mark(): Promise<void> {
    this.marked = true
  }
  async exists(): Promise<boolean> {
    return this.marked
  }
}

// NOTE: when Cache Storage is unavailable this returns a NON-DURABLE
// MemorySentinel (its mark does not survive a reload), so eviction cannot be
// distinguished from first run. Acceptable for P3 (client-only); P4 adds the
// durable server-side sentinel, which must gate any auto-generation of a new
// identity when no durable client sentinel exists.
export function createSentinel(): Sentinel {
  return typeof caches !== 'undefined' ? new CacheStorageSentinel() : new MemorySentinel()
}

export type StartupState = 'first-run' | 'loaded' | 'evicted-needs-restore'

/**
 * Given whether the identity store currently holds an identity and the sentinel,
 * classify startup:
 *   loaded               - identity present, normal start
 *   first-run            - no identity, never registered -> generate
 *   evicted-needs-restore- no identity but we DID register before -> the store
 *                          was cleared; must restore, never silently regenerate.
 */
export async function detectStartupState(hasIdentity: boolean, sentinel: Sentinel): Promise<StartupState> {
  if (hasIdentity) return 'loaded'
  return (await sentinel.exists()) ? 'evicted-needs-restore' : 'first-run'
}
