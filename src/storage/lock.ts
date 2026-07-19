// Single-writer serialization for ratchet operations (DESIGN 5.3). Two problems:
//   - Within one tab, IndexedDB transactions auto-close on an event-loop yield
//     and cannot be held across async crypto, so per-transaction atomicity does
//     not serialize a load -> compute -> save critical section. An in-memory
//     async mutex does.
//   - Across tabs / PWA windows of the same origin, only ONE may advance a given
//     session. The Web Locks API provides that origin-wide lock.
//
// createLock() returns the Web Locks implementation when available (covering
// both cases) and falls back to the in-memory mutex otherwise. In the fallback,
// cross-tab single-writer is NOT guaranteed; the app should keep to one tab.

export interface Lock {
  withLock<T>(name: string, fn: () => Promise<T>): Promise<T>
}

/** Serializes calls per name via a promise chain (also the no-Web-Locks fallback). */
export class InMemoryLock implements Lock {
  private readonly chains = new Map<string, Promise<unknown>>()

  withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.chains.get(name) ?? Promise.resolve()
    // Run fn after prev settles, whether it resolved or rejected.
    const result = prev.then(fn, fn)
    // Keep the chain alive without ever rejecting, so one failure does not wedge
    // the queue.
    this.chains.set(
      name,
      result.then(
        () => undefined,
        () => undefined,
      ),
    )
    return result
  }
}

/** Origin-wide single writer across tabs via the Web Locks API. */
export class WebLocksLock implements Lock {
  async withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    // The lock is held for as long as the callback's promise is unsettled, so
    // running fn() inside it serializes the whole critical section. We capture
    // the result rather than return request()'s value, whose DOM type is
    // imprecise.
    let result!: T
    await navigator.locks.request(name, async () => {
      result = await fn()
    })
    return result
  }
}

export function createLock(): Lock {
  if (typeof navigator !== 'undefined' && navigator.locks && typeof navigator.locks.request === 'function') {
    return new WebLocksLock()
  }
  return new InMemoryLock()
}
