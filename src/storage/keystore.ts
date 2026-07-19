// Durable key/value byte storage (DESIGN 8.1, P0). This is the "abstract key
// storage behind an interface" seam that keeps the native door open (DESIGN
// 10.5): the app depends only on KeyStore, so a later Tauri build can swap in an
// OS-keychain implementation without touching call sites.
//
// P0 scope is a minimal, correct put/get for the identity blob. The full
// atomic, single-writer (Web Locks) ratchet-state store is P3.

export interface KeyStore {
  get(key: string): Promise<Uint8Array | null>
  put(key: string, value: Uint8Array): Promise<void>
  delete(key: string): Promise<void>
  keys(): Promise<string[]>
}

/** In-memory store, for tests and ephemeral contexts. */
export class MemoryKeyStore implements KeyStore {
  private readonly map = new Map<string, Uint8Array>()

  async get(key: string): Promise<Uint8Array | null> {
    const v = this.map.get(key)
    return v ? v.slice() : null
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    this.map.set(key, value.slice())
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key)
  }

  async keys(): Promise<string[]> {
    return [...this.map.keys()]
  }
}

const DB_NAME = 'nightjar'
const STORE_NAME = 'keyval'

/** IndexedDB-backed store for the browser (DESIGN 8.1). */
export class IdbKeyStore implements KeyStore {
  private dbPromise: Promise<IDBDatabase> | null = null

  private open(): Promise<IDBDatabase> {
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1)
        req.onupgradeneeded = () => {
          req.result.createObjectStore(STORE_NAME)
        }
        req.onsuccess = () => resolve(req.result)
        req.onerror = () => reject(req.error)
      })
    }
    return this.dbPromise
  }

  private async tx<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.open()
    return new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, mode)
      const request = fn(transaction.objectStore(STORE_NAME))
      let result: T
      request.onsuccess = () => {
        result = request.result
      }
      request.onerror = () => reject(request.error)
      // Resolve only when the transaction COMMITS (durable), not merely when the
      // request succeeds: a put can succeed while the transaction still aborts at
      // commit time (quota, disk error). Load-bearing for "commit before release".
      transaction.oncomplete = () => resolve(result)
      transaction.onabort = () => reject(transaction.error)
      transaction.onerror = () => reject(transaction.error)
    })
  }

  async get(key: string): Promise<Uint8Array | null> {
    const value = await this.tx<unknown>('readonly', (s) => s.get(key))
    if (value == null) return null
    if (value instanceof Uint8Array) return value
    if (value instanceof ArrayBuffer) return new Uint8Array(value)
    throw new Error('unexpected stored value type')
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    // Store a copy as a plain ArrayBuffer slice so the structured clone is a
    // stable snapshot independent of the caller's buffer.
    await this.tx('readwrite', (s) => s.put(value.slice(), key))
  }

  async delete(key: string): Promise<void> {
    await this.tx('readwrite', (s) => s.delete(key))
  }

  async keys(): Promise<string[]> {
    const keys = await this.tx<IDBValidKey[]>('readonly', (s) => s.getAllKeys())
    return keys.map(String)
  }
}
