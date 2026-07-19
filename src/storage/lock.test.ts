import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest'
import { InMemoryLock, WebLocksLock, type Lock } from './lock'

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

// Minimal exclusive Web Locks stand-in: serializes requests per name and returns
// the callback's result, so WebLocksLock's error-propagation and release paths
// (untestable in Node otherwise) get real coverage.
function mockLocks() {
  const queues = new Map<string, Promise<unknown>>()
  return {
    request(name: string, cb: () => unknown) {
      const prev = queues.get(name) ?? Promise.resolve()
      const run = prev.then(
        () => cb(),
        () => cb(),
      )
      queues.set(
        name,
        run.then(
          () => undefined,
          () => undefined,
        ),
      )
      return run
    },
  }
}

beforeEach(() => {
  vi.stubGlobal('navigator', { locks: mockLocks() })
})
afterEach(() => {
  vi.unstubAllGlobals()
})

function contract(name: string, makeLock: () => Lock) {
  describe(name, () => {
    it('serializes calls sharing a name', async () => {
      const lock = makeLock()
      const order: string[] = []
      const a = lock.withLock('x', async () => {
        order.push('a-start')
        await delay(20)
        order.push('a-end')
      })
      const b = lock.withLock('x', async () => {
        order.push('b-start')
        order.push('b-end')
      })
      await Promise.all([a, b])
      expect(order).toEqual(['a-start', 'a-end', 'b-start', 'b-end'])
    })

    it('does not serialize across different names', async () => {
      const lock = makeLock()
      const order: string[] = []
      const x = lock.withLock('x', async () => {
        order.push('x-start')
        await delay(20)
        order.push('x-end')
      })
      const y = lock.withLock('y', async () => {
        order.push('y-start')
        order.push('y-end')
      })
      await Promise.all([x, y])
      expect(order.indexOf('y-end')).toBeLessThan(order.indexOf('x-end'))
    })

    it('propagates the result and, after a rejection, releases so the queue keeps working', async () => {
      const lock = makeLock()
      expect(await lock.withLock('n', async () => 42)).toBe(42)
      await expect(lock.withLock('n', async () => Promise.reject(new Error('boom')))).rejects.toThrow('boom')
      expect(await lock.withLock('n', async () => 7)).toBe(7) // lock released, not wedged
    })
  })
}

contract('InMemoryLock', () => new InMemoryLock())
contract('WebLocksLock (mock navigator.locks)', () => new WebLocksLock())
