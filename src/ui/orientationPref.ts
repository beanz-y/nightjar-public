// Per-device orientation-lock preference: force portrait mode on mobile.
// This is a session-level request using the Screen Orientation API; it
// may be ignored by some browsers or require the app to be in fullscreen.
// Stored in localStorage to remember the user's preference across reloads.

import { useEffect, useState } from 'react'

export type OrientationLock = 'any' | 'portrait'

const KEY = 'nightjar.orientationLock'
const EVENT = 'nightjar:orientationlock'

export function getOrientationLock(): OrientationLock {
  try {
    const v = localStorage.getItem(KEY)
    if (v === 'portrait' || v === 'any') return v
  } catch {
    /* storage unavailable */
  }
  return 'any'
}

export function setOrientationLock(v: OrientationLock): void {
  try {
    localStorage.setItem(KEY, v)
  } catch {
    /* storage unavailable */
  }
  try {
    window.dispatchEvent(new CustomEvent(EVENT))
  } catch {
    /* no window */
  }
}

/** Subscribe a component to the current preference; re-renders on change. */
export function useOrientationLock(): OrientationLock {
  const [lock, setLock] = useState<OrientationLock>(getOrientationLock)
  useEffect(() => {
    const update = () => setLock(getOrientationLock())
    window.addEventListener(EVENT, update)
    window.addEventListener('storage', update)
    return () => {
      window.removeEventListener(EVENT, update)
      window.removeEventListener('storage', update)
    }
  }, [])
  return lock
}
