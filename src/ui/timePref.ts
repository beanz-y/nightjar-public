// Per-device time-format preference: follow the device locale (auto), or force
// 12-hour or 24-hour clocks. This is a display-only choice, stored in localStorage
// like the notification opt-in; it never touches stored data or crypto. A small
// event lets open views re-render live when it changes, and the browser 'storage'
// event keeps sibling tabs in sync.

import { useEffect, useState } from 'react'

export type TimeFormat = 'auto' | '12' | '24'

const KEY = 'nightjar.timeFormat'
const EVENT = 'nightjar:timeformat'

export function getTimeFormat(): TimeFormat {
  try {
    const v = localStorage.getItem(KEY)
    if (v === '12' || v === '24' || v === 'auto') return v
  } catch {
    /* storage unavailable */
  }
  return 'auto'
}

export function setTimeFormat(v: TimeFormat): void {
  try {
    localStorage.setItem(KEY, v)
  } catch {
    /* storage unavailable */
  }
  try {
    window.dispatchEvent(new CustomEvent(EVENT))
  } catch {
    /* no window (e.g. node tests) */
  }
}

/** The Intl `hour12` flag for a format, or undefined to let the locale decide. */
export function hour12For(fmt: TimeFormat): boolean | undefined {
  return fmt === '12' ? true : fmt === '24' ? false : undefined
}

/** Subscribe a component to the current preference; re-renders on change. */
export function useTimeFormat(): TimeFormat {
  const [fmt, setFmt] = useState<TimeFormat>(getTimeFormat)
  useEffect(() => {
    const update = () => setFmt(getTimeFormat())
    window.addEventListener(EVENT, update)
    window.addEventListener('storage', update)
    return () => {
      window.removeEventListener(EVENT, update)
      window.removeEventListener('storage', update)
    }
  }, [])
  return fmt
}
