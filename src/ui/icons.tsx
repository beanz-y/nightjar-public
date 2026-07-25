// Inline SVG icons for the tile/menu affordances.
//
// These were originally Unicode glyphs (for example U+2B73 for "back up
// identity"), which is a font-coverage bet we lose on mobile: the Miscellaneous
// Symbols and Arrows and Miscellaneous Mathematical Symbols blocks are not in
// the default Android system fonts, so the glyph rendered as a tofu box on real
// phones. Drawing the icons ourselves removes the dependency on what fonts the
// device happens to ship.
//
// They are plain JSX (part of the one SRI-pinned bundle), stroke-only, and
// inherit their size and color from the parent via `currentColor`, so no CSP
// change, no external asset, and no new request. Decorative only: every one of
// them sits next to a real text label and the wrapper carries aria-hidden.

interface IconProps {
  /** Rendered size in px (the parent sets color). */
  size?: number
}

function Svg({ size = 22, children }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  )
}

/** Save/download: an arrow coming down into a tray. */
export function DownloadIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 3v11" />
      <path d="M7.5 10.5 12 15l4.5-4.5" />
      <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
    </Svg>
  )
}

/** Verify: a check inside a shield. */
export function ShieldCheckIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 3 5 6v6c0 4.2 2.8 7.6 7 9 4.2-1.4 7-4.8 7-9V6l-7-3Z" />
      <path d="m9 12 2 2 4-4" />
    </Svg>
  )
}

/** Scan: camera viewfinder corners around a QR-ish center. */
export function ScanIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 8.5V6a2 2 0 0 1 2-2h2.5" />
      <path d="M15.5 4H18a2 2 0 0 1 2 2v2.5" />
      <path d="M20 15.5V18a2 2 0 0 1-2 2h-2.5" />
      <path d="M8.5 20H6a2 2 0 0 1-2-2v-2.5" />
      <path d="M8 12h8" />
    </Svg>
  )
}

/** Type/paste a code: a keyboard. */
export function KeyboardIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="2.5" y="6" width="19" height="12" rx="2" />
      <path d="M6.5 9.5h.01M10 9.5h.01M13.5 9.5h.01M17 9.5h.01M6.5 13h.01M17 13h.01" />
      <path d="M9.5 15.5h5" />
    </Svg>
  )
}

/** Session-only (ephemeral): an eye with a slash, i.e. seen but not kept. Paired
 *  with a written strip above the compose bar when armed, never on its own: an
 *  icon alone would be a weaker signal than the text chip it replaced, and DESIGN
 *  8.7 requires the armed state to be unmissable. */
export function EphemeralIcon(props: IconProps) {
  return (
    <Svg size={props.size ?? 18}>
      <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" />
      <circle cx="12" cy="12" r="2.6" />
      <path d="M3.5 3.5l17 17" />
    </Svg>
  )
}

/** Invite someone new: a plus. */
export function PlusIcon(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </Svg>
  )
}
