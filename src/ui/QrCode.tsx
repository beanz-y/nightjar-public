// Renders a QR matrix (src/ui/qr.ts) as a self-contained, crisp SVG. No external
// libraries and no raster canvas, so it is safe under the strict CSP and scales
// to any size. The payload here is never secret (a safety number derives from
// PUBLIC identity keys; an invite URL is meant to be shared), so a display-only
// QR leaks nothing.

import { useMemo } from 'react'
import { qrMatrix } from './qr'

interface QrCodeProps {
  text: string
  /** Rendered pixel size of the square (excluding the quiet-zone margin). */
  size?: number
  /** Quiet-zone width in modules (spec recommends 4). */
  quiet?: number
  className?: string
}

export function QrCode({ text, size = 208, quiet = 4, className }: QrCodeProps) {
  const matrix = useMemo(() => {
    try {
      return qrMatrix(text)
    } catch {
      return null
    }
  }, [text])

  if (!matrix) return <div className="qr-error small muted">(could not render a QR for this value)</div>

  const n = matrix.length
  const dim = n + quiet * 2
  const rects: string[] = []
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (matrix[y][x]) rects.push(`M${x + quiet} ${y + quiet}h1v1h-1z`)
    }
  }

  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox={`0 0 ${dim} ${dim}`}
      role="img"
      aria-label="QR code"
      shapeRendering="crispEdges"
    >
      <rect width={dim} height={dim} fill="#ffffff" />
      <path d={rects.join('')} fill="#000000" />
    </svg>
  )
}
