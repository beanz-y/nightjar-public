import { createHash } from 'node:crypto'
import { type Plugin, defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// App build config (DESIGN 10.1, 10.2). Vitest config lives separately in
// vitest.config.ts to avoid the dual-Vite type clash (Vitest bundles its own
// Vite), and because the crypto tests run in Node and need no React plugin.
//
//  - modulePreload.polyfill = false avoids Vite's injected INLINE preload
//    script, so the built index.html carries no inline <script> and runs under
//    a `script-src 'self'` CSP with no 'unsafe-inline'.
//  - __APP_VERSION__ comes from an env var, never a build clock, so two builds
//    of the same source produce byte-identical output.
//  - sri() stamps subresource-integrity attributes into the built index.html
//    (DESIGN 10.2): the entry HTML then pins the exact script/style bytes it
//    will run, and the Integrity-Policy header (public/_headers) makes a
//    script without integrity metadata a hard failure in supporting browsers.
//    Deterministic (a pure function of emitted content), so reproducible
//    builds are unaffected.

function sri(): Plugin {
  const b64Sha256 = (data: string | Uint8Array): string =>
    'sha256-' + createHash('sha256').update(data).digest('base64')
  return {
    name: 'nightjar-sri',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const html = bundle['index.html']
      if (!html || html.type !== 'asset' || typeof html.source !== 'string') return
      const integrityFor = (path: string): string | null => {
        const item = bundle[path.replace(/^\//, '')]
        if (!item) return null
        return b64Sha256(item.type === 'chunk' ? item.code : (item.source as string | Uint8Array))
      }
      let out = html.source as string
      // <script ... src="/assets/x.js"> (module entry chunks).
      out = out.replace(/<script([^>]*?)\ssrc="([^"]+)"([^>]*?)>/g, (m, pre, src, post) => {
        const sri = integrityFor(src)
        if (!sri || m.includes('integrity=')) return m
        return `<script${pre} src="${src}"${post} integrity="${sri}">`
      })
      // <link rel="stylesheet" href> and <link rel="modulepreload" href>.
      out = out.replace(/<link([^>]*?)\shref="([^"]+)"([^>]*?)>/g, (m, pre, href, post) => {
        if (!/rel="(stylesheet|modulepreload)"/.test(m) || m.includes('integrity=')) return m
        const sri = integrityFor(href)
        if (!sri) return m
        return `<link${pre} href="${href}"${post} integrity="${sri}">`
      })
      html.source = out
    },
  }
}

export default defineConfig({
  plugins: [react(), sri()],
  define: {
    __APP_VERSION__: JSON.stringify(process.env.NIGHTJAR_VERSION ?? 'dev'),
  },
  build: {
    target: 'es2022',
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
})
