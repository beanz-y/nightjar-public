import { defineConfig } from 'vite'
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
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(process.env.NIGHTJAR_VERSION ?? 'dev'),
  },
  build: {
    target: 'es2022',
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
})
