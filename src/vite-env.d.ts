/// <reference types="vite/client" />

// Injected by vite.config.ts (define). Content-derived / env-provided, never a
// build clock, so the value does not break reproducible builds.
declare const __APP_VERSION__: string

interface ImportMetaEnv {
  readonly VITE_RELAY_ORIGIN?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
