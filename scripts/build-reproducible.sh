#!/usr/bin/env bash
# Deterministic local build (DESIGN.md 10.1, DESIGN 10). Mirrors
# Dockerfile.build without a container, for developers reproducing a release on a
# matching Node version (see .nvmrc). The container remains the canonical path
# because it also pins the OS and toolchain; this script pins only app-level inputs.
#
# What actually delivers determinism here (DESIGN 10): lockfile-pinned tool
# versions (`npm ci`), no build-time dynamic values (__APP_VERSION__ comes from an
# env var, never a clock), and content-derived asset filenames. SOURCE_DATE_EPOCH
# is exported below for parity with archive-based toolchains, but it is INERT here:
# vite/rollup/esbuild do not consume it and the release manifest hashes file
# CONTENT only (no mtimes). It is kept as a harmless, documented no-op.
set -euo pipefail

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1577836800}"   # inert here; see above
export NIGHTJAR_VERSION="${NIGHTJAR_VERSION:-repro}"

echo "Node:              $(node --version)  (expected v$(cat .nvmrc))"
echo "NIGHTJAR_VERSION=  $NIGHTJAR_VERSION"

npm ci
npm run build

echo
echo "Canonical release hash (DESIGN 10 - the ONE recipe, also used by CI and"
echo "the canary; diff two independent builds' releaseHash to confirm byte-identity):"
# Single source of truth: never reimplement the hash here (MF5). Writes
# manifest.txt + release.json and prints the release hash.
node scripts/release-hash.mjs dist
