#!/usr/bin/env bash
# FIXTURE — synthetic project used by the test suite and the offline demo.
#
# This file is a STATIC ANALYSIS TARGET. Agent Inspector reads it; it never runs
# it. The deletion below is deliberately project-local and fully reproducible,
# because it is the exact action the product walkthrough points at: the demo's
# destructiveness is the thing the inspector is supposed to surface.
#
# What the inspector says about that line (see tests/demo.test.js):
#   R001 · filesystem deletion · scope project-local · MODERATE
#   recommendation: allow project-local deletion, but require approval on first
#   execution and keep the path inside the workspace.
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-8787}"

mkdir -p demo/site

rm -rf demo/.state
mkdir -p demo/.state

cp demo/fixtures/v1.html demo/site/index.html

node demo/serve.mjs demo/site "$PORT" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 0.8

node bin/contentpulse.js run --config demo/sources.yaml
node bin/contentpulse.js run --config demo/sources.yaml --dry-run
ls -1 demo/.state/out
