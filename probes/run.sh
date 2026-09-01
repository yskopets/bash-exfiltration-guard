#!/usr/bin/env bash
#
# Re-runs the parser comparison behind the choice of mvdan.cc/sh.
#
# Each candidate is handed the same six-command corpus (corpus.txt) and asked
# only one question: can you parse it? Dependencies are installed into a
# scratch directory so this leaves nothing behind.
#
#   ./probes/run.sh
#
set -u
cd "$(dirname "$0")"
work="${TMPDIR:-/tmp}/guard-parser-probes"
mkdir -p "$work"

echo "=== mvdan.cc/sh (Go) ==============================================="
(cd mvdan-sh && go run . < ../corpus.txt) || echo "  [skipped: go unavailable]"

echo
echo "=== bash-parser (JavaScript) ======================================="
if command -v npm >/dev/null; then
  mkdir -p "$work/bash-parser"
  (cd "$work/bash-parser" && npm install --silent --cache "$work/npm" bash-parser >/dev/null 2>&1)
  NODE_PATH="$work/bash-parser/node_modules" node bash-parser/probe.js corpus.txt
else
  echo "  [skipped: npm unavailable]"
fi

echo
echo "=== bashlex (Python) ==============================================="
if command -v python3 >/dev/null; then
  [ -d "$work/venv" ] || python3 -m venv "$work/venv" >/dev/null 2>&1
  "$work/venv/bin/pip" install -q bashlex >/dev/null 2>&1
  "$work/venv/bin/python3" bashlex/probe.py corpus.txt
else
  echo "  [skipped: python3 unavailable]"
fi

echo
echo "=== tree-sitter-bash (JavaScript) =================================="
if command -v npm >/dev/null; then
  mkdir -p "$work/tree-sitter"
  (cd "$work/tree-sitter" && npm install --silent --cache "$work/npm" tree-sitter tree-sitter-bash >/dev/null 2>&1)
  NODE_PATH="$work/tree-sitter/node_modules" node tree-sitter/probe.js corpus.txt
else
  echo "  [skipped: npm unavailable]"
fi
