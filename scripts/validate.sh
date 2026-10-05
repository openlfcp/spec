#!/usr/bin/env bash
# Validation entry point for the spec repository.
#
# 1. every JSON file parses;
# 2. the vector suites and format fixtures match the lfcp-vector-format/1
#    schema (scripts/validate-vectors.mjs);
# 3. the lfcp-vector-format/1 migration changed no vector value
#    (scripts/check-vector-migration.mjs; needs full Git history).
#
# Run `pnpm install --frozen-lockfile` first.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d node_modules ]; then
  echo "spec: node_modules missing; run 'pnpm install --frozen-lockfile' first" >&2
  exit 1
fi

count=0
while IFS= read -r -d '' file; do
  node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$file"
  count=$((count + 1))
done < <(find . -name '*.json' -not -path './.git/*' -not -path '*/node_modules/*' -not -path './.venv/*' -print0)
echo "spec: ${count} JSON file(s) parsed"

node scripts/validate-vectors.mjs
node scripts/check-vector-migration.mjs
