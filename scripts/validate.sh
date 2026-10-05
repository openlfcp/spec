#!/usr/bin/env bash
# Validation entry point for the spec repository.
#
# Placeholder until the test-vector format and schema checks land
# (LFCP-004). For now it only checks that every JSON file in the
# repository parses.
set -euo pipefail

cd "$(dirname "$0")/.."

count=0
while IFS= read -r -d '' file; do
  node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$file"
  count=$((count + 1))
done < <(find . -name '*.json' -not -path './.git/*' -not -path '*/node_modules/*' -print0)

echo "spec: ${count} JSON file(s) parsed"
