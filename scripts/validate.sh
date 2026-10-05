#!/usr/bin/env bash
# Validation entry point for the spec repository.
#
# 1. every JSON file parses;
# 2. the vector suites and format fixtures match the lfcp-vector-format/1
#    schema (scripts/validate-vectors.mjs);
# 3. the lfcp-vector-format/1 migration changed no vector value
#    (scripts/check-vector-migration.mjs; needs full Git history);
# 4. wire/LFCP-WIRE-01*.cddl match the CDDL blocks of wire/LFCP-WIRE-01.md
#    (scripts/extract-cddl.mjs --check);
# 5. the Wire CDDL compiles, agrees with its Part XXVIII summary and accepts
#    or rejects every fixture in wire/fixtures/manifest.json
#    (scripts/check-cddl.rb, with the cddl gem);
# 6. the Shared Objects structural contract accepts its valid fixtures,
#    rejects its invalid ones at the expected fields, and agrees with the
#    Shared Objects vectors (scripts/validate-shared-objects.mjs);
# 7. MVP-0.1-BASELINE.md lists exactly the canonical files
#    (scripts/check-baseline.mjs).
#
# Run `pnpm install --frozen-lockfile` and `bundle install` first.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d node_modules ]; then
  echo "spec: node_modules missing; run 'pnpm install --frozen-lockfile' first" >&2
  exit 1
fi
if ! bundle check >/dev/null 2>&1; then
  echo "spec: Ruby gems missing; run 'bundle install' first" >&2
  exit 1
fi

count=0
while IFS= read -r -d '' file; do
  node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$file"
  count=$((count + 1))
done < <(find . -name '*.json' -not -path './.git/*' -not -path '*/node_modules/*' -not -path './.venv/*' -not -path './vendor/*' -print0)
echo "spec: ${count} JSON file(s) parsed"

node scripts/validate-vectors.mjs
node scripts/check-vector-migration.mjs
node scripts/extract-cddl.mjs --check
bundle exec ruby scripts/check-cddl.rb
node scripts/validate-shared-objects.mjs
node scripts/check-baseline.mjs
