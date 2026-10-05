#!/usr/bin/env node
// Proves that a new MVP 0.1 baseline changed no published vector value
// except the ones its decisions approve.
//
// For each suite listed in migrations/mvp-0.1-baseline.3/value-changes.json,
// the suite at the previous baseline tag is read from Git and compared leaf
// by leaf with the current file. Cases are addressed by their `id`.
//
// - A value present at the previous baseline must be unchanged at the same
//   path, unless `changed` lists that path with the old value (`from`), the
//   new value (`to`, or null when the value was removed) and the approving
//   decision (`rule`).
// - New values (new cases, or new fields in existing cases) are allowed;
//   they are counted and listed with --verbose. An added value that changes
//   what an existing case means may be listed explicitly with `from: null`.
// - Every `changed` entry must match a real difference, so the list cannot
//   go stale.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const manifestFile = join(root, "migrations", "mvp-0.1-baseline.3", "value-changes.json");

// Leaves of a suite as path -> JSON value. `cases` elements are keyed by id.
function flatten(doc) {
  const leaves = new Map();
  const walk = (value, path) => {
    if (Array.isArray(value) && value.length > 0) {
      const byId = path === "cases";
      value.forEach((item, index) => walk(item, byId ? `${path}[id=${item.id}]` : `${path}[${index}]`));
    } else if (value !== null && typeof value === "object" && Object.keys(value).length > 0) {
      for (const [key, item] of Object.entries(value)) walk(item, path ? `${path}.${key}` : key);
    } else {
      leaves.set(path, JSON.stringify(value));
    }
  };
  walk(doc, "");
  return leaves;
}

const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
const verbose = process.argv.includes("--verbose");
let failed = false;

for (const suite of manifest.suites) {
  let oldText;
  try {
    oldText = execFileSync("git", ["show", `${manifest.previous_baseline}:${suite.suite_file}`], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    throw new Error(`cannot read ${suite.suite_file} at ${manifest.previous_baseline}; this check needs the tag and full history`);
  }
  const before = flatten(JSON.parse(oldText));
  const after = flatten(JSON.parse(readFileSync(join(root, suite.suite_file), "utf8")));
  const changed = new Map(suite.changed.map((c) => [c.path, c]));
  const errors = [];
  const used = new Set();
  let unchanged = 0;

  for (const [path, value] of before) {
    const now = after.get(path);
    if (now === value) {
      unchanged += 1;
      continue;
    }
    const entry = changed.get(path);
    const expectedNow = entry && entry.to === null ? undefined : JSON.stringify(entry?.to);
    if (entry && JSON.stringify(entry.from) === value && expectedNow === now) {
      used.add(path);
    } else if (now === undefined) {
      errors.push(`value removed without approval: ${path} = ${value}`);
    } else {
      errors.push(`value changed without approval: ${path} = ${value} -> ${now}`);
    }
  }
  for (const [path, entry] of changed) {
    if (used.has(path) || entry.from !== null) continue;
    if (!before.has(path) && after.get(path) === JSON.stringify(entry.to)) used.add(path);
  }
  for (const path of changed.keys()) {
    if (!used.has(path)) errors.push(`changed entry does not match a difference: ${path}`);
  }
  const added = [...after.keys()].filter((path) => !before.has(path));

  const status = errors.length === 0 ? "ok  " : "FAIL";
  console.log(`${status}  ${suite.suite_file} (vs ${manifest.previous_baseline})`);
  console.log(`      ${before.size} values at the previous baseline: unchanged ${unchanged}, changed with approval ${used.size}; added ${added.length}`);
  if (verbose) {
    for (const path of used) console.log(`      changed: ${path} (${changed.get(path).rule})`);
    for (const path of added) console.log(`      added: ${path}`);
  }
  for (const e of errors) console.log(`      ${e}`);
  failed ||= errors.length > 0;
}
process.exit(failed ? 1 : 0);
