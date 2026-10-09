#!/usr/bin/env node
// Proves that the move of the vector suites to lfcp-vector-format/1 (LFCP-004)
// changed no value.
//
// For each mapping file in migrations/vector-format-1/, the suite as it was at
// the baseline commit is read from Git and compared with the current file:
//
// 1. every leaf value of the old file is found, unchanged, at the new location
//    given by the mapping's `moves` (or is listed in `structural` because the
//    new format encodes it as structure, e.g. the case type);
// 2. no two old values land on the same new location, so the multiset of old
//    values equals the multiset of values at their new locations;
// 3. every other leaf of the new file is explained by an `added` rule.
//    Cases whose ID did not exist at migration time are skipped, so later
//    additions to a suite do not break this check.
//
// A later, explicitly approved change to a migrated value is listed under
// `changed` (old path, old value, new value, approval). Such a value must
// match both sides exactly and is left out of the multiset comparison. A
// new value of null means the value was removed: it must be absent from the
// new file.
//
// Path syntax in mapping files: dot-separated keys; `name[id=X]` selects the
// array element whose `id` is X; `[N]` the element at index N; `*` matches
// any key, `[id=*]` any id and `[*]` any element; `$1`, `$2`, ... insert
// what the wildcards matched (for `[*]`, the index).
//
// A move may name an encoding as a third element: "base64url" means the old
// value is standard base64 and the new one the same bytes as unpadded
// base64url (RFC 4648 §4, §5); the bytes, not the strings, must be equal.
// A mapping's `old_id_lists` replaces the default list of old top-level
// arrays whose elements are addressed by their `id`.

import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const mappingDir = join(root, "migrations", "vector-format-1");

// Top-level arrays whose elements are addressed by their `id`.
const OLD_ID_LISTS = new Set(["deterministic_vectors", "behavioral_scenarios", "invalid_cases"]);
const NEW_ID_LISTS = new Set(["cases"]);

const segText = (seg) =>
  "key" in seg ? seg.key : "id" in seg ? `[id=${seg.id}]` : "index" in seg ? `[${seg.index}]` : "[*]";
const pathText = (segs) => segs.map((s, i) => (i > 0 && "key" in s ? "." : "") + segText(s)).join("");

function parsePath(text) {
  const segs = [];
  for (const part of text.split(".")) {
    const m = /^([^[\]]+)?(?:\[(?:id=([^\]]*)|(\*)|(\d+))\])?$/.exec(part);
    if (!m) throw new Error(`bad mapping path: ${text}`);
    if (m[1] !== undefined) segs.push({ key: m[1] });
    if (m[2] !== undefined) segs.push({ id: m[2] });
    if (m[3] !== undefined) segs.push({ any: true });
    if (m[4] !== undefined) segs.push({ index: Number(m[4]) });
  }
  return segs;
}

function flatten(doc, idLists) {
  const leaves = [];
  const walk = (value, segs) => {
    if (Array.isArray(value) && value.length > 0) {
      const byId = segs.length === 1 && idLists.has(segs[0].key);
      value.forEach((item, index) =>
        walk(item, [...segs, byId ? { id: String(item.id) } : { index }]),
      );
    } else if (value !== null && typeof value === "object" && Object.keys(value).length > 0) {
      for (const [key, item] of Object.entries(value)) walk(item, [...segs, { key }]);
    } else {
      leaves.push({ segs, value });
    }
  };
  walk(doc, []);
  return leaves;
}

// Matches rule segments against the start of a concrete path; returns the
// wildcard captures, or null.
function matchPrefix(rule, segs, whole) {
  if (rule.length > segs.length || (whole && rule.length !== segs.length)) return null;
  const captures = [];
  for (let i = 0; i < rule.length; i += 1) {
    const r = rule[i];
    const s = segs[i];
    if ("key" in r) {
      if (!("key" in s)) return null;
      if (r.key === "*") captures.push(s.key);
      else if (r.key !== s.key) return null;
    } else if ("id" in r) {
      if (!("id" in s)) return null;
      if (r.id === "*") captures.push(s.id);
      else if (r.id !== s.id) return null;
    } else if ("key" in s) {
      return null;
    } else if ("index" in r) {
      if (!("index" in s) || r.index !== s.index) return null;
    } else if ("index" in s) {
      captures.push(String(s.index));
    }
  }
  return captures;
}

const substitute = (text, captures) => text.replace(/\$(\d+)/g, (_, n) => captures[Number(n) - 1]);

function getAt(doc, segs) {
  let node = doc;
  for (const seg of segs) {
    if ("key" in seg) {
      if (node === null || typeof node !== "object" || Array.isArray(node) || !(seg.key in node)) return { found: false };
      node = node[seg.key];
    } else if ("id" in seg) {
      if (!Array.isArray(node)) return { found: false };
      const hits = node.filter((item) => item && String(item.id) === seg.id);
      if (hits.length !== 1) return { found: false };
      node = hits[0];
    } else {
      if (!Array.isArray(node) || seg.index >= node.length) return { found: false };
      node = node[seg.index];
    }
  }
  return { found: true, value: node };
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function checkSuite(mappingFile) {
  const mapping = JSON.parse(readFileSync(mappingFile, "utf8"));
  const errors = [];
  let oldText;
  try {
    oldText = execFileSync("git", ["show", `${mapping.baseline_commit}:${mapping.suite_file}`], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 256 * 1024 * 1024,
    });
  } catch {
    throw new Error(
      `cannot read ${mapping.suite_file} at baseline ${mapping.baseline_commit}; ` +
        "this check needs the repository's full Git history (e.g. actions/checkout with fetch-depth: 0)",
    );
  }
  const oldDoc = JSON.parse(oldText);
  if (oldDoc.format === "lfcp-vector-format/1") throw new Error(`${mapping.suite_file} at the baseline is already in the new format`);
  const oldIdLists = mapping.old_id_lists ? new Set(mapping.old_id_lists) : OLD_ID_LISTS;
  const newDoc = JSON.parse(readFileSync(join(root, mapping.suite_file), "utf8"));

  const moves = mapping.moves.map(([from, to, encoding]) => ({ from: parsePath(from), to, encoding }));
  const encode = (encoding, value) =>
    encoding === "base64url" ? Buffer.from(value, "base64").toString("base64url") : value;
  const structural = mapping.structural.map((r) => ({ ...r, segs: parsePath(r.path) }));
  const added = mapping.added.map((r) => ({ ...r, segs: parsePath(r.path) }));
  const changed = new Map((mapping.changed ?? []).map((r) => [r.path, r]));
  const changedValues = [];

  const claimed = new Map();
  const oldValues = [];
  const newValues = [];
  let structuralCount = 0;

  for (const leaf of flatten(oldDoc, oldIdLists)) {
    const where = pathText(leaf.segs);
    let target = null;
    for (const move of moves) {
      const captures = matchPrefix(move.from, leaf.segs, false);
      if (captures) {
        target = [...parsePath(substitute(move.to, captures)), ...leaf.segs.slice(move.from.length)];
        if (move.encoding) {
          if (typeof leaf.value !== "string" || Buffer.from(leaf.value, "base64").toString("base64") !== leaf.value) {
            errors.push(`old value at ${where} is not canonical base64`);
          }
          leaf.value = encode(move.encoding, leaf.value);
        }
        break;
      }
    }
    if (!target) {
      const rule = structural.find((r) => matchPrefix(r.segs, leaf.segs, true));
      if (rule && same(rule.value, leaf.value)) structuralCount += 1;
      else errors.push(`old value at ${where} has no mapping`);
      continue;
    }
    const targetText = pathText(target);
    const found = getAt(newDoc, target);
    if (!found.found) {
      const approved = changed.get(where);
      if (approved && approved.to === null && same(approved.from, leaf.value)) {
        changedValues.push(`${where}: removed; ${approved.rule}`);
        continue;
      }
      errors.push(`old value at ${where} is missing from the new file (expected at ${targetText})`);
    } else if (!same(found.value, leaf.value)) {
      const approved = changed.get(where);
      if (approved && same(approved.from, leaf.value) && same(approved.to, found.value)) {
        changedValues.push(`${where}: ${approved.rule}`);
        claimed.set(targetText, where);
        continue;
      }
      errors.push(`value changed: ${where} = ${JSON.stringify(leaf.value)} but ${targetText} = ${JSON.stringify(found.value)}`);
    }
    if (claimed.has(targetText)) {
      errors.push(`two old values map to ${targetText}: ${claimed.get(targetText)} and ${where}`);
    }
    claimed.set(targetText, where);
    oldValues.push(JSON.stringify(leaf.value));
    newValues.push(JSON.stringify(found.value));
  }

  // A case counts as migrated when any old value moved into it; cases with
  // other IDs were added after the migration and are not checked here.
  const migratedCaseIds = new Set(
    [...claimed.keys()].map((p) => /^cases\[id=([^\]]*)\]/.exec(p)?.[1]).filter(Boolean),
  );
  const newLeaves = flatten(newDoc, NEW_ID_LISTS);
  const addedValues = [];
  let skipped = 0;
  for (const leaf of newLeaves) {
    const where = pathText(leaf.segs);
    if (claimed.has(where)) continue;
    const caseSeg = leaf.segs[0]?.key === "cases" ? leaf.segs[1] : null;
    if (caseSeg && "id" in caseSeg && !migratedCaseIds.has(caseSeg.id)) {
      skipped += 1;
      continue;
    }
    const rule = added.find((r) => matchPrefix(r.segs, leaf.segs, true));
    if (!rule) {
      errors.push(`new value at ${where} = ${JSON.stringify(leaf.value)} is not explained by the mapping`);
    } else if ("value" in rule && !same(rule.value, leaf.value)) {
      errors.push(`added value at ${where} = ${JSON.stringify(leaf.value)}, mapping allows ${JSON.stringify(rule.value)}`);
    } else {
      addedValues.push(`${where} = ${JSON.stringify(leaf.value)}`);
    }
  }

  const multisetEqual = same([...oldValues].sort(), [...newValues].sort());
  if (!multisetEqual) errors.push("multiset of old values differs from multiset of values at their new locations");

  return {
    suite: mapping.suite_file,
    baseline: mapping.baseline_commit,
    oldLeaves: oldValues.length + structuralCount + changedValues.length,
    changed: changedValues,
    moved: oldValues.length,
    structural: structuralCount,
    newLeaves: newLeaves.length,
    added: addedValues,
    skipped,
    multisetEqual,
    errors,
  };
}

const verbose = process.argv.includes("--verbose");
let failed = false;
const files = readdirSync(mappingDir).filter((f) => f.endsWith(".mapping.json")).sort();
for (const file of files) {
  const r = checkSuite(join(mappingDir, file));
  const status = r.errors.length === 0 ? "ok  " : "FAIL";
  console.log(`${status}  ${r.suite} (baseline ${r.baseline.slice(0, 12)})`);
  console.log(
    `      old leaves ${r.oldLeaves}: moved unchanged ${r.moved}, encoded as structure ${r.structural}; ` +
      `new leaves ${r.newLeaves}: moved ${r.moved}, added ${r.added.length}, outside migrated cases ${r.skipped}`,
  );
  for (const c of r.changed) console.log(`      changed with approval: ${c}`);
  console.log(`      multiset of ${r.moved} old values == values at their new locations: ${r.multisetEqual}`);
  if (verbose) for (const a of r.added) console.log(`      added ${a}`);
  for (const e of r.errors) console.log(`      ${e}`);
  failed ||= r.errors.length > 0;
}
process.exit(failed ? 1 : 0);
