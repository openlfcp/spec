#!/usr/bin/env node
// Protocol vector validator (LFCP-004 schema, LFCP-007 checks).
//
// - every test-vectors/*/*-TEST-VECTORS-*.json suite MUST pass the
//   lfcp-vector-format/1 schema (except the directories in OWN_FORMAT) and the checks in lib/vector-checks.mjs
//   (duplicate keys and ids, canonical b64url, hash recomputation,
//   deterministic encodings, cross-references);
// - every schemas/fixtures/valid-*.json format excerpt MUST pass the schema;
// - every schemas/fixtures/invalid-*.json fixture MUST fail the schema;
// - every self-test in schemas/fixtures/validator/ MUST produce exactly the
//   problem lines listed in schemas/fixtures/validator/expected.json.
//
// Each problem is printed on one line:
//
//   <suite> <case-id|-> <json-pointer> <reason>
//
// where <reason> starts with a stable code (schema/<keyword>, or one of the
// codes documented in lib/vector-checks.mjs).
//
// Run with --report to also print the hash-verification table.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import { duplicateKeys, semanticProblems, HASH_RULES, NOT_VERIFIED, ENCODING_RULES } from "./lib/vector-checks.mjs";
import { relevant, schemaReason } from "./lib/ajv-errors.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const schemaPath = join(root, "schemas", "lfcp-vector-format-1.schema.json");
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(schema);
const branchSchema = (name) => ajv.getSchema(`${schema.$id}#/$defs/${name}`);
const CASE_BRANCHES = { bytes: "bytes_case", validation: "validation_case", behavioral: "behavioral_case" };

const rel = (path) => relative(root, path);
const listJson = (dir, pattern) =>
  readdirSync(dir)
    .filter((name) => pattern.test(name))
    .sort()
    .map((name) => join(dir, name));

function schemaProblems(doc) {
  if (validate(doc)) return [];
  const problems = [];
  const caseErrors = new Map();
  for (const e of validate.errors) {
    const m = /^\/cases\/(\d+)(?=\/|$)/.exec(e.instancePath);
    if (m && doc.cases?.[Number(m[1])] && typeof doc.cases[Number(m[1])] === "object") {
      caseErrors.set(Number(m[1]), true);
    } else {
      problems.push(e);
    }
  }
  const out = relevant(problems).map((e) => ({ caseId: null, pointer: e.instancePath || "/", reason: schemaReason(e) }));
  for (const index of caseErrors.keys()) {
    const c = doc.cases[index];
    const check = branchSchema(CASE_BRANCHES[c.type] ?? "case_common");
    if (check(c)) continue;
    for (const e of relevant(check.errors)) {
      out.push({ caseId: typeof c.id === "string" ? c.id : null, pointer: `/cases/${index}${e.instancePath}`, reason: schemaReason(e) });
    }
  }
  return out;
}

// All problems for one file, as formatted lines.
function check(path) {
  const text = readFileSync(path, "utf8");
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return { lines: [`${rel(path)} - / bad-json: ${e.message}`], stats: new Map() };
  }
  const suite = typeof doc?.suite?.id === "string" ? doc.suite.id : rel(path);
  const problems = [...duplicateKeys(text), ...schemaProblems(doc)];
  let stats = new Map();
  if (problems.length === 0) {
    const result = semanticProblems(doc);
    problems.push(...result.problems);
    stats = result.stats;
  }
  const lines = problems.map((p) => `${suite} ${p.caseId ?? "-"} ${p.pointer} ${p.reason}`);
  return { suite, lines, stats };
}

let failures = 0;
const fail = (line) => {
  failures += 1;
  console.log(line);
};

// 1. Published suites. A suite in its own format until it moves to
// lfcp-vector-format/1 is checked by its own script instead.
// Directories whose suites have their own format and checker (none now: the
// shared sections corpus moved to lfcp-vector-format/1, LFCP-02-107).
const OWN_FORMAT = new Map();
const suites = readdirSync(join(root, "test-vectors"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && !OWN_FORMAT.has(entry.name))
  .flatMap((entry) => listJson(join(root, "test-vectors", entry.name), /-TEST-VECTORS-\d+\.json$/));
if (suites.length === 0) fail("- - / no-suites: no vector suites found under test-vectors/");
const verified = [];
for (const path of suites) {
  const { suite, lines, stats } = check(path);
  lines.forEach(fail);
  const total = [...stats.values()].reduce((a, b) => a + b, 0);
  if (lines.length === 0) console.log(`ok    ${rel(path)} (${suite}: ${total} hash value(s) recomputed)`);
  verified.push({ suite, stats });
}

// 2. Format fixtures (LFCP-004).
const fixtureDir = join(root, "schemas", "fixtures");
// These are excerpts that illustrate the format, so only the schema applies;
// suite-integrity checks (cross-references) would need the whole suite.
for (const path of listJson(fixtureDir, /^valid-.*\.json$/)) {
  const doc = JSON.parse(readFileSync(path, "utf8"));
  const lines = schemaProblems(doc).map((p) => `${doc.suite?.id ?? rel(path)} ${p.caseId ?? "-"} ${p.pointer} ${p.reason}`);
  if (lines.length === 0) console.log(`ok    ${rel(path)}`);
  else lines.forEach(fail);
}
for (const path of listJson(fixtureDir, /^invalid-.*\.json$/)) {
  if (validate(JSON.parse(readFileSync(path, "utf8")))) fail(`${rel(path)} - / self-test: expected schema rejection, but it validated`);
  else console.log(`ok    ${rel(path)} (rejected as expected)`);
}

// 3. Validator self-tests: exact expected problem lines.
const selfDir = join(fixtureDir, "validator");
const expected = JSON.parse(readFileSync(join(selfDir, "expected.json"), "utf8")).cases;
const selfFiles = listJson(selfDir, /^(?!expected\.json$).*\.json$/).map((p) => p.split("/").pop());
for (const name of selfFiles) {
  if (!(name in expected)) fail(`${rel(join(selfDir, name))} - / self-test: no entry in expected.json`);
}
for (const [name, want] of Object.entries(expected)) {
  const { lines } = check(join(selfDir, name));
  const got = [...lines].sort();
  const wanted = [...want.problems].sort();
  if (JSON.stringify(got) === JSON.stringify(wanted)) {
    console.log(`ok    ${rel(join(selfDir, name))} (${want.covers}: ${lines.length} expected problem(s))`);
  } else {
    fail(`${rel(join(selfDir, name))} - / self-test: problem lines differ from expected.json`);
    for (const l of wanted.filter((x) => !got.includes(x))) console.log(`      missing:    ${l}`);
    for (const l of got.filter((x) => !wanted.includes(x))) console.log(`      unexpected: ${l}`);
  }
}

if (process.argv.includes("--report")) {
  console.log("\nhash recomputation:");
  for (const rule of HASH_RULES) console.log(`  ${rule.field}: ${rule.section}`);
  console.log("  fixtures actor_*_hex: SHARED-OBJECTS-PROFILE-01 §8");
  for (const { suite, stats } of verified) {
    console.log(`  ${suite}: ${[...stats].map(([k, v]) => `${k} ${v}`).join(", ")}`);
  }
  console.log("deterministic encodings checked:");
  for (const e of ENCODING_RULES) console.log(`  ${e}`);
  console.log("not verified:");
  for (const [field, reason] of NOT_VERIFIED) console.log(`  ${field}: ${reason}`);
}

console.log(`vectors: ${failures} problem(s)`);
process.exit(failures === 0 ? 0 : 1);
