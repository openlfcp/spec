#!/usr/bin/env node
// Shared Objects structural contract checks (LFCP-006).
//
// 1. State fixtures in profiles/shared-objects-01/schema/fixtures/:
//    valid-*.json MUST pass; each invalid-*.json MUST report exactly the
//    problem pointers listed in expected.json.
// 2. SHARED-OBJECTS-TEST-VECTORS-01 consistency: every Task, object map and
//    field value that the behavioral scenarios S01-S14 state or write MUST
//    satisfy the contract.
// 3. The invalid vectors I01-I07 and the Object ID vectors D06-D08 MUST be
//    classified as the vector says, invalid at the expected field.
//
// Problem lines: <source> <case-id|-> <json-pointer> <reason>

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { rootProblems, fieldProblems, objectProblems, transitionProblems } from "./lib/shared-objects-checks.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixtureDir = join(root, "profiles/shared-objects-01/schema/fixtures");
const suitePath = "test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json";
const suite = JSON.parse(readFileSync(join(root, suitePath), "utf8"));
const SUITE = suite.suite.id;
const readJson = (name) => JSON.parse(readFileSync(join(fixtureDir, name), "utf8"));
const escape = (key) => String(key).replace(/~/g, "~0").replace(/\//g, "~1");
const sameSet = (a, b) => JSON.stringify([...new Set(a)].sort()) === JSON.stringify([...new Set(b)].sort());

let failures = 0;
const fail = (line) => {
  failures += 1;
  console.log(line);
};

// 1. Fixtures.
const files = readdirSync(fixtureDir).filter((f) => f.endsWith(".json") && f !== "expected.json").sort();
const expected = JSON.parse(readFileSync(join(fixtureDir, "expected.json"), "utf8")).cases;
for (const name of files) {
  const problems = rootProblems(readJson(name));
  if (name.startsWith("valid-")) {
    if (problems.length === 0) console.log(`ok    fixtures/${name}`);
    else problems.forEach((p) => fail(`fixtures/${name} - ${p.pointer} ${p.reason}`));
  } else if (!(name in expected)) {
    fail(`fixtures/${name} - / self-test: no entry in expected.json`);
  } else {
    const got = problems.map((p) => p.pointer);
    if (problems.length > 0 && sameSet(got, expected[name].pointers)) {
      console.log(`ok    fixtures/${name} (invalid at ${expected[name].pointers.join(", ")})`);
    } else {
      fail(`fixtures/${name} - / self-test: reported ${JSON.stringify(got)}, expected ${JSON.stringify(expected[name].pointers)}`);
    }
  }
}

// 2. Scenario consistency.
const cases = suite.cases;
const index = new Map(cases.map((c, i) => [c.id, i]));
const baseTask = cases[index.get("S01")].inputs.branches[0].args;
const TASK_FIELDS = ["title", "status", "lifecycle", "priority", "due", "scheduled", "completion_date"];

for (const c of cases.filter((x) => x.type === "behavioral")) {
  const at = `/cases/${index.get(c.id)}`;
  const checks = [];
  const object = (ptr, obj, key) => checks.push(() => objectProblems(obj, key).map((p) => [`${ptr}${p.pointer === "/" ? "" : p.pointer}`, p.reason]));
  const objects = (ptr, map) => Object.entries(map).forEach(([k, o]) => object(`${ptr}/${escape(k)}`, o, k));
  const field = (ptr, f, value) => checks.push(() => fieldProblems(baseTask, f, value).map((p) => [ptr, p.reason]));
  const tag = (ptr, t) => checks.push(() => fieldProblems(baseTask, "tags", { [t]: true }).map((p) => [ptr, p.reason]));
  const principal = (ptr, r) => checks.push(() => fieldProblems(baseTask, "assignees", { [r]: true }).map((p) => [ptr, p.reason]));

  const bs = c.inputs.base_state ?? {};
  if (bs.type === "task") object(`${at}/inputs/base_state`, bs);
  if (bs.task) object(`${at}/inputs/base_state/task`, bs.task);
  if (bs.objects) objects(`${at}/inputs/base_state/objects`, bs.objects);
  (c.inputs.branches ?? []).forEach((b, j) => {
    const bp = `${at}/inputs/branches/${j}`;
    if (b.intent === "task.create" && b.args) object(`${bp}/args`, b.args);
    if (b.object) object(`${bp}/object`, b.object);
    for (const [f, v] of Object.entries(b.writes ?? {})) if (TASK_FIELDS.includes(f)) field(`${bp}/writes/${f}`, f, v);
    if (typeof b.tag === "string") tag(`${bp}/tag`, b.tag);
    if (typeof b.principal === "string") principal(`${bp}/principal`, b.principal);
  });
  const ex = c.expected ?? {};
  if (ex.objects) objects(`${at}/expected/objects`, ex.objects);
  for (const [k, v] of Object.entries(ex)) {
    const ep = `${at}/expected/${escape(k)}`;
    if (TASK_FIELDS.includes(k)) field(ep, k, v);
    if (k === "task_status") field(ep, "status", v);
    if (k === "tags" && Array.isArray(v)) v.forEach((t, j) => tag(`${ep}/${j}`, t));
    if (k === "assignees" && Array.isArray(v)) v.forEach((r, j) => principal(`${ep}/${j}`, r));
    const m = /^(.+)_(conflict_set|values_may_include)$/.exec(k);
    if (m && TASK_FIELDS.includes(m[1]) && Array.isArray(v)) v.forEach((x, j) => field(`${ep}/${j}`, m[1], x));
  }
  const problems = checks.flatMap((run) => run());
  problems.forEach(([ptr, reason]) => fail(`${SUITE} ${c.id} ${ptr} ${reason}`));
  if (problems.length === 0) console.log(`ok    ${SUITE} ${c.id}: ${checks.length} state/field value(s) satisfy the contract`);
}

// 3. Invalid and Object ID vectors.
const K = suite.fixtures.objects.task_1;
const baseRoot = { profile: "org.openlfcp.shared-objects.v1", objects: { [K]: baseTask }, extensions: {} };
const INVALID = {
  I01: [`/objects/${K}/id`],
  I02: ["/objects/NOT-A-UUID"],
  I03: [`/objects/${K}/title`],
  I04: [`/objects/${K}/due`],
  I05: [`/objects/${K}/tags`],
  I06: [`/objects/${K}/assignees/not-a-principal`],
  I07: [`/objects/${K}/type`],
};
for (const [id, wanted] of Object.entries(INVALID)) {
  const c = cases[index.get(id)];
  const m = c.inputs.mutation;
  const after = structuredClone(baseRoot);
  if ("field" in m) after.objects[m.object_key][m.field] = m.value;
  else after.objects[m.object_key] = m.value;
  const problems = [...rootProblems(after), ...transitionProblems(baseRoot, after)];
  const hits = problems.filter((p) => wanted.some((w) => p.pointer === w || p.pointer.startsWith(`${w}/`)));
  if (c.expected.valid === false && hits.length > 0) {
    console.log(`ok    ${SUITE} ${id}: invalid at ${wanted.join(", ")} (${[...new Set(hits.map((p) => p.reason.split(":")[0]))].join(", ")})`);
  } else {
    fail(`${SUITE} ${id} ${wanted[0]} classification: expected invalid at this field, got ${JSON.stringify(problems)}`);
  }
}
for (const id of ["D06-uuidv7-valid", "D07-uuid-invalid-uppercase", "D08-uuid-invalid-version"]) {
  const c = cases[index.get(id)];
  const value = c.inputs.object_id;
  const problems = rootProblems({ ...baseRoot, objects: { [value]: { ...baseTask, id: value } } });
  const valid = problems.length === 0;
  if (valid === c.expected.valid) console.log(`ok    ${SUITE} ${id}: object id ${valid ? "valid" : "invalid"} as expected`);
  else fail(`${SUITE} ${id} /cases/${index.get(id)}/inputs/object_id classification: expected valid=${c.expected.valid}`);
}

console.log(`shared-objects: ${failures} problem(s)`);
process.exit(failures === 0 ? 0 : 1);
