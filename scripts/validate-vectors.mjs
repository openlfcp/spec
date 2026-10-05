#!/usr/bin/env node
// Schema-validates the published vector suites and the format fixtures
// against schemas/lfcp-vector-format-1.schema.json.
//
// - every test-vectors/*/*-TEST-VECTORS-*.json suite MUST validate;
// - every schemas/fixtures/valid-*.json fixture MUST validate;
// - every schemas/fixtures/invalid-*.json fixture MUST fail validation.
//
// Checks beyond the schema (hex/hash recomputation, cross-references) belong
// to the protocol vector validator (LFCP-007).

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const schemaPath = join(root, "schemas", "lfcp-vector-format-1.schema.json");

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(JSON.parse(readFileSync(schemaPath, "utf8")));

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const rel = (path) => relative(root, path);
const listJson = (dir, pattern) =>
  readdirSync(dir)
    .filter((name) => pattern.test(name))
    .sort()
    .map((name) => join(dir, name));

const suites = readdirSync(join(root, "test-vectors"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .flatMap((entry) => listJson(join(root, "test-vectors", entry.name), /-TEST-VECTORS-\d+\.json$/));
const fixtureDir = join(root, "schemas", "fixtures");
const mustPass = [...suites, ...listJson(fixtureDir, /^valid-.*\.json$/)];
const mustFail = listJson(fixtureDir, /^invalid-.*\.json$/);

let failures = 0;

for (const path of mustPass) {
  if (validate(readJson(path))) {
    console.log(`ok    ${rel(path)}`);
  } else {
    failures += 1;
    console.log(`FAIL  ${rel(path)}`);
    for (const error of validate.errors) {
      console.log(`      ${error.instancePath || "/"} ${error.message}`);
    }
  }
}

for (const path of mustFail) {
  if (validate(readJson(path))) {
    failures += 1;
    console.log(`FAIL  ${rel(path)} (expected schema rejection, but it validated)`);
  } else {
    console.log(`ok    ${rel(path)} (rejected as expected)`);
  }
}

if (suites.length === 0) {
  failures += 1;
  console.log("FAIL  no vector suites found under test-vectors/");
}

console.log(`vectors: ${mustPass.length + mustFail.length} file(s) checked, ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
