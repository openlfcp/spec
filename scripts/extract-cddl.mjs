#!/usr/bin/env node
// Extracts the CDDL embedded in wire/LFCP-WIRE-01.md.
//
// The prose document stays the single source of truth. This script copies
// every ```cddl block, in document order, into:
//
//   wire/LFCP-WIRE-01.cddl          blocks from the body (Parts I-XXVII)
//   wire/LFCP-WIRE-01.summary.cddl  blocks from "Part XXVIII. Full CDDL Summary"
//
// The summary restates body rules, and CDDL forbids redefining a rule, so the
// two are kept apart; scripts/check-cddl.rb checks that they agree.
//
// A block that does not start with a rule definition (e.g. the bare `{}`
// unprotected header, or the unnamed Sig_structure array) is not valid CDDL on
// its own. It is copied as comments; wire/LFCP-WIRE-01.supplement.cddl gives
// it a name.
//
//   node scripts/extract-cddl.mjs          rewrite the .cddl files
//   node scripts/extract-cddl.mjs --check  fail if they are out of date

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = "wire/LFCP-WIRE-01.md";
const outputs = {
  body: "wire/LFCP-WIRE-01.cddl",
  summary: "wire/LFCP-WIRE-01.summary.cddl",
};
const SUMMARY_HEADING = /^# Part XXVIII\. Full CDDL Summary\s*$/;
const RULE_START = /^\s*([A-Za-z@_$][A-Za-z0-9@_$.-]*)\s*(?:<[^>]*>)?\s*(?:\/\/=|\/=|=)/;

const lines = readFileSync(join(root, source), "utf8").split("\n");

const blocks = [];
let section = "";
let part = "body";
for (let i = 0; i < lines.length; i += 1) {
  const line = lines[i];
  if (SUMMARY_HEADING.test(line)) part = "summary";
  if (/^#{1,4} /.test(line)) section = line.replace(/^#+\s*/, "");
  if (line.trim() === "```cddl") {
    const start = i + 1;
    const body = [];
    for (i += 1; i < lines.length && lines[i].trim() !== "```"; i += 1) body.push(lines[i]);
    const firstCode = body.find((l) => l.trim() !== "" && !l.trim().startsWith(";")) ?? "";
    blocks.push({ line: start, section, part, body, named: RULE_START.test(firstCode) });
  }
}

function render(part) {
  const header = [
    `; GENERATED from ${source} by scripts/extract-cddl.mjs. Do not edit.`,
    "; Regenerate with: node scripts/extract-cddl.mjs",
    part === "summary"
      ? "; Contents: Part XXVIII (Full CDDL Summary), which restates body rules."
      : "; Contents: every ```cddl block before Part XXVIII, in document order.",
    "",
  ];
  const out = [...header];
  for (const b of blocks.filter((x) => x.part === part)) {
    out.push(`; --- ${source}:${b.line} (${b.section}) ---`);
    if (b.named) {
      out.push(...b.body);
    } else {
      out.push("; Unnamed block: not a CDDL rule on its own; named in LFCP-WIRE-01.supplement.cddl.");
      out.push(...b.body.map((l) => (l === "" ? ";" : `; ${l}`)));
    }
    out.push("");
  }
  return out.join("\n");
}

const check = process.argv.includes("--check");
let stale = 0;
for (const [part, path] of Object.entries(outputs)) {
  const text = render(part);
  const full = join(root, path);
  if (check) {
    let current = null;
    try {
      current = readFileSync(full, "utf8");
    } catch {
      // Missing file counts as out of date.
    }
    if (current !== text) {
      stale += 1;
      console.log(`FAIL  ${path} is out of date with ${source}; run: node scripts/extract-cddl.mjs`);
    } else {
      console.log(`ok    ${path} matches ${source}`);
    }
  } else {
    writeFileSync(full, text);
    console.log(`wrote ${path}`);
  }
}

const count = (part, named) => blocks.filter((b) => b.part === part && b.named === named).length;
console.log(
  `cddl: ${blocks.length} blocks in ${source}: body ${count("body", true)} named + ${count("body", false)} unnamed, ` +
    `summary ${count("summary", true)} named + ${count("summary", false)} unnamed`,
);
process.exit(stale === 0 ? 0 : 1);
