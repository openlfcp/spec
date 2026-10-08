#!/usr/bin/env node
// Keeps each MVP-0.N-BASELINE.md in step with the repository (LFCP-010):
//
// - every path listed in a manifest table (first cell, in backticks) exists;
//   a path ending in "/" names a directory and covers everything below it;
// - every file under the canonical roots is listed, directly or through a
//   listed directory.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFESTS = readdirSync(root).filter((name) => /^MVP-0\.\d+-BASELINE\.md$/.test(name)).sort();
const ROOTS = ["wire", "profiles", "integration", "test-vectors", "schemas", "adr"];

const problems = [];
let entries = 0;
for (const MANIFEST of MANIFESTS) {
const text = readFileSync(join(root, MANIFEST), "utf8");
const listed = [...text.matchAll(/^\| `([^`]+)` \|/gm)].map((m) => m[1]);
entries += listed.length;
for (const path of listed) {
  const full = join(root, path);
  const isDir = path.endsWith("/");
  if (!existsSync(full) || statSync(full).isDirectory() !== isDir) {
    problems.push(`${MANIFEST} lists ${path}, which does not exist as a ${isDir ? "directory" : "file"}`);
  }
}

const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [relative(root, path)];
  });
const covered = (file) => listed.some((p) => (p.endsWith("/") ? file.startsWith(p) : file === p));
for (const top of ROOTS) {
  if (!existsSync(join(root, top))) continue;
  for (const file of walk(join(root, top))) {
    if (!covered(file)) problems.push(`${file} is not listed in ${MANIFEST}`);
  }
}
}

for (const p of problems) console.log(`FAIL  ${p}`);
console.log(`baseline: ${MANIFESTS.length} manifests, ${entries} entries, ${problems.length} problem(s)`);
process.exit(problems.length === 0 ? 0 : 1);
