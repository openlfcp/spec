// SHARED-OBJECTS-TEST-VECTORS-01 Automerge reference corpus generator.
//
// Compatibility target: @automerge/automerge 3.5.0, pinned exactly as a
// devDependency of this repository (pnpm install --frozen-lockfile).
//
//   node test-vectors/shared-objects-01/generate_automerge_reference_01.mjs [--out-dir DIR]
//
// Writes SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json next to this script (or
// into DIR). For every behavioral scenario S01-S14 of
// SHARED-OBJECTS-TEST-VECTORS-01.json it records the exact Automerge changes
// that build the scenario, in an order in which each change's dependencies
// precede it, the full-save image of the converged document, its logical
// state and its scalar conflict sets. `negatives` holds changes a receiver
// must not merge (SPEC-PATCH-04 / SO-SEC1).
//
// The corpus is supplementary: conformance does NOT require independently
// generated changes or save images to be byte-identical (SHARED-OBJECTS-
// PROFILE-01 §14). A second implementation applies these changes, loads these
// save images and compares the logical state and conflicts.
//
// The output is deterministic: every actor comes from the vector fixtures
// (SHARED-OBJECTS-PROFILE-01 §8), every change has time 0 and a fixed
// message, and no randomness is used. scripts/validate.sh regenerates it and
// compares the bytes.
//
// Document model (SHARED-OBJECTS-PROFILE-01 §15-§16, §23, §30): the root is
// {profile, objects, extensions}. Every string value is written as an
// Automerge scalar string (ImmutableString), never as collaborative Text:
// Task fields are "maps and scalar registers" (§30, §26, §32, §33, §38).

import * as A from "@automerge/automerge";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const outIndex = process.argv.indexOf("--out-dir");
const OUT_DIR = outIndex > 0 ? path.resolve(process.argv[outIndex + 1]) : HERE;
const OUT_NAME = "SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json";
const PROFILE = "org.openlfcp.shared-objects.v1";
const AUTOMERGE_VERSION = "3.5.0";

const vectors = JSON.parse(
  fs.readFileSync(path.join(HERE, "SHARED-OBJECTS-TEST-VECTORS-01.json"), "utf8"),
);
const fixtures = vectors.fixtures;
const scenarios = new Map(
  vectors.cases.filter((c) => c.type === "behavioral").map((c) => [c.id, c]),
);
const hex = (u8) => Buffer.from(u8).toString("hex");
const sha256 = (u8) => crypto.createHash("sha256").update(u8).digest("hex");

/** Resource A actor of a fixture Principal (§8). */
const actorOf = (name) => {
  const principal = fixtures.principals[name];
  if (!principal) throw new Error(`unknown fixture principal ${name}`);
  return principal.actor_a_hex;
};

/** A JSON value as Automerge input: strings become scalar strings. */
function scalarize(value) {
  if (typeof value === "string") return new A.ImmutableString(value);
  if (Array.isArray(value)) return value.map(scalarize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scalarize(v)]));
  }
  return value;
}

/** An Automerge value as plain JSON: scalar strings become strings. */
function plain(value) {
  if (A.isImmutableString(value)) return value.toString();
  if (Array.isArray(value)) return value.map(plain);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]));
  }
  return value;
}

/**
 * One scenario's history: documents per branch, and every change in an
 * order in which dependencies come first.
 */
class History {
  constructor() {
    this.changes = [];
  }

  /** Apply `fn` as one Automerge change by `doc`'s actor (§10). */
  change(doc, label, actor, fn) {
    const next = A.change(doc, { message: label, time: 0 }, fn);
    const added = A.getChanges(doc, next);
    if (added.length !== 1) throw new Error(`${label}: expected one change, got ${added.length}`);
    const decoded = A.decodeChange(added[0]);
    this.changes.push({
      label,
      actor,
      actor_hex: decoded.actor,
      seq: decoded.seq,
      hash: decoded.hash,
      deps: [...decoded.deps].sort(),
      change_hex: hex(added[0]),
      change_sha256: sha256(added[0]),
    });
    return next;
  }
}

/** §16: the initial document, in one change. */
function initialDocument(history, actorName) {
  const doc = A.init({ actor: actorOf(actorName) });
  return history.change(doc, "profile.init", actorName, (d) => {
    d.profile = new A.ImmutableString(PROFILE);
    d.objects = {};
    d.extensions = {};
  });
}

/** The objects a scenario's base_state puts into the document. */
function baseObjects(base) {
  if (base.type !== undefined) return { [base.id]: base };
  if (base.task !== undefined) return { [base.task.id]: base.task };
  if (base.objects !== undefined) return base.objects;
  return {};
}

/** Apply one branch intent or operation to `doc` (§59-§69). */
function applyBranch(history, doc, branch, label) {
  const actor = branch.actor;
  const objectId = fixtures.objects.task_1;
  const write = (fn) => history.change(doc, label, actor, fn);
  if (branch.intent === "task.create") {
    return write((d) => {
      d.objects[branch.args.id] = scalarize(branch.args);
    });
  }
  if (branch.operation === "create") {
    return write((d) => {
      d.objects[branch.object.id] = scalarize(branch.object);
    });
  }
  if (branch.writes !== undefined) {
    return write((d) => {
      const task = d.objects[objectId];
      for (const [field, value] of Object.entries(branch.writes)) {
        // §36: a cleared date deletes the property.
        if (value === null) {
          delete task[field];
          continue;
        }
        // An intent always writes (e.g. S10's restore of an active Task must
        // conflict with a concurrent delete). Automerge skips an assignment
        // of the value already there, so delete it first.
        if (field in task && plain(task[field]) === value) delete task[field];
        task[field] = scalarize(value);
      }
    });
  }
  switch (branch.intent) {
    case "task.add_tag": // §67
      return write((d) => {
        const tags = d.objects[objectId].tags;
        // fresh_write: re-add a present tag as a new write. Automerge skips
        // an assignment of the value already there, so delete it first.
        if (branch.fresh_write) delete tags[branch.tag];
        tags[branch.tag] = true;
      });
    case "task.remove_tag":
      return write((d) => {
        delete d.objects[objectId].tags[branch.tag];
      });
    case "task.add_assignee": // §68
      return write((d) => {
        const assignees = d.objects[objectId].assignees;
        if (branch.fresh_write) delete assignees[branch.principal];
        assignees[branch.principal] = true;
      });
    case "task.remove_assignee": // §68
      return write((d) => {
        delete d.objects[objectId].assignees[branch.principal];
      });
    default:
      throw new Error(`${label}: unsupported branch ${JSON.stringify(branch)}`);
  }
}

/** Merge branch documents into one converged document. */
function mergeAll(docs) {
  return docs.slice(1).reduce((merged, doc) => A.merge(merged, doc), A.clone(docs[0]));
}

/** Scalar fields of every object with more than one concurrent value. */
function conflictSets(doc) {
  const out = {};
  for (const [id, object] of Object.entries(doc.objects)) {
    const objectConflicts = A.getConflicts(doc.objects, id);
    if (objectConflicts && Object.keys(objectConflicts).length > 1) {
      out[id] = { "": Object.keys(objectConflicts).length };
      continue;
    }
    for (const field of Object.keys(object)) {
      const values = A.getConflicts(object, field);
      if (values && Object.keys(values).length > 1) {
        out[id] ??= {};
        out[id][field] = Object.values(values).map((v) => plain(v)).sort();
      }
    }
  }
  return out;
}

/** Run one scenario: build its history and its converged document. */
function run(id, history = new History()) {
  const scenario = scenarios.get(id);
  const { base_state: base, branches } = scenario.inputs;
  let doc;
  let snapshot = null;

  if (base.derived_from !== undefined) {
    // S04: continue from another scenario's merged state.
    const source = base.derived_from.split(/\s+/)[0];
    doc = run(source, history).doc;
  } else if (base.build !== undefined) {
    // S14: "Apply S01 then S06": S06's branches on S01's state.
    doc = run("S01", history).doc;
    const s06 = scenarios.get("S06").inputs.branches;
    doc = mergeAll(
      s06.map((branch, i) =>
        applyBranch(history, A.clone(doc, { actor: actorOf(branch.actor) }), branch, `S14.S06.${i + 1}`),
      ),
    );
  } else {
    doc = initialDocument(history, "andrey");
    const objects = baseObjects(base);
    if (Object.keys(objects).length > 0) {
      doc = history.change(doc, `${id}.base`, "andrey", (d) => {
        for (const [objectId, object] of Object.entries(objects)) {
          d.objects[objectId] = scalarize(object);
        }
      });
    }
  }

  const forks = [];
  branches.forEach((branch, i) => {
    const label = `${id}.${i + 1}`;
    if (branch.operation === "load-save-roundtrip-without-understanding-type") {
      // S12: load and save as another actor without changing anything.
      doc = A.load(A.save(doc), { actor: actorOf(branch.actor) });
      return;
    }
    if (branch.operation === "snapshot_save_load_roundtrip") {
      snapshot = A.save(doc);
      doc = A.load(snapshot, { actor: actorOf("andrey") });
      return;
    }
    const start = A.clone(doc, { actor: actorOf(branch.actor) });
    const changed = applyBranch(history, start, branch, label);
    if (branch.from === "base") forks.push(changed);
    else doc = changed; // from the merged state, or after the snapshot
  });
  if (forks.length > 0) doc = mergeAll(forks);
  return { doc, history, snapshot, scenario };
}

const corpus = {
  description:
    "Automerge reference corpus for SHARED-OBJECTS-TEST-VECTORS-01: for each behavioral scenario, the exact " +
    "Automerge changes (dependencies first), the full-save image of the converged document, its logical state " +
    "and its scalar conflict sets. Generated by generate_automerge_reference_01.mjs; supplementary, not " +
    "byte-normative (SHARED-OBJECTS-PROFILE-01 §14).",
  automerge_version: AUTOMERGE_VERSION,
  profile: PROFILE,
  resource_hex: fixtures.resource_a_hex,
  actors: Object.fromEntries(Object.keys(fixtures.principals).map((name) => [name, actorOf(name)])),
  conventions: {
    strings: "every string value is an Automerge scalar string (ImmutableString), never Text",
    numbers: "integers are Automerge int values",
    change_time: 0,
    change_message: "the change label",
    conflicts:
      "conflicts[object-id][field] lists the concurrent values of a scalar field, sorted; " +
      "conflicts[object-id][''] counts concurrent objects under one Object ID (an OBJECT_ID_COLLISION)",
  },
  scenarios: [],
};

for (const id of scenarios.keys()) {
  const { doc, history, snapshot, scenario } = run(id);
  const save = A.save(doc);
  // A save image must load to the same logical state.
  const reloaded = A.load(save);
  if (JSON.stringify(plain(A.toJS(reloaded))) !== JSON.stringify(plain(A.toJS(doc)))) {
    throw new Error(`${id}: the save image does not reload to the same state`);
  }
  const entry = {
    id,
    description: scenario.description,
    changes: history.changes,
    heads: [...A.getHeads(doc)].sort(),
    save_hex: hex(save),
    save_sha256: sha256(save),
    state: plain(A.toJS(doc)),
    conflicts: conflictSets(doc),
  };
  if (snapshot !== null) {
    entry.snapshot = {
      note: "full-save image taken before the post-snapshot change; load it, then apply the changes it does not contain",
      save_hex: hex(snapshot),
      save_sha256: sha256(snapshot),
      heads: [...A.getHeads(A.load(snapshot))].sort(),
    };
  }
  corpus.scenarios.push(entry);
}

// Negative cases (SPEC-PATCH-04). SO-SEC1 (SHARED-OBJECTS-PROFILE-01 §8,
// §11): a Data Unit signed by andrey whose framed plaintext carries a real
// change by pavel's actor, on top of S01's state. A receiver does not merge
// it: PROFILE_INVALID with the diagnostic CHANGE_ACTOR_MISMATCH.

/** Deterministic CBOR of [1, bstr] (§11 framing). */
function frame(bytes) {
  const n = bytes.length;
  const head =
    n < 24 ? [0x40 + n] : n < 256 ? [0x58, n] : n < 65536 ? [0x59, n >> 8, n & 0xff] : null;
  if (head === null) throw new Error("change too large for this test framing");
  return Uint8Array.from([0x82, 0x01, ...head, ...bytes]);
}

const s01 = run("S01").doc;
const foreign = new History();
const asPavel = A.clone(s01, { actor: actorOf("pavel") });
foreign.change(asPavel, "SO-SEC1.foreign", "pavel", (d) => {
  d.objects[fixtures.objects.task_1].title = new A.ImmutableString("Written into another actor's history");
});
const [foreignChange] = foreign.changes;
if (foreignChange.actor_hex === actorOf("andrey")) throw new Error("SO-SEC1: the change must not be andrey's");
corpus.negatives = [
  {
    id: "SO-SEC1-change-actor-mismatch",
    description:
      "A Data Unit signed by andrey whose plaintext carries a change by pavel's Automerge actor, on top of S01",
    rule: "SHARED-OBJECTS-PROFILE-01 §8, §11: the change's actor MUST be the §8 actor of the Data Unit's signer; " +
      "a receiver MUST NOT merge a change of any other actor.",
    base_scenario: "S01",
    signer: "andrey",
    signer_actor_hex: actorOf("andrey"),
    change: foreignChange,
    plaintext_hex: hex(frame(Buffer.from(foreignChange.change_hex, "hex"))),
    expected: {
      valid: false,
      disposition: "reject",
      error: { code: "PROFILE_INVALID", diagnostic: "CHANGE_ACTOR_MISMATCH" },
    },
  },
];

// SPEC-PATCH-05 (SHARED-OBJECTS-PROFILE-01 §11, §13, §74.1): plaintexts
// whose Automerge bytes fail the chunk checks are PROFILE_INVALID with the
// diagnostic INVALID_AUTOMERGE_BYTES. The signer is the change's own actor,
// so only the bytes are wrong.
const own = new History();
const asAndrey = A.clone(s01, { actor: actorOf("andrey") });
own.change(asAndrey, "SO-BYTES.own", "andrey", (d) => {
  d.objects[fixtures.objects.task_1].title = new A.ImmutableString("A change with a broken checksum");
});
const [ownChange] = own.changes;
const corrupted = Buffer.from(ownChange.change_hex, "hex");
corrupted[4] ^= 0x01; // the first checksum byte (magic, then 4 checksum bytes)
const BYTES_RULE =
  "SHARED-OBJECTS-PROFILE-01 §11, §13, §74.1: a receiver MUST verify the chunk type and checksum and rejects " +
  "invalid Automerge bytes with PROFILE_INVALID and the diagnostic INVALID_AUTOMERGE_BYTES.";
const bytesError = { code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" };
corpus.negatives.push(
  {
    id: "SO-BYTES-change-checksum",
    description: "andrey's own change on S01 with its first checksum byte flipped",
    note: "change is the change before corruption; plaintext_hex frames the corrupted bytes. Automerge 3.5.0 parses them without checking the checksum.",
    rule: BYTES_RULE,
    base_scenario: "S01",
    signer: "andrey",
    signer_actor_hex: actorOf("andrey"),
    change: ownChange,
    plaintext_hex: hex(frame(corrupted)),
    expected: { valid: false, disposition: "reject", error: bytesError },
  },
  {
    id: "SO-BYTES-document-chunk",
    description: "A Data Unit plaintext that frames S01's full save (a document chunk) instead of a change",
    rule: BYTES_RULE,
    base_scenario: "S01",
    signer: "andrey",
    signer_actor_hex: actorOf("andrey"),
    plaintext_hex: hex(frame(A.save(s01))),
    expected: { valid: false, disposition: "reject", error: bytesError },
  },
);

fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(path.join(OUT_DIR, OUT_NAME), JSON.stringify(corpus, null, 2) + "\n");
console.log(`wrote ${path.join(OUT_DIR, OUT_NAME)}`);
