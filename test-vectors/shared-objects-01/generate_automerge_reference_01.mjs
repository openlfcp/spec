// SHARED-OBJECTS-TEST-VECTORS-01 Automerge reference corpus generator.
//
// Compatibility target: @automerge/automerge 3.5.0, pinned exactly as a
// devDependency of this repository (pnpm install --frozen-lockfile).
//
//   node test-vectors/shared-objects-01/generate_automerge_reference_01.mjs [--out-dir DIR]
//
// Writes SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json next to this script (or
// into DIR). For every behavioral scenario S01-S16 of
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
import zlib from "node:zlib";

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

// SPEC-PATCH-06 (SHARED-OBJECTS-PROFILE-01 §30, §74.1, SO-STRINGS): save
// images whose strings are collaborative Text somewhere, with every problem a
// validator reports: INVALID_FIELD_TYPE at the Text value's own pointer, by
// precedence over the field's own rule; the root profile as Text is
// INVALID_ROOT. Plain JS strings are written as Text here on purpose; scalar
// strings are ImmutableString. Mirrors sdk-rs 8cb872b and sdk-ts eb35817.
const K = fixtures.objects.task_1;
const textEdit = (label, f) => {
  const d = A.change(A.clone(s01, { actor: actorOf("andrey") }), { message: label, time: 0 }, f);
  return A.save(d);
};
const invalid = (pointer, diagnostic) => ({ pointer, code: "PROFILE_INVALID", diagnostic });
corpus.validations = [
  {
    id: "SO-STRINGS-text-anywhere",
    description:
      "The S01 Task with Text inside extensions (a map value and a list item), in an unknown field, in status and in due",
    rule: "SHARED-OBJECTS-PROFILE-01 §30, §74.1: every string in any object is a scalar string; Text is INVALID_FIELD_TYPE at its own pointer, before the field's own rule.",
    base_scenario: "S01",
    save_hex: hex(
      textEdit("SO-STRINGS.text-anywhere", (d) => {
        const o = d.objects[K];
        o.extensions = {
          "org.example.app": {
            note: "n",
            ok: new A.ImmutableString("scalar"),
            list: [new A.ImmutableString("s"), "l"],
          },
        };
        o.x_unknown = "u";
        o.status = "todo";
        o.due = "2026-10-05";
      }),
    ),
    expected_problems: [
      invalid(`/objects/${K}/due`, "INVALID_FIELD_TYPE"),
      invalid(`/objects/${K}/extensions/org.example.app/list/1`, "INVALID_FIELD_TYPE"),
      invalid(`/objects/${K}/extensions/org.example.app/note`, "INVALID_FIELD_TYPE"),
      invalid(`/objects/${K}/status`, "INVALID_FIELD_TYPE"),
      invalid(`/objects/${K}/x_unknown`, "INVALID_FIELD_TYPE"),
    ],
  },
  {
    id: "SO-STRINGS-text-tag-member",
    description: "The S01 Task with a tags member whose value is Text",
    rule: "SHARED-OBJECTS-PROFILE-01 §30, §74.1: INVALID_FIELD_TYPE comes before INVALID_COLLECTION_REPRESENTATION at the same pointer.",
    base_scenario: "S01",
    save_hex: hex(
      textEdit("SO-STRINGS.text-tag-member", (d) => {
        d.objects[K].tags.backend = "yes";
      }),
    ),
    expected_problems: [invalid(`/objects/${K}/tags/backend`, "INVALID_FIELD_TYPE")],
  },
  {
    id: "SO-STRINGS-text-root-profile",
    description: "The S01 document whose root profile value is Text",
    rule: "SHARED-OBJECTS-PROFILE-01 §15, §30, §74.1: the root profile must be the scalar profile identifier; otherwise INVALID_ROOT.",
    base_scenario: "S01",
    save_hex: hex(
      textEdit("SO-STRINGS.text-root-profile", (d) => {
        d.profile = PROFILE;
      }),
    ),
    expected_problems: [invalid("/profile", "INVALID_ROOT")],
  },
];

// SPEC-PATCH-07 (SHARED-OBJECTS-PROFILE-01 §30): an object's maps and lists
// nest at most 64 levels; the field's own map is depth 1. The first map
// at depth 65 is INVALID_FIELD_TYPE at its pointer, and nothing below it
// is examined. Mirrors sdk-rs bb43a78.
/** `levels` nested maps (the outermost first), the innermost holding one int. */
const nest = (levels) => {
  let v = { leaf: 1 };
  for (let i = 1; i < levels; i++) v = { d: v };
  return v;
};
// extensions is depth 1 and "org.example.app" depth 2, so its value's
// innermost map is at depth `levels + 1`.
const deep = (levels) =>
  textEdit(`SO-DEPTH.${levels + 1}`, (d) => {
    d.objects[K].extensions = { "org.example.app": nest(levels) };
  });
corpus.validations.push(
  {
    id: "SO-DEPTH-64",
    description: "The S01 Task whose extensions nest maps exactly 64 levels deep",
    rule: "SHARED-OBJECTS-PROFILE-01 §30: maps and lists nest at most 64 levels in an object (the field's own map is depth 1).",
    base_scenario: "S01",
    save_hex: hex(deep(63)),
    expected_problems: [],
  },
  {
    id: "SO-DEPTH-65",
    description: "The S01 Task whose extensions nest maps 65 levels deep",
    rule: "SHARED-OBJECTS-PROFILE-01 §30, §74.1: the map at depth 65 is INVALID_FIELD_TYPE at its own pointer; nothing below it is examined.",
    base_scenario: "S01",
    save_hex: hex(deep(64)),
    expected_problems: [
      invalid(`/objects/${K}/extensions/org.example.app${"/d".repeat(63)}`, "INVALID_FIELD_TYPE"),
    ],
  },
);

// SPEC-PATCH-07 (SHARED-OBJECTS-PROFILE-01 §11.1, §13.1): expansion limits.
// Changes have exact limits (every receiver accepts or rejects the same
// change); Snapshots have local limits with a floor every receiver accepts.
// A receiver checks a chunk before its Automerge engine sees it.
const leb = (n) => {
  const out = [];
  do {
    let b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return out;
};
const sleb = (n) => {
  const out = [];
  for (;;) {
    const b = n & 0x7f;
    n = Math.floor(n / 128);
    if ((n === 0 && (b & 0x40) === 0) || (n === -1 && (b & 0x40) !== 0)) {
      out.push(b);
      return out;
    }
    out.push(b | 0x80);
  }
};
/** A chunk: magic, checksum (first 4 bytes of the chunk hash), type, length, data. */
const chunk = (type, data) => {
  const hash = crypto
    .createHash("sha256")
    .update(Uint8Array.from([type, ...leb(data.length)]))
    .update(data)
    .digest();
  return Uint8Array.from([0x85, 0x6f, 0x4a, 0x83, ...hash.subarray(0, 4), type, ...leb(data.length), ...data]);
};
const EXP_ACTOR = actorOf("andrey");
const expBase = A.decodeChange(
  A.getLastLocalChange(
    A.change(A.init({ actor: EXP_ACTOR }), { message: "EXP.base", time: 0 }, (d) => {
      d.a = 0;
    }),
  ),
);
/** A change of `n` ops `root[key] = null` with `preds` each: Automerge's own encoder, every column run-length collapses. */
const nullSets = (n, key = "k", preds = []) =>
  A.encodeChange({
    actor: EXP_ACTOR,
    seq: 2,
    startOp: expBase.startOp + expBase.ops.length,
    time: 0,
    message: null,
    deps: [expBase.hash],
    ops: Array.from({ length: n }, () => ({ action: "set", obj: "_root", key, value: null, pred: preds })),
  });
const predsOf = (n) => Array.from({ length: n }, (_, i) => `${i + 1}@${EXP_ACTOR}`);
/** The same change as a compressed chunk (type 2): one stored DEFLATE block. */
const compressed = (change) => {
  const headerLen = 9 + leb(change.length - 9).length;
  const data = change.subarray(headerLen);
  const len = data.length;
  const stored = Uint8Array.from([0x01, len & 0xff, len >> 8, ~len & 0xff, (~len >> 8) & 0xff, ...data]);
  return Uint8Array.from([...change.subarray(0, 8), 2, ...leb(stored.length), ...stored]);
};
/**
 * `zeros` zero bytes as one dynamic-Huffman DEFLATE block (RFC 1951), built
 * by hand so the bytes never depend on a zlib version: literal 0 (code 10),
 * then length 258 at distance 1 (codes 0 and 0) repeated, literal zeros for
 * the rest, end of block (11).
 */
function deflateZeros(zeros) {
  const out = [];
  let acc = 0;
  let bits = 0;
  const put = (value, n) => {
    for (let i = 0; i < n; i++) {
      acc |= ((value >> i) & 1) << bits;
      if (++bits === 8) {
        out.push(acc);
        acc = 0;
        bits = 0;
      }
    }
  };
  const code = (c, n) => {
    for (let i = n - 1; i >= 0; i--) put((c >> i) & 1, 1);
  };
  put(1, 1); // BFINAL
  put(2, 2); // dynamic Huffman
  put(29, 5); // HLIT: 286 literal/length codes
  put(0, 5); // HDIST: 1 distance code
  put(14, 4); // HCLEN: 18 code length codes
  const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1];
  const clLen = { 18: 1, 1: 2, 2: 2 };
  for (const sym of order) put(clLen[sym] ?? 0, 3);
  // Code length codes: 18 -> 0, 1 -> 10, 2 -> 11.
  const cl = { 1: [0b10, 2], 2: [0b11, 2], 18: [0b0, 1] };
  const zerosRun = (n) => {
    code(...cl[18]);
    put(n - 11, 7);
  };
  code(...cl[2]); // literal 0: length 2
  zerosRun(138);
  zerosRun(117); // literals 1..255 unused
  code(...cl[2]); // 256 (end of block): length 2
  zerosRun(28); // 257..284 unused
  code(...cl[1]); // 285 (length 258): length 1
  code(...cl[1]); // distance 0 (distance 1): length 1
  // Literal/length codes: 285 -> 0, 0 -> 10, 256 -> 11; distance 0 -> 0.
  code(0b10, 2);
  let left = zeros - 1;
  for (; left >= 258; left -= 258) {
    code(0b0, 1);
    code(0b0, 1);
  }
  for (; left > 0; left--) code(0b10, 2);
  code(0b11, 2);
  if (bits > 0) out.push(acc);
  const bytes = Uint8Array.from(out);
  const check = zlib.inflateRawSync(bytes);
  if (check.length !== zeros || check.some((b) => b !== 0)) throw new Error("deflateZeros is wrong");
  return bytes;
}
/** A document chunk with no actors, heads or change columns and the given op columns. */
const documentChunk = (columns) =>
  chunk(0, Uint8Array.from([
    0, // actors
    0, // heads
    0, // change columns
    ...leb(columns.length),
    ...columns.flatMap(([spec, data]) => [...leb(spec), ...leb(data.length)]),
    ...columns.flatMap(([, data]) => [...data]),
  ]));
const ACTION_INT = (4 << 4) | 2;
const RAW_DEFLATED = (5 << 4) | 0x08 | 7;
const rleRun = (n) => Uint8Array.from([...sleb(n), ...leb(1)]);
const LIMITS = { change: { max_rows: 16384, max_group_sum: 262144, max_string_bytes: 4194304, max_deps: 1024, max_actors: 1024 }, snapshot_floor: { max_rows: 262144, max_group_sum: 262144, max_string_bytes: 33554432, max_inflated_bytes: 33554432, max_actors: 1024, max_heads: 1024 } };
const expansion = (id, kind, description, rule, bytes, within) => ({
  id,
  kind,
  description,
  rule,
  bytes_hex: hex(bytes),
  sha256: sha256(bytes),
  expected: within
    ? { within_limits: true }
    : { within_limits: false, error: { code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" } },
});
const CHANGE_RULE = "SHARED-OBJECTS-PROFILE-01 §11.1: exact change limits, checked before the engine";
const FLOOR_RULE = "SHARED-OBJECTS-PROFILE-01 §13.1: a receiver accepts at least the floor; one with floor limits rejects above it";
const save01 = A.save(s01);
corpus.expansion = {
  limits: LIMITS,
  note:
    "Each case is checked with the expansion check alone (§11.1 for a change, §13.1 with floor limits for a Snapshot). " +
    "A case within the limits may still fail other checks (it is not a valid Shared Objects change or document).",
  cases: [
    expansion("EXP-change-ops-at-limit", "change", "16,384 operations: the limit", CHANGE_RULE, nullSets(16384), true),
    expansion("EXP-change-ops-over-limit", "change", "16,385 operations", CHANGE_RULE, nullSets(16385), false),
    expansion("EXP-change-rle-bomb", "change", "1,000,000 operations in about 112 bytes (Automerge's own encoder)", CHANGE_RULE, nullSets(1_000_000), false),
    expansion("EXP-change-preds-per-op-at-limit", "change", "one operation with 2 predecessors of 2 actors (its own and one other)", CHANGE_RULE, nullSets(1, "k", [`1@${EXP_ACTOR}`, `1@${"cc".repeat(32)}`]), true),
    expansion("EXP-change-preds-per-op-over-limit", "change", "one operation with 2 predecessors and no other actor", CHANGE_RULE, nullSets(1, "k", predsOf(2)), false),
    expansion("EXP-change-preds-bomb", "change", "one operation with 16,385 predecessors of one actor", CHANGE_RULE, nullSets(1, "k", predsOf(16385)), false),
    expansion("EXP-change-strings-at-limit", "change", "16,384 rows of a 256-byte key: 4 MiB of strings", CHANGE_RULE, nullSets(16384, "x".repeat(256)), true),
    expansion("EXP-change-strings-over-limit", "change", "16,384 rows of a 257-byte key", CHANGE_RULE, nullSets(16384, "x".repeat(257)), false),
    expansion("EXP-change-compressed", "change", "a valid change as a compressed chunk (type 2)", "SHARED-OBJECTS-PROFILE-01 §11: a change is an uncompressed chunk (type 1)", compressed(nullSets(3)), false),
    expansion("EXP-snapshot-rows-at-floor", "snapshot", "an op column of 262,144 values", FLOOR_RULE, documentChunk([[ACTION_INT, rleRun(262144)]]), true),
    expansion("EXP-snapshot-rows-over-floor", "snapshot", "an op column of 262,145 values", FLOOR_RULE, documentChunk([[ACTION_INT, rleRun(262145)]]), false),
    expansion("EXP-snapshot-inflated-at-floor", "snapshot", "a deflated column inflating to 32 MiB", FLOOR_RULE, documentChunk([[RAW_DEFLATED, deflateZeros(33554432)]]), true),
    expansion("EXP-snapshot-inflated-over-floor", "snapshot", "a deflated column inflating to 32 MiB + 1 byte", FLOOR_RULE, documentChunk([[RAW_DEFLATED, deflateZeros(33554433)]]), false),
    expansion("EXP-snapshot-trailing-chunk", "snapshot", "the S01 save followed by a change chunk", "SHARED-OBJECTS-PROFILE-01 §13, §13.1: exactly one document chunk, nothing after it", Uint8Array.from([...save01, ...nullSets(1)]), false),
  ],
};
/** Rebuilds a change chunk with its operation columns replaced by `mutate(columns)`. */
function rebuildChange(change, mutate) {
  let pos = 9;
  const u = () => {
    let v = 0;
    let scale = 1;
    for (;;) {
      const b = change[pos++];
      v += (b & 0x7f) * scale;
      if ((b & 0x80) === 0) return v;
      scale *= 128;
    }
  };
  const s = () => {
    let v = 0;
    let scale = 1;
    for (;;) {
      const b = change[pos++];
      v += (b & 0x7f) * scale;
      scale *= 128;
      if ((b & 0x80) === 0) return b & 0x40 ? v - scale : v;
    }
  };
  u(); // chunk length
  const start = pos;
  const skip = (n) => {
    pos += n;
  };
  skip(u() * 32); // deps
  skip(u()); // actor
  u(); // seq
  u(); // start op
  s(); // time
  skip(u()); // message
  const others = u();
  for (let i = 0; i < others; i++) skip(u());
  const headerEnd = pos;
  const metas = Array.from({ length: u() }, () => [u(), u()]);
  const columns = metas.map(([spec, length]) => {
    const data = change.subarray(pos, pos + length);
    pos += length;
    return [spec, data];
  });
  const extra = change.subarray(pos);
  const next = mutate(columns);
  return chunk(1, Uint8Array.from([
    ...change.subarray(start, headerEnd),
    ...leb(next.length),
    ...next.flatMap(([spec, data]) => [...leb(spec), ...leb(data.length)]),
    ...next.flatMap(([, data]) => [...data]),
    ...extra,
  ]));
}
// A change with an object actor column: a set inside a map the base change created.
const nested = (() => {
  const doc = A.change(A.init({ actor: EXP_ACTOR }), { message: "EXP.map", time: 0 }, (d) => {
    d.m = {};
  });
  const next = A.change(doc, { message: "EXP.nested", time: 0 }, (d) => {
    d.m.x = 1;
  });
  return A.getLastLocalChange(next);
})();
const OBJ_ACTOR = (0 << 4) | 1;
corpus.expansion.cases.push(
  expansion(
    "EXP-change-duplicate-column",
    "change",
    "a valid change with its first column listed twice",
    "SHARED-OBJECTS-PROFILE-01 §11.1 (7): no two columns share a specification",
    rebuildChange(nullSets(3), (cols) => [cols[0], ...cols]),
    false,
  ),
  expansion(
    "EXP-change-actor-index",
    "change",
    "a change whose object actor column names actor index 1 with no other actors",
    "SHARED-OBJECTS-PROFILE-01 §11.1 (8): an actor index is less than one plus the number of other actors",
    rebuildChange(nested, (cols) =>
      cols.map(([spec, data]) => (spec === OBJ_ACTOR ? [spec, Uint8Array.from([...sleb(1), ...leb(1)])] : [spec, data])),
    ),
    false,
  ),
);
if (checkStructure(nested) !== "ok") throw new Error("the nested base change must be structurally valid");
/** The base of the actor-index case has an object actor column at index 0. */
function checkStructure(change) {
  let ok = false;
  rebuildChange(change, (cols) => {
    ok = cols.some(([spec]) => spec === OBJ_ACTOR);
    return cols;
  });
  return ok ? "ok" : "no object actor column";
}

// SHARED-OBJECTS-PROFILE-01 §11.1: a change naming an actor the document
// does not know. Automerge panics applying it (JS: PanicError; automerge-rs:
// an unwrap); a receiver rejects it before the engine.
{
  const stranger = "cc".repeat(32);
  const own = A.decodeChange(
    A.getLastLocalChange(
      A.change(A.clone(s01, { actor: actorOf("andrey") }), { message: "SO-UNKNOWN-ACTOR", time: 0 }, (d) => {
        d.objects[K].priority = "high";
      }),
    ),
  );
  const forged = A.encodeChange({
    ...own,
    ops: own.ops.map((o) => ({ ...o, pred: [...o.pred, `1@${stranger}`] })),
  });
  corpus.negatives.push({
    id: "SO-UNKNOWN-ACTOR",
    description: "andrey's next change on S01 whose predecessor list names an operation of an actor S01 does not know",
    rule: "SHARED-OBJECTS-PROFILE-01 §11.1: every other actor of a change is already an actor of the document; otherwise INVALID_AUTOMERGE_BYTES before the engine.",
    base_scenario: "S01",
    signer: "andrey",
    signer_actor_hex: actorOf("andrey"),
    plaintext_hex: hex(frame(forged)),
    expected: { valid: false, disposition: "reject", error: { code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" } },
  });
}

// SPEC-PATCH-08 (SHARED-OBJECTS-PROFILE-01 §11.2): the document depth bound.
// The root is depth 0; an object created in an object of depth d has depth
// d + 1; no object may be deeper than 256. A receiver rejects, before its
// engine, a change that would create one, and a Snapshot holding one.
{
  const base = A.change(A.init({ actor: EXP_ACTOR }), { message: "DEPTH.base", time: 0 }, (d) => {
    d.a = 0;
  });
  const baseChange = A.getLastLocalChange(base);
  const baseDecoded = A.decodeChange(baseChange);
  /** Changes, one per entry of `levels`, each nesting that many maps under the previous change's deepest one. */
  const chain = (levels, last = "makeMap") => {
    const out = [];
    let deps = [baseDecoded.hash];
    let startOp = baseDecoded.startOp + baseDecoded.ops.length;
    let parent = "_root";
    levels.forEach((n, c) => {
      const ops = Array.from({ length: n }, (_, i) => {
        const op = {
          action: c === levels.length - 1 && i === n - 1 ? last : "makeMap",
          obj: parent,
          key: "d",
          pred: [],
        };
        parent = `${startOp + i}@${EXP_ACTOR}`;
        return op;
      });
      const change = A.encodeChange({ actor: EXP_ACTOR, seq: c + 2, startOp, time: 0, message: null, deps, ops });
      out.push(change);
      deps = [A.decodeChange(change).hash];
      startOp += n;
    });
    return out;
  };
  const changeCase = (id, description, changes, expected) => ({
    id,
    description,
    rule: "SHARED-OBJECTS-PROFILE-01 §11.2: no object deeper than 256; the change that would create one is rejected before the engine",
    changes: [baseChange, ...changes].map((c, i) => ({ change_hex: hex(c), expected: i === 0 ? "accept" : expected[i - 1] })),
  });
  const wide = A.encodeChange({
    actor: EXP_ACTOR,
    seq: 2,
    startOp: baseDecoded.startOp + baseDecoded.ops.length,
    time: 0,
    message: null,
    deps: [baseDecoded.hash],
    ops: Array.from({ length: 300 }, (_, i) => ({ action: "makeMap", obj: "_root", key: `k${i}`, pred: [] })),
  });
  const saveOf = (changes) => A.save(A.applyChanges(A.init({ actor: actorOf("pavel") }), [baseChange, ...changes])[0]);
  corpus.depth = {
    limit: 256,
    note:
      "Each case is a list of changes applied in order to an empty replica: accept (merged), reject (PROFILE_INVALID / " +
      "INVALID_AUTOMERGE_BYTES before the engine) or held (a dependency was rejected, so it never applies). " +
      "Snapshot cases are save images a receiver accepts or rejects before loading them.",
    cases: [
      changeCase("DEPTH-256", "one change nesting maps exactly 256 levels deep", chain([256]), ["accept"]),
      changeCase("DEPTH-257", "one change nesting maps 257 levels deep", chain([257]), ["reject"]),
      changeCase("DEPTH-text-257", "256 nested maps and a text object inside the deepest one (depth 257)", chain([257], "makeText"), ["reject"]),
      changeCase(
        "DEPTH-cumulative",
        "ten changes of 30 levels each: the ninth would reach depth 270, the tenth builds on it",
        chain(Array(10).fill(30)),
        [...Array(8).fill("accept"), "reject", "held"],
      ),
      changeCase("DEPTH-wide", "one change creating 300 maps side by side under the root (depth 1 each)", [wide], ["accept"]),
    ],
    snapshots: [
      {
        id: "DEPTH-snapshot-256",
        description: "a save whose deepest object is at depth 256",
        rule: "SHARED-OBJECTS-PROFILE-01 §11.2, §13.1",
        save_hex: hex(saveOf(chain([256]))),
        expected: "accept",
      },
      {
        id: "DEPTH-snapshot-257",
        description: "a save whose deepest object is at depth 257",
        rule: "SHARED-OBJECTS-PROFILE-01 §11.2, §13.1: rejected before the engine loads it",
        save_hex: hex(saveOf(chain([257]))),
        expected: "reject",
      },
    ],
  };
}

// POST-001 (SHARED-OBJECTS-PROFILE-01 §14.1): a replica never merges two
// changes with one actor and sequence number. andrey equivocates; X is one
// unit of the pair. pavel built c on X; after the rebuild that excludes X
// (and c with it), pavel re-issues the work as c2, which reuses c's sequence
// number (§9). A replica R that still holds X and c receives c2: it holds
// it. When R learns of the equivocation and rebuilds without X and c, the
// held c2 applies.
{
  const IS = (v) => new A.ImmutableString(v);
  const last = (doc) => A.getLastLocalChange(doc);
  const xDoc = A.change(A.clone(s01, { actor: actorOf("andrey") }), { message: "COLLISION.X", time: 0 }, (d) => {
    d.objects[K].title = IS("Title from one unit of an equivocating pair");
  });
  const cDoc = A.change(A.clone(xDoc, { actor: actorOf("pavel") }), { message: "COLLISION.c", time: 0 }, (d) => {
    d.objects[K].status = IS("in_progress");
  });
  const c2Doc = A.change(A.clone(s01, { actor: actorOf("pavel") }), { message: "COLLISION.c2", time: 0 }, (d) => {
    d.objects[K].status = IS("in_progress");
  });
  const [x, c, c2] = [last(xDoc), last(cDoc), last(c2Doc)];
  const [dx, dc, dc2] = [x, c, c2].map((b) => A.decodeChange(b));
  if (dc.actor !== dc2.actor || dc.seq !== dc2.seq || dc.hash === dc2.hash || !dc.deps.includes(dx.hash)) {
    throw new Error("COLLISION: c and c2 must share an actor and sequence number and differ, and c must depend on X");
  }
  const rebuilt = A.applyChanges(A.clone(s01), [c2])[0];
  corpus.collision = {
    rule:
      "SHARED-OBJECTS-PROFILE-01 §14.1: a change whose actor and sequence number match a different change in the " +
      "document is held, not merged and not profile-invalid; it is retried after every rebuild that removes changes",
    note:
      "Each case starts from the converged document of its base scenario and runs its steps in order: a change step " +
      "gives the change to the replica (accept: merged; held: held; duplicate: already in the document, no-op); an " +
      "exclude step is the rebuild of §14.1 without the listed changes and everything that depends on them, after " +
      "which the held changes are retried.",
    cases: [
      {
        id: "COLLISION-reissued-after-equivocation",
        description:
          "pavel's re-issued change c2 reuses the sequence number of c, which depends on X, one unit of andrey's " +
          "equivocating pair; the replica holds c2 until it rebuilds without X",
        base_scenario: "S01",
        steps: [
          { change_hex: hex(x), hash: dx.hash, actor: "andrey", seq: dx.seq, expected: "accept" },
          { change_hex: hex(c), hash: dc.hash, actor: "pavel", seq: dc.seq, expected: "accept" },
          { change_hex: hex(c2), hash: dc2.hash, actor: "pavel", seq: dc2.seq, expected: "held" },
          { change_hex: hex(c), hash: dc.hash, actor: "pavel", seq: dc.seq, expected: "duplicate" },
          { exclude: [dx.hash], expected: { removed: [dx.hash, dc.hash].sort(), applied: [dc2.hash] } },
        ],
        held_state: plain(A.toJS(cDoc)),
        final_heads: [...A.getHeads(rebuilt)].sort(),
        final_state: plain(A.toJS(rebuilt)),
      },
    ],
  };
}

// SPEC-PATCH-10 (SHARED-OBJECTS-PROFILE-01 §11.3, §11.4, ADR 0010): a
// change is in its one canonical encoding, and its operations refer only
// to its causal history. `canonical` cases are checked with §11.1 and
// §11.3 alone; `references` cases are given, after their history, to a
// replica's admission. The bad changes are written by hand from Automerge's
// own changes; findings F2 to F4 of an external review are among them.
{
  const ANDREY = actorOf("andrey");
  const PAVEL = actorOf("pavel");
  const commit = (doc, label, fn) => A.change(doc, { message: label, time: 0 }, fn);
  const last = (doc) => A.getLastLocalChange(doc);

  /** A change chunk's parts, every number read as written. */
  const parts = (change) => {
    let pos = 9;
    const u = () => {
      let v = 0;
      let scale = 1;
      for (;;) {
        const b = change[pos++];
        v += (b & 0x7f) * scale;
        if ((b & 0x80) === 0) return v;
        scale *= 128;
      }
    };
    const s = () => {
      let v = 0;
      let scale = 1;
      for (;;) {
        const b = change[pos++];
        v += (b & 0x7f) * scale;
        scale *= 128;
        if ((b & 0x80) === 0) return b & 0x40 ? v - scale : v;
      }
    };
    const take = (n) => change.subarray(pos, (pos += n));
    u(); // chunk length
    const deps = Array.from({ length: u() }, () => take(32));
    const actor = take(u());
    const seq = u();
    const startOp = u();
    const time = s();
    const message = take(u());
    const others = Array.from({ length: u() }, () => take(u()));
    const metas = Array.from({ length: u() }, () => [u(), u()]);
    const columns = metas.map(([spec, length]) => [spec, take(length)]);
    return { deps, actor, seq, startOp, time, message, others, columns, extra: change.subarray(pos) };
  };
  /** The chunk of `p`; `raw` overrides the encoding of a header number by its bytes. */
  const assemble = (p, raw = {}) =>
    chunk(1, Uint8Array.from([
      ...leb(p.deps.length),
      ...p.deps.flatMap((d) => [...d]),
      ...leb(p.actor.length),
      ...p.actor,
      ...(raw.seq ?? leb(p.seq)),
      ...leb(p.startOp),
      ...sleb(p.time),
      ...leb(p.message.length),
      ...p.message,
      ...leb(p.others.length),
      ...p.others.flatMap((o) => [...leb(o.length), ...o]),
      ...leb(p.columns.length),
      ...p.columns.flatMap(([spec, data]) => [...leb(spec), ...leb(data.length)]),
      ...p.columns.flatMap(([, data]) => [...data]),
      ...p.extra,
    ]));
  const edit = (change, f, raw) => {
    const p = parts(change);
    f(p);
    return assemble(p, raw);
  };
  const column = (p, spec) => p.columns.find(([s]) => s === spec);
  const setColumn = (p, spec, data) => {
    p.columns = p.columns.map(([s, d]) => [s, s === spec ? Uint8Array.from(data) : d]);
  };
  const bytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));
  /** The canonical run-length encoding of `values` (§11.3 rule 5); null is a null. */
  const rleCol = (values, enc) => {
    const out = [];
    let literal = [];
    const flush = () => {
      if (literal.length > 0) out.push(...sleb(-literal.length), ...literal.flatMap(enc));
      literal = [];
    };
    for (let i = 0; i < values.length; ) {
      let j = i + 1;
      while (j < values.length && values[j] === values[i]) j++;
      if (values[i] === null) {
        flush();
        out.push(...sleb(0), ...leb(j - i));
      } else if (j - i >= 2) {
        flush();
        out.push(...sleb(j - i), ...enc(values[i]));
      } else literal.push(values[i]);
      i = j;
    }
    flush();
    return out;
  };
  const deltas = (values) => {
    let prev = 0;
    return values.map((v) => {
      if (v === null) return null;
      const d = v - prev;
      prev = v;
      return d;
    });
  };

  // A base change with a map object, a list with an element, an int value
  // and a string value: Automerge's own, canonical.
  const base0 = commit(A.init({ actor: ANDREY }), "CAN.base", (d) => {
    d.m = {};
    d.l = [1];
  });
  // Taken before the next change: Automerge outdates a document it changes.
  const goodHistory = A.getAllChanges(base0);
  const base = commit(base0, "CAN.change", (d) => {
    d.m.x = 300;
    d.m.y = new A.ImmutableString("y");
    d.l.insertAt(1, 2);
  });
  const good = last(base);
  if (hex(edit(good, () => {})) !== hex(good)) throw new Error("parts/assemble do not round-trip");
  // A change with two dependencies, and one overwriting a conflict: two
  // predecessors of two actors.
  const forkA = commit(A.init({ actor: ANDREY }), "CAN.k.andrey", (d) => {
    d.k = 1;
  });
  const forkP = commit(A.init({ actor: PAVEL }), "CAN.k.pavel", (d) => {
    d.k = 2;
  });
  const merged = A.merge(A.clone(forkA, { actor: ANDREY }), forkP);
  const twoHistory = A.getAllChanges(merged);
  const overwrite = commit(merged, "CAN.k.overwrite", (d) => {
    d.k = 3;
  });
  const twoDeps = last(overwrite);
  if (A.decodeChange(twoDeps).deps.length !== 2) throw new Error("expected two deps");
  if (A.decodeChange(twoDeps).ops[0].pred.length !== 2) throw new Error("expected two preds");

  const INSERT = (3 << 4) | 4;
  const ACTION = (4 << 4) | 2;
  const VALUE_META = (5 << 4) | 6;
  const VALUE = (5 << 4) | 7;
  const PRED_ACTOR = (7 << 4) | 1;
  const PRED_CTR = (7 << 4) | 3;
  const OBJ_CTR = (0 << 4) | 2;
  const EXPAND = (9 << 4) | 4;
  const n = A.decodeChange(good).ops.length;
  const goodParts = parts(good);
  const metaOf = (p) => column(p, VALUE_META)[1];
  if (n !== 3) throw new Error("CAN.change: expected 3 operations");

  const CANON_RULE = (item) => `SHARED-OBJECTS-PROFILE-01 §11.3 (${item}): the canonical change encoding`;
  const canonicalCase = (id, item, description, change, history, canonical) => ({
    id,
    rule: CANON_RULE(item),
    description,
    history_hex: history.map(hex),
    change_hex: hex(change),
    expected: canonical
      ? { canonical: true }
      : { canonical: false, error: { code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" } },
  });
  const refused = [
    canonicalCase("CAN-control", "all", "Automerge's own change: map, list, int and string values", good, goodHistory, true),
    canonicalCase("CAN-control-two-actors", "all", "Automerge's own merge overwrite: two dependencies, two predecessors of two actors", twoDeps, twoHistory, true),
    canonicalCase("CAN-1-leb-header", "1", "the sequence number 2 written in two bytes (0x82 0x00)", edit(good, () => {}, { seq: [0x82, 0x00] }), goodHistory, false),
    canonicalCase("CAN-2-deps-order", "2", "the two dependencies in descending order", edit(twoDeps, (p) => p.deps.reverse()), twoHistory, false),
    canonicalCase(
      "CAN-2-unused-actor",
      "2",
      "an other actor (pavel) that no operation names",
      edit(good, (p) => {
        p.others = [bytes(PAVEL)];
      }),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-3-column-order",
      "3",
      "the action and insert columns swapped",
      edit(good, (p) => {
        const i = p.columns.findIndex(([s]) => s === INSERT);
        const j = p.columns.findIndex(([s]) => s === ACTION);
        [p.columns[i], p.columns[j]] = [p.columns[j], p.columns[i]];
      }),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-3-absent-column-present",
      "3",
      "an expand column holding only false (it is present only when some flag is true)",
      edit(good, (p) => {
        p.columns.push([EXPAND, Uint8Array.from(leb(n))]);
      }),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-3-unknown-column",
      "3",
      "an extra column with specification 0xb2 (id 11, integer)",
      edit(good, (p) => {
        p.columns.push([0xb2, Uint8Array.from([...sleb(n), ...leb(0)])]);
      }),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-4-rows-F3a",
      "4",
      "the insert column with 13 rows for 3 operations (finding F3a)",
      edit(good, (p) => setColumn(p, INSERT, leb(13))),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-5-split-run",
      "5",
      "the action column's three equal values as a run of 1 and a run of 2 (one run of 3)",
      edit(good, (p) => {
        if (hex(column(p, ACTION)[1]) !== hex(rleCol([1, 1, 1], leb))) throw new Error("expected three puts");
        setColumn(p, ACTION, [...sleb(1), ...leb(1), ...sleb(2), ...leb(1)]);
      }),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-6-value-leb",
      "6",
      "the int value 300 written in three bytes",
      edit(good, (p) => {
        const meta = [...metaOf(p)];
        // Rebuild the value metadata and bytes: 300 as 0xac 0x82 0x00.
        const values = A.decodeChange(good).ops.map((o) => o.value);
        const enc = values.map((v) =>
          v === 300 ? [0xac, 0x82, 0x00] : typeof v === "string" ? [...Buffer.from(v)] : [...sleb(v)],
        );
        const types = values.map((v) => (typeof v === "string" ? 6 : 4));
        const minimal = values.map((v) => (typeof v === "string" ? [...Buffer.from(v)] : [...sleb(v)]));
        const metaCol = (e) => rleCol(e.map((x, i) => x.length * 16 + types[i]), leb);
        if (hex(metaCol(minimal)) !== hex(meta) || hex(minimal.flat()) !== hex(column(p, VALUE)[1]))
          throw new Error("CAN-6: the value columns do not round-trip");
        setColumn(p, VALUE_META, metaCol(enc));
        setColumn(p, VALUE, enc.flat());
      }),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-6-value-type",
      "6",
      "a value of type 10",
      edit(good, (p) => {
        const values = A.decodeChange(good).ops.map((o) => o.value);
        const enc = values.map((v) => (typeof v === "string" ? [...Buffer.from(v)] : [...sleb(v)]));
        const metas = enc.map((e, i) => e.length * 16 + (i === 0 ? 10 : typeof values[i] === "string" ? 6 : 4));
        setColumn(p, VALUE_META, rleCol(metas, leb));
        setColumn(p, VALUE, enc.flat());
      }),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-7-make-value",
      "7",
      "a map made with an int value",
      (() => {
        const made = last(commit(A.init({ actor: ANDREY }), "CAN.make", (d) => {
          d.m = {};
        }));
        return edit(made, (p) => {
          setColumn(p, VALUE_META, rleCol([1 * 16 + 4], leb));
          p.columns.push([VALUE, Uint8Array.from([0x07])]);
          p.columns.sort(([a], [b]) => a - b);
        });
      })(),
      [],
      false,
    ),
    canonicalCase(
      "CAN-8-counter-F2",
      "8",
      "an object counter of 2^32 (finding F2: automerge-rs 0.12 aborts parsing it)",
      edit(good, (p) => {
        const objs = A.decodeChange(good).ops.map((o) => (o.obj === "_root" ? null : Number(o.obj.split("@")[0])));
        if (hex(rleCol(objs, leb)) !== hex(column(p, OBJ_CTR)[1])) throw new Error("CAN-8: object counters do not round-trip");
        setColumn(p, OBJ_CTR, rleCol(objs.map((c) => (c === 1 ? 2 ** 32 : c)), leb));
      }),
      goodHistory,
      false,
    ),
    canonicalCase(
      "CAN-9-preds-order",
      "9",
      "an operation's two predecessors in descending order",
      edit(twoDeps, (p) => {
        const preds = A.decodeChange(twoDeps).ops[0].pred.map((x) => x.split("@"));
        const index = (actor) => (actor === A.decodeChange(twoDeps).actor ? 0 : 1);
        const encodePreds = (list) => [
          rleCol(list.map(([, a]) => index(a)), leb),
          rleCol(deltas(list.map(([c]) => Number(c))), sleb),
        ];
        const [actors, counters] = encodePreds(preds);
        if (hex(actors) !== hex(column(p, PRED_ACTOR)[1]) || hex(counters) !== hex(column(p, PRED_CTR)[1]))
          throw new Error("CAN-9: predecessors do not round-trip");
        const [swappedActors, swappedCounters] = encodePreds([...preds].reverse());
        setColumn(p, PRED_ACTOR, swappedActors);
        setColumn(p, PRED_CTR, swappedCounters);
      }),
      twoHistory,
      false,
    ),
    // Added after the cases of earlier baselines, which are addressed by index.
    canonicalCase(
      "CAN-8-start-op-empty",
      "8",
      "a change without operations whose start op is 2^32 (finding N1: automerge-rs 0.12 refuses it)",
      edit(A.encodeChange({ ...A.decodeChange(good), ops: [] }), (p) => {
        p.startOp = 2 ** 32;
      }),
      goodHistory,
      false,
    ),
  ];
  // F2 and F3a as found: Data Unit plaintexts of the review.
  corpus.canonical = {
    rule: "SHARED-OBJECTS-PROFILE-01 §11.3: a receiver rejects a change that is not its one canonical encoding, before its engine",
    note:
      "Each case is checked with the §11.1 limits and the §11.3 rules alone; history_hex is the history the change was " +
      "written on, for an implementation that applies it after the check. Every change elsewhere in this corpus is canonical.",
    cases: refused,
  };

  // §11.4: changes built from Automerge's decoded changes, encoded again by
  // Automerge with one reference changed.
  const reference = (id, ruleId, description, history, change, admitted) => ({
    id,
    rule: `SHARED-OBJECTS-PROFILE-01 §11.4 (${ruleId}): operations refer only to the change's causal history`,
    description,
    history_hex: history.map(hex),
    change_hex: hex(change),
    expected: admitted
      ? { admitted: true }
      : { admitted: false, broken_rule: ruleId, error: { code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" } },
  });
  const changesOf = (doc) => A.getAllChanges(doc);
  // Counter c (1), k (2), then an increment of c (3), by andrey.
  const counters = commit(
    commit(A.init({ actor: ANDREY }), "REF.base", (d) => {
      d.c = new A.Counter(1);
      d.k = 1;
    }),
    "REF.inc",
    (d) => {
      d.c.increment(2);
    },
  );
  const cHist = changesOf(counters);
  const cHeads = A.getHeads(counters);
  const next = (ops, extra = {}) =>
    A.encodeChange({ actor: ANDREY, seq: 3, startOp: 4, time: 0, message: null, deps: cHeads, ops, ...extra });
  const put = (key, value, pred) => ({ action: "set", obj: "_root", key, value, datatype: "int", pred });
  // A list l (1) with elements 2, 3, a put on 2 (4), and a list m (5) with element 6.
  const lists = commit(A.init({ actor: ANDREY }), "REF.lists", (d) => {
    d.l = [1, 2];
    d.l[0] = 3;
    d.m = [1];
  });
  const lHist = changesOf(lists);
  const lHeads = A.getHeads(lists);
  const lid = (c) => `${c}@${ANDREY}`;
  const lnext = (ops) =>
    A.encodeChange({ actor: ANDREY, seq: 2, startOp: 7, time: 0, message: null, deps: lHeads, ops });
  const lput = (elemId, pred, insert = false) => ({
    action: "set",
    obj: lid(1),
    elemId,
    insert,
    value: 9,
    datatype: "int",
    pred,
  });
  if (A.decodeChange(lHist[0]).ops.length !== 6) throw new Error("REF.lists: expected 6 operations");
  const inc = (key, pred) => ({ action: "inc", obj: "_root", key, value: 1, pred });
  // pavel's concurrent counter c; andrey's own increment after merging it
  // names both puts (R8 admits it).
  const pavelC = last(commit(A.init({ actor: PAVEL }), "REF.pavel-counter", (d) => {
    d.c = new A.Counter(5);
  }));
  const twoCounters = last(
    commit(A.applyChanges(A.clone(counters, { actor: ANDREY }), [pavelC])[0], "REF.inc-two", (d) => {
      d.c.increment(1);
    }),
  );
  {
    const ops = A.decodeChange(twoCounters).ops;
    if (ops.length !== 1 || ops[0].action !== "inc" || ops[0].pred.length !== 2) throw new Error("REF.inc-two: expected one increment naming both counters");
  }
  // A text t, then Automerge's own mark of its first character (R9).
  const text = commit(A.init({ actor: ANDREY }), "REF.text", (d) => {
    d.t = "ab";
  });
  const tHist = changesOf(text);
  const markChange = last(
    commit(text, "REF.mark", (d) => {
      A.mark(d, ["t"], { start: 0, end: 1, expand: "none" }, "bold", true);
    }),
  );
  if (!A.decodeChange(markChange).ops.every((o) => /^mark/.test(o.action))) throw new Error("REF.mark: expected mark operations");
  // pavel's concurrent k, not in the history of andrey's next change.
  const pavelK = last(commit(A.init({ actor: PAVEL }), "REF.pavel", (d) => {
    d.k = 2;
  }));
  const rcase = [
    reference("REF-control-overwrite", "R6", "overwrite the counter, predecessor the counter", cHist, next([put("c", 5, [lid(1)])]), true),
    reference("REF-control-pred-increment", "R6", "predecessor the increment", cHist, next([put("c", 5, [lid(3)])]), true),
    reference("REF-control-pred-in-change", "R6", "predecessor earlier in the change", cHist, next([put("z", 5, []), put("z", 6, [lid(4)])]), true),
    reference("REF-control-list-put", "R5", "put on an element, predecessor the last put", lHist, lnext([lput(lid(2), [lid(4)])]), true),
    reference("REF-R1-previous-not-in-history", "R1", "andrey's third change with no dependencies", cHist, next([put("z", 1, [])], { deps: [], startOp: 1 }), false),
    reference("REF-R2-start-past-history", "R2", "start op 6 after a history whose largest counter is 3", cHist, next([put("z", 1, [])], { startOp: 6 }), false),
    reference("REF-R2-start-reuses-counter", "R2", "start op 3 reuses andrey's counter 3", cHist, next([put("z", 1, [])], { startOp: 3 }), false),
    reference(
      "REF-R2-empty-F3c",
      "R2",
      "an empty first change with start op 2 (finding F3c)",
      [],
      A.encodeChange({ actor: ANDREY, seq: 1, startOp: 2, time: 0, message: null, deps: [], ops: [] }),
      false,
    ),
    reference("REF-R3-not-an-object", "R3", "a put into 2@andrey, which is a put, not a made object", cHist, next([{ action: "set", obj: lid(2), key: "x", value: 1, datatype: "int", pred: [] }]), false),
    reference("REF-R3-property-on-list", "R3", "a property key on a list", lHist, lnext([{ action: "set", obj: lid(1), key: "x", value: 1, datatype: "int", pred: [] }]), false),
    reference("REF-R4-insert-into-map", "R4", "an insertion into the root map", cHist, next([{ action: "set", obj: "_root", elemId: "_head", insert: true, value: 1, datatype: "int", pred: [] }]), false),
    reference("REF-R4-insert-with-pred", "R4", "an insertion with a predecessor", lHist, lnext([lput("_head", [lid(2)], true)]), false),
    reference("REF-R4-after-a-put", "R4", "an insertion after 4@andrey, a put, not an element", lHist, lnext([lput(lid(4), [], true)]), false),
    reference("REF-R4-after-other-list", "R4", "an insertion into l after an element of m", lHist, lnext([lput(lid(6), [], true)]), false),
    reference("REF-R5-put-on-head", "R5", "a put on the head", lHist, lnext([lput("_head", [])]), false),
    reference("REF-R6-other-key-F4", "R6", "a put on k with the counter c as predecessor (finding F4)", cHist, next([put("k", 5, [lid(1)])]), false),
    reference("REF-R6-missing", "R6", "a predecessor that is no operation", cHist, next([put("k", 5, [lid(9)])]), false),
    reference("REF-R6-later-in-change", "R6", "a predecessor later in the change", cHist, next([put("k", 5, [lid(5)]), put("k", 6, [])]), false),
    reference("REF-R6-other-element-F3b", "R6", "a put on element 2 with element 3 as predecessor (finding F3b)", lHist, lnext([lput(lid(2), [lid(3)])]), false),
    reference(
      "REF-R6-concurrent",
      "R6",
      "a predecessor of pavel's, concurrent with the change: the replica holds it, the history does not",
      [...cHist, pavelK],
      next([put("k", 5, [`1@${PAVEL}`])]),
      false,
    ),
    reference("REF-R7-delete-without-pred-F3d", "R7", "a deletion without a predecessor (finding F3d)", cHist, next([{ action: "del", obj: "_root", key: "k", pred: [] }]), false),
    // Added after the cases of earlier baselines, which are addressed by index.
    reference("REF-control-increment", "R8", "an increment of the counter, predecessor the put that set it", cHist, next([inc("c", [lid(1)])]), true),
    reference("REF-R8-increment-not-counter", "R8", "an increment of k, whose put is an integer, not a counter", cHist, next([inc("k", [lid(2)])]), false),
    reference("REF-control-increment-two-counters", "R8", "Automerge's own increment of two concurrent counters: both puts are its predecessors", [...cHist, pavelC], twoCounters, true),
    reference("REF-R8-increment-no-pred", "R8", "an increment without a predecessor", cHist, next([inc("c", [])]), false),
    reference("REF-R8-increment-pred-increment", "R8", "an increment whose predecessor is the increment, not the counter's put", cHist, next([inc("c", [lid(3)])]), false),
    reference("REF-R9-mark", "R9", "Automerge's own mark of the first character of a text", tHist, markChange, false),
    reference("REF-R10-make-table", "R10", "a table made at the root key t", cHist, next([{ action: "makeTable", obj: "_root", key: "t", pred: [] }]), false),
    reference(
      "REF-R10-write-into-table-D1",
      "R10",
      "a table made and written into in one change (finding D1: automerge 0.12 aborts applying it)",
      cHist,
      next([
        { action: "makeTable", obj: "_root", key: "t", pred: [] },
        { action: "set", obj: lid(4), key: "x", value: 1, datatype: "int", pred: [] },
      ]),
      false,
    ),
  ];
  corpus.references = {
    rule: "SHARED-OBJECTS-PROFILE-01 §11.4: a receiver rejects, before its engine, a change whose operations refer outside its causal history",
    note:
      "Each case applies history_hex in order (all admitted), then gives change_hex to the replica's admission. A refused " +
      "change names the §11.4 rule it breaks (broken_rule); the replica's document is unchanged, still hands out its " +
      "changes, saves and loads. Every change of history_hex and change_hex is canonical (§11.3).",
    cases: rcase,
  };
}

// The compressed case is a real compressed change: Automerge itself decodes it.
if (A.decodeChange(compressed(nullSets(3))).ops.length !== 3) throw new Error("compressed() is wrong");

fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(path.join(OUT_DIR, OUT_NAME), JSON.stringify(corpus, null, 2) + "\n");
console.log(`wrote ${path.join(OUT_DIR, OUT_NAME)}`);
