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
const LIMITS = { change: { max_rows: 16384, max_group_sum: 16384, max_string_bytes: 4194304, max_deps: 1024, max_actors: 1024 }, snapshot_floor: { max_rows: 262144, max_group_sum: 262144, max_string_bytes: 33554432, max_inflated_bytes: 33554432, max_actors: 1024, max_heads: 1024 } };
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
    expansion("EXP-change-preds-at-limit", "change", "one operation with 16,384 predecessors", CHANGE_RULE, nullSets(1, "k", predsOf(16384)), true),
    expansion("EXP-change-preds-over-limit", "change", "one operation with 16,385 predecessors", CHANGE_RULE, nullSets(1, "k", predsOf(16385)), false),
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
// The compressed case is a real compressed change: Automerge itself decodes it.
if (A.decodeChange(compressed(nullSets(3))).ops.length !== 3) throw new Error("compressed() is wrong");

fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(path.join(OUT_DIR, OUT_NAME), JSON.stringify(corpus, null, 2) + "\n");
console.log(`wrote ${path.join(OUT_DIR, OUT_NAME)}`);
