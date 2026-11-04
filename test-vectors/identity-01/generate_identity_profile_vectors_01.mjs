#!/usr/bin/env node
// Generates IDENTITY-PROFILE-TEST-VECTORS-01 (IDENTITY-PROFILE-01 §12.2, ID-05):
// the Identity Resource document, admission (§3), state validation (§4),
// pairing links and fingerprints (§5.2), the approval digest, the rootOf
// tables of the wire corpus and assignee display (§10).
//
// Conventions of the Automerge reference corpus (SHARED-OBJECTS-AUTOMERGE-
// REFERENCE-01): every change is made by the pinned @automerge/automerge
// 3.5.0 with time 0 and no message, by the actor of SHARED-OBJECTS-PROFILE-01
// §8 for the Identity Resource I, so the output is deterministic. Principals,
// Resources, certificates and Control Records come from
// ../lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.json, which must be generated
// first.
//
// Every expectation below is written from the profile text and checked
// against the reference admission and validation of this file; a
// disagreement stops the generator. The reference decides the profile rules
// from the change's operations and the objects of its causal history; it is
// test support, not a production validator.
//
//   node generate_identity_profile_vectors_01.mjs [--out-dir DIR]

import * as A from "@automerge/automerge";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SUITE_ID = "IDENTITY-PROFILE-TEST-VECTORS-01";
const PROFILE = "org.openlfcp.identity.v1";
const outArg = process.argv.indexOf("--out-dir");
const OUT = outArg > 0 ? process.argv[outArg + 1] : HERE;

const wire = JSON.parse(readFileSync(join(HERE, "../lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.json"), "utf8"));
const legacy = JSON.parse(readFileSync(join(HERE, "../lfcp-wire-01/LFCP-TEST-VECTORS-01.json"), "utf8"));
const W = new Map(wire.cases.map((c) => [c.id, c]));

const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
const hex = (b) => Buffer.from(b).toString("hex");
const b64u = (b) => Buffer.from(b).toString("base64url");
const S = (v) => new A.ImmutableString(v);

const principal = (label) => {
  const c = W.get(`principal_${label.toLowerCase()}`);
  if (!c) throw new Error(`no principal ${label}`);
  return { id: Buffer.from(c.expected.principal_id.hex, "hex"), descriptor: Buffer.from(c.expected.descriptor_cbor.hex, "hex"), c };
};
const RES = Object.fromEntries(Object.entries(wire.fixtures.resources).map(([k, v]) => [k, Buffer.from(v.id.hex, "hex")]));
const I = RES.I;
const actorOf = (label) => hex(sha(Buffer.from("OPENLFCP-SHARED-OBJECTS-ACTOR-v1"), I, principal(label).id));
const pref = (label) => "p:" + b64u(principal(label).id);
const rref = (name) => b64u(RES[name]);
const SCOPE_FILL = Array.from({ length: 65 }, (_, k) => b64u(sha(Buffer.from(`LFCP-TV-IDENTITY-SCOPE-${String(k + 1).padStart(2, "0")}`))));
const recordId = (cid) => W.get(cid).inputs.record_id.hex;

// Writer classes at a Data Unit's control_ref, from I's Control state (§2.3).
function writerClass(label, controlRef) {
  const ps = W.get(controlRef).expected.post_state;
  if (ps.owner === label) return "root";
  const d = ps.devices[label];
  if (!d) return "other";
  return d.kind === 0 ? "personal" : d.kind === 2 ? "pairing" : "other";
}

// ---------------------------------------------------------------------------
// Deterministic CBOR (the subset needed here) and framing (SOP §11, §13).
// ---------------------------------------------------------------------------

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}
const bstr = (b) => Buffer.concat([head(2, b.length), Buffer.from(b)]);
const frame = (b) => Buffer.concat([Buffer.from([0x82, 0x01]), bstr(b)]);

/** Decodes a principal-descriptor (W §7): a closed map {0, 1, 2} of 32-byte strings; null if not one. */
function decodeDescriptor(bytes) {
  let i = 0;
  const b = Buffer.from(bytes);
  if (b[i++] !== 0xa3) return null;
  const out = {};
  for (let k = 0; k < 3; k++) {
    const key = b[i++];
    if (key !== k || b[i++] !== 0x58 || b[i++] !== 32) return null;
    out[k] = b.subarray(i, i + 32);
    i += 32;
  }
  if (i !== b.length) return null;
  if (!sha(Buffer.from("LFCP-PRINCIPAL-v1"), out[1], out[2]).equals(out[0])) return null;
  return out;
}

// ---------------------------------------------------------------------------
// Changes and replicas.
// ---------------------------------------------------------------------------

const CHANGES = new Map(); // name -> record

function record(name, writer, bytes, unitSeq, controlRef) {
  const d = A.decodeChange(bytes);
  const r = { name, writer, bytes: Buffer.from(bytes), unitSeq, controlRef, hash: d.hash, seq: d.seq, deps: d.deps, actor: d.actor, decoded: d };
  if (CHANGES.has(name)) throw new Error(`duplicate change ${name}`);
  CHANGES.set(name, r);
  return r;
}

/** The last change of `doc` made by `fn` as `writer`, recorded under `name`. */
function change(name, doc, writer, unitSeq, controlRef, fn) {
  const before = A.getHeads(doc);
  const next = A.change(A.clone(doc, { actor: actorOf(writer) }), { time: 0 }, fn);
  const bytes = A.getLastLocalChange(next);
  const r = record(name, writer, bytes, unitSeq, controlRef);
  // Automerge 3.5 lists the heads, plus the actor's own previous change when another change covers it.
  if (!before.every((h) => r.deps.includes(h))) throw new Error(`${name}: the change does not depend on the heads`);
  return { doc: next, r };
}

/** A document holding exactly the given changes and their ancestors (the causal history). */
function historyOf(deps) {
  const all = new Map([...CHANGES.values()].map((r) => [r.hash, r]));
  const need = new Set();
  const stack = [...deps];
  while (stack.length) {
    const h = stack.pop();
    if (need.has(h)) continue;
    need.add(h);
    stack.push(...all.get(h).deps);
  }
  const [doc] = A.applyChanges(A.init(), [...need].map((h) => all.get(h).bytes));
  return doc;
}

const CONTAINERS = ["roster", "devices", "requests", "extensions"];
const ADMISSION_ORDER = ["INVALID_AUTOMERGE_BYTES", "CHANGE_ACTOR_MISMATCH", "INVALID_ROOT", "CONTAINER_REPLACED", "IMMUTABLE_FIELD_MUTATED", "UNAUTHORIZED_WRITER", "INVALID_FIELD_TYPE"];

const oid = (obj, key) => (obj == null ? null : A.getObjectId(obj, key));
const values = (obj, key) => {
  if (obj == null) return [];
  let c;
  try {
    c = A.getConflicts(obj, key);
  } catch {
    c = undefined; // a value of a conflict set is not attached to the document: no nested conflicts to read
  }
  return c ? Object.values(c) : obj[key] === undefined ? [] : [obj[key]];
};
const str = (v) => (v === undefined || v === null ? v : A.isImmutableString(v) ? v.toString() : v);

/** AI0's content rule: exactly the six root keys, profile and identity.root set, four empty containers. */
function initialContent(doc, rootLabel) {
  const keys = Object.keys(doc).sort();
  if (JSON.stringify(keys) !== JSON.stringify(["devices", "extensions", "identity", "profile", "requests", "roster"])) return false;
  if (!A.isImmutableString(doc.profile) || str(doc.profile) !== PROFILE) return false;
  if (!doc.identity || JSON.stringify(Object.keys(doc.identity)) !== '["root"]' || !A.isImmutableString(doc.identity.root)) return false;
  if (str(doc.identity.root) !== pref(rootLabel)) return false;
  return CONTAINERS.every((k) => doc[k] && typeof doc[k] === "object" && !A.isImmutableString(doc[k]) && Object.keys(doc[k]).length === 0);
}

/**
 * The §3 diagnostic of change `r` (null when admitted), decided on its causal
 * history and its writer class at its control_ref. `held` means the
 * (actor, seq) is taken by a different change in `doc` (SOP §14.1).
 */
function admit(r, root = "OWNER") {
  if (r.actor !== actorOf(r.writer)) return "CHANGE_ACTOR_MISMATCH";
  if (r.deps.length === 0) {
    if (r.seq !== 1) return "INVALID_AUTOMERGE_BYTES"; // SOP §11.4 R1, before AI0
    if (r.actor !== actorOf(root) || r.unitSeq !== 1) return "INVALID_ROOT";
    const [doc] = A.applyChanges(A.init(), [r.bytes]);
    return initialContent(doc, root) ? null : "INVALID_ROOT";
  }
  const prev = historyOf(r.deps);
  const latest = A.getAllChanges(prev).map((b) => A.decodeChange(b)).filter((d) => d.actor === r.actor).length;
  if (r.seq !== latest + 1) return "INVALID_AUTOMERGE_BYTES";
  const [next] = A.applyChanges(A.clone(prev), [r.bytes]);
  const found = new Set();
  const ops = r.decoded.ops;
  const idOf = (i) => `${r.decoded.startOp + i}@${r.actor}`;
  const containerOids = Object.fromEntries(CONTAINERS.map((k) => [oid(prev, k), k]));
  const identityOid = oid(prev, "identity");
  // Objects of entries (and the lists inside them) in the history: object id -> [container, key].
  const entryOf = new Map();
  for (const k of ["roster", "devices", "requests"]) {
    for (const [key, entry] of Object.entries(prev[k] ?? {})) {
      const eid = oid(prev[k], key);
      if (eid) entryOf.set(eid, [k, key]);
      for (const [f, v] of Object.entries(entry ?? {})) {
        const lid = oid(entry, f);
        if (lid && v && typeof v === "object" && !A.isImmutableString(v)) entryOf.set(lid, [k, key, f]);
      }
    }
  }
  for (const op of ops) {
    if (op.obj === "_root" && CONTAINERS.includes(op.key)) found.add("CONTAINER_REPLACED");
    if (containerOids[op.obj] && op.action === "set" && values(prev[containerOids[op.obj]], op.key).some((v) => typeof v === "object" && !A.isImmutableString(v))) found.add("CONTAINER_REPLACED");
    if (entryOf.has(op.obj) && entryOf.get(op.obj).length === 2 && op.action === "set") {
      const [k, key] = entryOf.get(op.obj);
      const cur = prev[k][key]?.[op.key];
      if (cur && typeof cur === "object" && !A.isImmutableString(cur)) found.add("CONTAINER_REPLACED");
    }
    if ((op.obj === "_root" && (op.key === "profile" || op.key === "identity")) || (identityOid && op.obj === identityOid)) found.add("IMMUTABLE_FIELD_MUTATED");
    if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
    // §2.1: the profile's scalars are ImmutableString, boolean and uint; an int, float, counter or timestamp is not one (AI3).
    if (op.action === "set" && ["int", "float64", "counter", "timestamp"].includes(op.datatype)) found.add("INVALID_FIELD_TYPE");
  }
  const cls = writerClass(r.writer, r.controlRef);
  if (cls === "pairing" || cls === "other") {
    const mine = pref(r.writer);
    const requestsOid = oid(prev, "requests");
    const made = new Map(); // object id made in this change -> entry key
    const keys = new Set();
    let violation = false;
    ops.forEach((op, i) => {
      if (op.action === "del") return (violation = true);
      if (op.obj === requestsOid) {
        if (op.action !== "makeMap" || values(prev.requests, op.key).length > 0) return (violation = true);
        made.set(idOf(i), op.key);
        keys.add(op.key);
        return;
      }
      if (made.has(op.obj)) {
        if (op.action.startsWith("make")) made.set(idOf(i), made.get(op.obj));
        keys.add(made.get(op.obj));
        return;
      }
      const e = entryOf.get(op.obj);
      if (e && e[0] === "requests") {
        const key = e[1];
        const entry = prev.requests[key];
        const owned = oid(prev.requests, key).endsWith(`@${r.actor}`) && values(prev.requests, key).length === 1 &&
          values(entry, "pairing").length === 1 && str(entry.pairing) === mine;
        if (!owned) return (violation = true);
        if (op.action.startsWith("make")) made.set(idOf(i), key);
        keys.add(key);
        return;
      }
      violation = true;
    });
    if (keys.size !== 1) violation = true;
    for (const key of keys) {
      const after = next.requests?.[key];
      if (!after || values(next.requests, key).length !== 1 || values(after, "pairing").length !== 1 || str(after.pairing) !== mine) violation = true;
    }
    if (violation) found.add("UNAUTHORIZED_WRITER");
  }
  // AI5 (decision I8): devices[k].missing_keys, and anything inside it, is written only by the Principal k names.
  {
    const mine = pref(r.writer);
    const devicesOid = oid(prev, "devices");
    const entryKey = new Map(); // entry map object id (in the history or made here) -> key
    const hint = new Map(); // object id inside some devices[k].missing_keys -> k
    for (const key of Object.keys(prev.devices ?? {})) {
      const eid = oid(prev.devices, key);
      if (!eid) continue;
      entryKey.set(eid, key);
      const walk = (parent, prop) => {
        const v = parent[prop];
        if (!v || typeof v !== "object" || A.isImmutableString(v)) return;
        hint.set(oid(parent, prop), key);
        for (const p of Object.keys(v)) walk(v, Array.isArray(v) ? Number(p) : p);
      };
      if (prev.devices[key] && typeof prev.devices[key] === "object") walk(prev.devices[key], "missing_keys");
    }
    let foreign = false;
    ops.forEach((op, i) => {
      if (op.obj === devicesOid) {
        // Deleting or replacing devices[k] is not a write of missing_keys; a map made here may receive one.
        if (op.action === "makeMap") entryKey.set(idOf(i), op.key);
        return;
      }
      const key = entryKey.has(op.obj) && op.key === "missing_keys" ? entryKey.get(op.obj) : hint.get(op.obj);
      if (key === undefined) return;
      if (op.action.startsWith("make")) hint.set(idOf(i), key);
      if (key !== mine) foreign = true;
    });
    if (foreign) found.add("UNAUTHORIZED_WRITER");
  }
  return ADMISSION_ORDER.find((d) => found.has(d)) ?? null;
}

/**
 * A replica: delivers Data Unit plaintexts in an order and reports what it
 * admitted, refused, held and kept pending (§2.2, §3, SOP §14.1).
 */
function replay(names, { blocked = [] } = {}) {
  let doc = A.init();
  const refused = {};
  const pending = [];
  const admitted = [];
  let initial = null;
  const queue = [...names];
  const tryApply = (n) => {
    const r = CHANGES.get(n);
    // AI0's eligibility is decided on the bytes and the carrying unit, before any hold.
    if (r.actor !== actorOf(r.writer)) return (refused[n] = "CHANGE_ACTOR_MISMATCH"), true;
    if (r.deps.length === 0 && (r.seq !== 1 || r.actor !== actorOf("OWNER") || r.unitSeq !== 1)) return (refused[n] = admit(r)), true;
    const heads = new Set(A.getAllChanges(doc).map((b) => A.decodeChange(b).hash));
    if (!r.deps.every((d) => heads.has(d))) return false;
    const diag = admit(r);
    if (diag) return (refused[n] = diag), true;
    [doc] = A.applyChanges(doc, [r.bytes]);
    admitted.push(n);
    if (r.deps.length === 0) initial = n;
    return true;
  };
  const waiting = [];
  for (const n of queue) {
    if (blocked.includes(n)) { waiting.push(n); continue; }
    if (!tryApply(n)) waiting.push(n);
    let progress = true;
    while (progress) {
      progress = false;
      for (const w of [...waiting]) if (!blocked.includes(w) && tryApply(w)) { waiting.splice(waiting.indexOf(w), 1); progress = true; }
    }
  }
  for (const b of blocked) {
    let progress = true;
    blocked = blocked.filter((x) => x !== b);
    while (progress) {
      progress = false;
      for (const w of [...waiting]) if (!blocked.includes(w) && tryApply(w)) { waiting.splice(waiting.indexOf(w), 1); progress = true; }
    }
  }
  pending.push(...waiting);
  return { doc, admitted, refused, pending, initial };
}

// ---------------------------------------------------------------------------
// State validation (§4).
// ---------------------------------------------------------------------------

const B64_32 = /^[A-Za-z0-9_-]{43}$/;
const isResourceRef = (v) => typeof v === "string" && B64_32.test(v) && Buffer.from(v, "base64url").length === 32 && b64u(Buffer.from(v, "base64url")) === v;
const isPrincipalRef = (v) => typeof v === "string" && v.startsWith("p:") && isResourceRef(v.slice(2));
const TS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/;
function isTimestamp(v) {
  const m = TS.exec(v);
  if (!m) return false;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  const dt = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d && h < 24 && mi < 60 && s < 60;
}
const STATE_ORDER = ["INVALID_ROOT", "MISSING_REQUIRED_FIELD", "INVALID_FIELD_TYPE", "INVALID_RESOURCE_REF", "INVALID_PRINCIPAL_REF", "INVALID_DESCRIPTOR", "INVALID_ENUM_VALUE", "INVALID_TIMESTAMP", "INVALID_EXTENSION_NAMESPACE"];
const isStr = (v) => A.isImmutableString(v);
// A uint is read back as a bigint; an Automerge int (a JS number) is not a uint (§2.1).
const isUint = (v) => typeof v === "bigint" && v >= 0n;
/** Writes a plain value on live proxies: numbers as A.Uint, strings as ImmutableString (Automerge turns a Uint nested in a literal into a map). */
function put(target, key, value) {
  if (A.isImmutableString(value) || typeof value === "boolean" || value === null) target[key] = value;
  else if (typeof value === "number") target[key] = new A.Uint(value);
  else if (typeof value === "string") target[key] = S(value);
  else if (Array.isArray(value)) {
    target[key] = [];
    value.forEach((v, i) => put(target[key], i, v));
  } else {
    target[key] = {};
    for (const [k, v] of Object.entries(value)) put(target[key], k, v);
  }
}

function rootDiagnostic(doc, owner = "OWNER") {
  if (!isStr(doc.profile) || str(doc.profile) !== PROFILE) return "INVALID_ROOT";
  for (const k of CONTAINERS) if (!doc[k] || typeof doc[k] !== "object" || isStr(doc[k])) return "INVALID_ROOT";
  if (!doc.identity || !isStr(doc.identity.root) || str(doc.identity.root) !== pref(owner)) return "INVALID_ROOT";
  return null;
}

/** The first §4 diagnostic of one value of an entry, or null. */
function entryDiagnostic(container, key, entry) {
  const found = new Set();
  const field = (f) => entry[f];
  if (!entry || typeof entry !== "object" || isStr(entry)) return "INVALID_FIELD_TYPE";
  if (container === "roster") {
    if (!isResourceRef(key)) found.add("INVALID_RESOURCE_REF");
    for (const f of ["profile", "endpoints", "coordinator"]) if (field(f) === undefined) found.add("MISSING_REQUIRED_FIELD");
    if (field("profile") !== undefined && !isStr(field("profile"))) found.add("INVALID_FIELD_TYPE");
    if (field("coordinator") !== undefined && !isStr(field("coordinator"))) found.add("INVALID_FIELD_TYPE");
    if (field("endpoints") !== undefined && !(Array.isArray(field("endpoints")) && field("endpoints").every(isStr))) found.add("INVALID_FIELD_TYPE");
    if (field("name") !== undefined && !isStr(field("name"))) found.add("INVALID_FIELD_TYPE");
    if (field("archived") !== undefined && typeof field("archived") !== "boolean") found.add("INVALID_FIELD_TYPE");
  } else if (container === "devices") {
    if (!isPrincipalRef(key)) found.add("INVALID_PRINCIPAL_REF");
    for (const f of ["label", "kind"]) if (field(f) === undefined) found.add("MISSING_REQUIRED_FIELD");
    if (field("label") !== undefined && !isStr(field("label"))) found.add("INVALID_FIELD_TYPE");
    if (field("kind") !== undefined && !isUint(field("kind"))) found.add("INVALID_FIELD_TYPE");
    else if (field("kind") !== undefined && field("kind") > 1n) found.add("INVALID_ENUM_VALUE");
    if (field("added_at") !== undefined && !(isStr(field("added_at")) && isTimestamp(str(field("added_at"))))) found.add("INVALID_TIMESTAMP");
    const mk = field("missing_keys");
    if (mk !== undefined) {
      if (!mk || typeof mk !== "object" || isStr(mk) || Array.isArray(mk)) found.add("INVALID_FIELD_TYPE");
      else for (const [k, eps] of Object.entries(mk)) {
        if (!isResourceRef(k)) found.add("INVALID_RESOURCE_REF");
        if (!Array.isArray(eps) || !eps.every(isUint)) found.add("INVALID_FIELD_TYPE");
      }
    }
  } else {
    if (!isPrincipalRef(key)) found.add("INVALID_PRINCIPAL_REF");
    for (const f of ["descriptor", "pairing", "label", "kind"]) if (field(f) === undefined) found.add("MISSING_REQUIRED_FIELD");
    const kind = field("kind");
    if (kind !== undefined && !isUint(kind)) found.add("INVALID_FIELD_TYPE");
    else if (kind !== undefined && kind > 1n) found.add("INVALID_ENUM_VALUE");
    const scope = field("scope");
    if (kind === 1n && scope === undefined) found.add("MISSING_REQUIRED_FIELD");
    if (scope !== undefined) {
      if (kind === 0n || !Array.isArray(scope) || scope.length === 0 || scope.length > 64 || !scope.every(isStr) || new Set(scope.map(str)).size !== scope.length) found.add("INVALID_FIELD_TYPE");
      else if (!scope.every((s) => isResourceRef(str(s)))) found.add("INVALID_RESOURCE_REF");
    }
    for (const f of ["descriptor", "pairing", "label"]) if (field(f) !== undefined && !isStr(field(f))) found.add("INVALID_FIELD_TYPE");
    if (isStr(field("pairing")) && !isPrincipalRef(str(field("pairing")))) found.add("INVALID_PRINCIPAL_REF");
    if (isStr(field("descriptor"))) {
      const raw = str(field("descriptor"));
      const d = /^[A-Za-z0-9_-]*$/.test(raw) ? decodeDescriptor(Buffer.from(raw, "base64url")) : null;
      if (!d || !isPrincipalRef(key) || !Buffer.from(key.slice(2), "base64url").equals(d[0])) found.add("INVALID_DESCRIPTOR");
    }
    if (field("requested_at") !== undefined && !(isStr(field("requested_at")) && isTimestamp(str(field("requested_at"))))) found.add("INVALID_TIMESTAMP");
  }
  return STATE_ORDER.find((d) => found.has(d)) ?? null;
}

/**
 * The concurrent values of `obj[key]` with their scalar type restored:
 * getConflicts returns a plain JS string for both an ImmutableString and a
 * Text, so the type is read from the operation that wrote each value.
 */
function typedValues(doc, obj, key) {
  let c;
  try {
    c = A.getConflicts(obj, key);
  } catch {
    c = undefined;
  }
  if (!c) return values(obj, key);
  const ops = new Map();
  for (const b of A.getAllChanges(doc)) {
    const d = A.decodeChange(b);
    d.ops.forEach((op, i) => ops.set(`${d.startOp + i}@${d.actor}`, op));
  }
  return Object.entries(c).map(([id, v]) => {
    if (typeof v !== "string") return v;
    const op = ops.get(id);
    return op?.action === "makeText" ? { text: v } : S(v);
  });
}

/** §4 per entry, with rule 2 for concurrent values. */
function validateEntry(doc, container, key) {
  const maps = values(doc[container], key);
  if (maps.length > 1) return { valid: false, conflicted: true, diagnostic: null };
  const entry = maps[0];
  const fields = Object.keys(entry ?? {});
  for (const f of fields) {
    const vs = typedValues(doc, entry, f);
    if (vs.length > 1) {
      const diags = vs.map((v) => entryDiagnostic(container, key, { ...plainEntry(entry), [f]: v }));
      if (container === "requests") return { valid: false, conflicted: true, diagnostic: STATE_ORDER.find((d) => diags.includes(d)) ?? null };
      if (f === "kind") return { valid: false, conflicted: true, diagnostic: null };
      const bad = STATE_ORDER.find((d) => diags.includes(d));
      if (bad) return { valid: false, diagnostic: bad };
    }
  }
  const diag = entryDiagnostic(container, key, entry);
  return { valid: diag === null, diagnostic: diag };
}
const plainEntry = (entry) => Object.fromEntries(Object.keys(entry).map((k) => [k, entry[k]]));

/** A JSON view of the document: scalars as values, concurrent values as `<field>_conflict_set`. */
function view(obj) {
  if (A.isImmutableString(obj)) return obj.toString();
  if (typeof obj === "bigint") return Number(obj);
  if (Array.isArray(obj)) return obj.map(view);
  if (obj && typeof obj === "object") {
    const out = {};
    for (const k of Object.keys(obj).sort()) {
      const vs = values(obj, k);
      if (vs.length > 1) out[`${k}_conflict_set`] = vs.map(view).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
      else out[k] = view(obj[k]);
    }
    return out;
  }
  return obj;
}

// ---------------------------------------------------------------------------
// The document fixtures.
// ---------------------------------------------------------------------------

const ROSTER_X = { profile: S("org.lfcp.test.raw.v1"), endpoints: [S(wire.fixtures.endpoint.url)], coordinator: S(wire.fixtures.endpoint.coordinator), name: S("Project X") };
const ROSTER_Y = { profile: S("org.lfcp.test.raw.v1"), endpoints: [S(wire.fixtures.endpoint.url)], coordinator: S(wire.fixtures.endpoint.coordinator), name: S("Project Y") };

function initialFn(rootRef = pref("OWNER"), extra = {}) {
  return (d) => {
    d.profile = S(PROFILE);
    d.identity = { root: S(rootRef) };
    d.roster = {};
    d.devices = {};
    d.requests = {};
    d.extensions = {};
    Object.assign(d, extra);
  };
}

const reqEntry = (device, pairing, extra = {}) => ({
  descriptor: S(b64u(principal(device).descriptor)), pairing: S(pref(pairing)), label: S(`${device} laptop`), kind: 0, platform: S("desktop"), ...extra,
});

const empty = A.init({ actor: actorOf("OWNER") });
const C0 = change("C0_initial", empty, "OWNER", 1, "P0_genesis_i", initialFn());
const C1 = change("C1_fill", C0.doc, "OWNER", 2, "P0_genesis_i", (d) => {
  d.roster[rref("X")] = ROSTER_X;
  d.roster[rref("Y")] = ROSTER_Y;
  put(d.devices, pref("OWNER"), { label: S("Desktop"), kind: 0 });
});
const BASE = C1.doc;

// ---------------------------------------------------------------------------
// Cases.
// ---------------------------------------------------------------------------

const CASES = [];
const add = (c) => {
  if (CASES.some((x) => x.id === c.id)) throw new Error(`duplicate case ${c.id}`);
  CASES.push(c);
  return c;
};
const changeInputs = (r) => ({
  writer: r.writer,
  writer_class: writerClass(r.writer, r.controlRef),
  writer_ref: pref(r.writer),
  automerge_actor: r.actor,
  automerge_seq: r.seq,
  unit_actor_seq: r.unitSeq,
  control_ref: r.controlRef,
  change_hash: r.hash,
  deps: r.deps,
  automerge_change: { hex: hex(r.bytes) },
  framed_plaintext: { hex: hex(frame(r.bytes)) },
});
const historyRefs = (r) => {
  const all = new Map([...CHANGES.values()].map((x) => [x.hash, x]));
  const need = [];
  const seen = new Set();
  const visit = (h) => {
    if (seen.has(h)) return;
    seen.add(h);
    all.get(h).deps.forEach(visit);
    need.push(all.get(h).name);
  };
  r.deps.forEach(visit);
  return need;
};

function check(id, got, want) {
  if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`${id}: expected ${JSON.stringify(want)}, reference gives ${JSON.stringify(got)}`);
}

const RULES = {
  AI0: ["IDENTITY-PROFILE-01 §2.2, §3 AI0", "The initial change has no dependencies, is the root actor's Automerge sequence 1, is carried by the root's Data Unit with actor sequence 1, and creates exactly the six root keys with the four containers empty."],
  R1: ["SHARED-OBJECTS-PROFILE-01 §11.4 R1; IDENTITY-PROFILE-01 §2.2", "A change with sequence number s > 1 has its actor's change s - 1 in its causal history; reported before INVALID_ROOT."],
  AI1: ["IDENTITY-PROFILE-01 §3 AI1", "A change that is not the initial change does not write profile or anything under identity."],
  AI2: ["IDENTITY-PROFILE-01 §3 AI2", "A change does not replace or delete roster, devices, requests or extensions."],
  AI3: ["IDENTITY-PROFILE-01 §3 AI3", "Collaborative Text is never used."],
  AI4: ["IDENTITY-PROFILE-01 §3 AI4", "A pairing or other writer creates or writes into one entry requests[k] that it owns, deletes nothing and replaces no entry map; pairing stays its own PrincipalRef."],
  AI5: ["IDENTITY-PROFILE-01 §2.1, §3 AI5", "devices[k].missing_keys, and anything inside it, is created, written or deleted only by the Principal whose PrincipalRef is k (the root for its own entry); deleting the entry devices[k], or replacing it with a map without missing_keys, is not a write of missing_keys."],
  RESERVED: ["IDENTITY-PROFILE-01 §2.4", "Admission has no rule for the reserved root keys: a later change that writes them is admitted when §3 otherwise admits it; the value is preserved uninterpreted."],
  OK: ["IDENTITY-PROFILE-01 §3", "The change passes the checks of its bytes, the sequence checks and AI0 to AI4."],
};

function changeCase(id, r, want, description, { rule } = {}) {
  const got = admit(r);
  check(id, got, want);
  const [sec, text] = RULES[rule ?? (want === null ? "OK" : { INVALID_ROOT: "AI0", INVALID_AUTOMERGE_BYTES: "R1", IMMUTABLE_FIELD_MUTATED: "AI1", CONTAINER_REPLACED: "AI2", INVALID_FIELD_TYPE: "AI3", UNAUTHORIZED_WRITER: "AI4" }[want])];
  return add({
    id, type: "validation", kind: "profile_change", description, rule: { section: sec, text },
    inputs: changeInputs(r),
    context: { history: historyRefs(r).map((n) => ({ case: `change.${n}`, field: "automerge_change_hex", in: "inputs" })) },
    expected: want === null ? { valid: true } : { valid: false, error: { code: "PROFILE_INVALID", diagnostic: want } },
  });
}

/** Every recorded change, published once as a bytes case so that others can reference it. */
function changeRecords() {
  for (const r of CHANGES.values()) {
    add({
      id: `change.${r.name}`, type: "bytes", kind: "profile_change_framing",
      description: `Automerge change ${r.name} by ${r.writer} (unit actor sequence ${r.unitSeq}, control_ref ${r.controlRef})`,
      inputs: { automerge_change_hex: { hex: hex(r.bytes) }, ...Object.fromEntries(Object.entries(changeInputs(r)).filter(([k, v]) => !["automerge_change", "framed_plaintext", "deps"].includes(k))), deps: r.deps.join(",") },
      expected: { framed_cbor: { hex: hex(frame(r.bytes)) }, sha256: { hex: hex(sha(frame(r.bytes))) } },
    });
  }
}

// ---- documents (§2, §3) ----

check("identity_doc_initial", admit(C0.r), null);
add({
  id: "identity_doc_initial", type: "bytes", kind: "profile_change_framing",
  description: "The initial change of I for OWNER: profile, identity.root and four empty containers (§2.2)",
  rule: { section: RULES.AI0[0], text: RULES.AI0[1] },
  inputs: { automerge_change_hex: { hex: hex(C0.r.bytes) }, writer: "OWNER", automerge_actor: C0.r.actor, automerge_seq: 1, unit_actor_seq: 1, control_ref: "P0_genesis_i", change_hash: C0.r.hash },
  expected: { framed_cbor: { hex: hex(frame(C0.r.bytes)) }, sha256: { hex: hex(sha(frame(C0.r.bytes))) } },
  note: "Valid: see identity_doc_initial.admission.",
});
changeCase("identity_doc_initial.admission", C0.r, null, "The initial change is admitted", { rule: "AI0" });

const byDev = change("D0_initial_by_dev_a", A.init({ actor: actorOf("DEV_A") }), "DEV_A", 1, "P1_device_grant_dev_a_i", initialFn());
changeCase("identity_doc_initial_by_device", byDev.r, "INVALID_ROOT", "An initial change authored by DEV_A's actor, in DEV_A's unit 1");
const extraKey = change("C0x_initial_extra_key", A.init({ actor: actorOf("OWNER") }), "OWNER", 1, "P0_genesis_i", initialFn(pref("OWNER"), { recovery: {} }));
changeCase("identity_doc_initial_extra_key", extraKey.r, "INVALID_ROOT", "An initial change that also creates the reserved key recovery");
const filled = change("C0f_initial_filled_roster", A.init({ actor: actorOf("OWNER") }), "OWNER", 1, "P0_genesis_i", (d) => {
  initialFn()(d);
  d.roster[rref("X")] = ROSTER_X;
});
changeCase("identity_doc_initial_filled_roster", filled.r, "INVALID_ROOT", "An initial change whose roster is not empty");
const badRoot = change("C0b_initial_bad_root", A.init({ actor: actorOf("OWNER") }), "OWNER", 1, "P0_genesis_i", initialFn(pref("BOB")));
changeCase("identity_doc_bad_root", badRoot.r, "INVALID_ROOT", "An initial change with identity.root = p:<BOB>, not the Genesis owner");

// A second root change without dependencies, carried by the root's unit 2.
const second = change("C0s_second_initial", A.init({ actor: actorOf("OWNER") }), "OWNER", 2, "P0_genesis_i", initialFn(pref("OWNER"), {}));
// Make it differ from C0: its own roster key is set later by the fill F; the change itself is a valid-looking initial change.
if (second.r.hash === C0.r.hash) {
  CHANGES.delete("C0s_second_initial");
}
const secondDistinct = CHANGES.has("C0s_second_initial") ? second : change("C0s_second_initial", A.init({ actor: actorOf("OWNER") }), "OWNER", 2, "P0_genesis_i", (d) => {
  initialFn()(d);
  d.extensions = {};
  d.devices = {};
});
const fillOnSecond = change("F_fill_on_second", secondDistinct.doc, "OWNER", 3, "P0_genesis_i", (d) => {
  d.roster[rref("Y")] = ROSTER_Y;
});

const second2 = (() => {
  // C0 and C0s must differ; if A.change produced identical bytes, the variant above differs by key order of creation.
  if (secondDistinct.r.hash === C0.r.hash) throw new Error("C0s equals C0");
  return secondDistinct;
})();

function scenario(id, description, rule, inputs, expected, assertions) {
  return add({ id, type: "behavioral", kind: "identity_document", description, rule: { section: rule[0], text: rule[1] }, inputs, expected, assertions });
}

{
  const orders = { unit1_first: ["C0_initial", "C0s_second_initial", "F_fill_on_second"], unit2_first: ["C0s_second_initial", "F_fill_on_second", "C0_initial"] };
  const out = {};
  for (const [k, names] of Object.entries(orders)) {
    const res = replay(names);
    out[k] = { initial_change: res.initial, refused: res.refused, held: [], pending: res.pending };
  }
  const blocked = replay(["C0s_second_initial", "F_fill_on_second", "C0_initial"], { blocked: ["C0_initial"] });
  out.unit1_key_blocked = { initial_change: blocked.initial, refused: blocked.refused, held: [], pending: blocked.pending };
  const want = { initial_change: "C0_initial", refused: { C0s_second_initial: "INVALID_ROOT" }, held: [], pending: ["F_fill_on_second"] };
  for (const v of Object.values(out)) check("identity_doc_second_initial_other_unit", v, want);
  scenario("identity_doc_second_initial_other_unit",
    "Two different root changes without dependencies, Automerge sequence 1, in the root's Data Units with actor sequences 1 and 2, and a fill change depending on the second",
    RULES.AI0,
    { changes: ["C0_initial", "C0s_second_initial", "F_fill_on_second"].map((n) => ({ case: `change.${n}` })),
      orders: { ...orders, unit1_key_blocked: { order: orders.unit2_first, key_blocked_until_end: ["C0_initial"] } },
      snapshot: { b64url: b64u(A.save(historyOf([C0.r.hash]))), carries: "C0_initial", loaded_after: "the root's unit 1 is fetched and verified" } },
    { by_order: { unit1_first: out.unit1_first, unit2_first: out.unit2_first, unit1_key_blocked: out.unit1_key_blocked },
      snapshot: { initial_change: "C0_initial", used: true } },
    ["The unit-1 change is the initial change in every order; the unit-2 change is INVALID_ROOT at once (AI0 runs before the sequence hold of SOP §14.1) and is never held; the fill depends on it and waits forever.",
     "A KEY_BLOCKED unit 1 holds the whole document until it opens; nothing else becomes the initial change meanwhile.",
     "The same choice is made from a Snapshot once the root's unit 1 is fetched and its change is found in the Snapshot."]);
}
{
  const other = change("C0o_other_initial", A.init({ actor: actorOf("OWNER") }), "OWNER", 1, "P0_genesis_i", (d) => {
    d.extensions = {};
    initialFn()(d);
  });
  if (other.r.hash === C0.r.hash) throw new Error("C0o equals C0");
  CHANGES.delete("C0o_other_initial");
  const snap = A.save(other.doc);
  scenario("identity_doc_initial_without_unit_1",
    "A Snapshot whose change without dependencies is not the change of the root's Data Unit with actor sequence 1 (C0_initial)",
    ["IDENTITY-PROFILE-01 §2.2", "A replica that loads the document from a Snapshot takes the Snapshot's change without dependencies as the initial change only after it holds and has verified the root's Data Unit with actor sequence 1 and found that change in it."],
    { snapshot: { b64url: b64u(snap) }, snapshot_initial_change_hash: other.r.hash, root_unit_1: { case: "change.C0_initial" } },
    { snapshot_used: false, initial_change: "C0_initial" },
    ["The Snapshot's state is not used; the replica replays the units instead."]);
}
{
  // An initial-shaped change of the root with Automerge sequence 2 and no dependencies: C1 with its dependency removed.
  const bytes = Buffer.from(C1.r.bytes);
  const crafted = dropDeps(bytes);
  const r = record("C1x_seq_2_without_deps", "OWNER", crafted, 1, "P0_genesis_i");
  changeCase("identity_doc_initial_seq_2", r, "INVALID_AUTOMERGE_BYTES", "A change without dependencies with Automerge sequence 2 (C1_fill with its dependency removed), in the root's unit 1");
}
{
  const inUnit2 = change("C0u2_initial_in_unit_2", A.init({ actor: actorOf("OWNER") }), "OWNER", 2, "P0_genesis_i", (d) => {
    d.devices = {};
    initialFn()(d);
  });
  changeCase("identity_doc_initial_in_unit_2", inUnit2.r, "INVALID_ROOT", "A well-formed change without dependencies, Automerge sequence 1, carried by the root's Data Unit with actor sequence 2");
}
{
  const a = replay(["C0_initial", "C1_fill"]);
  const b = replay(["C1_fill", "C0_initial"]);
  const fromSnap = A.load(A.save(BASE));
  check("identity_doc_initial_then_fill", [view(a.doc), view(b.doc)], [view(BASE), view(BASE)]);
  check("identity_doc_initial_then_fill.snapshot", view(fromSnap), view(BASE));
  scenario("identity_doc_initial_then_fill", "The two changes of §5.1, in both orders, and the same state from a Snapshot",
    ["IDENTITY-PROFILE-01 §2.2, §5.1", "A dependent change that arrives first waits for the initial change; the state is a function of the accepted changes."],
    { changes: [{ case: "change.C0_initial" }, { case: "change.C1_fill" }], orders: [["C0_initial", "C1_fill"], ["C1_fill", "C0_initial"]],
      snapshot: { b64url: b64u(A.save(BASE)) } },
    { state: view(BASE), root_valid: rootDiagnostic(BASE) === null, admitted: ["C0_initial", "C1_fill"],
      entries: { roster: { [rref("X")]: "valid", [rref("Y")]: "valid" }, devices: { [pref("OWNER")]: "valid" } } },
    ["Both orders and the Snapshot give the same state and the same validation outcome."]);
}
{
  const profileMut = change("C2_profile_mutated", BASE, "OWNER", 3, "P0_genesis_i", (d) => { d.profile = S("org.openlfcp.identity.v2"); });
  changeCase("identity_doc_profile_mutated", profileMut.r, "IMMUTABLE_FIELD_MUTATED", "A later change by the root writing profile");
  const both = change("C2_container_and_profile", BASE, "OWNER", 3, "P0_genesis_i", (d) => { d.roster = {}; d.profile = S("org.openlfcp.identity.v2"); });
  changeCase("identity_doc_container_and_profile", both.r, "CONTAINER_REPLACED", "A change by the root replacing roster and writing profile: AI2 is reported before AI1");
  const reserved = change("C2_reserved_key_later", BASE, "OWNER", 3, "P0_genesis_i", (d) => { d.recovery = { note: S("reserved") }; });
  changeCase("identity_doc_reserved_key_later", reserved.r, null, "A later change by the root that creates the reserved key recovery: admitted, preserved, never interpreted",
    { rule: "RESERVED" });
  const replaced = change("C2_container_replaced", BASE, "OWNER", 3, "P0_genesis_i", (d) => { d.roster = {}; });
  changeCase("identity_doc_container_replaced", replaced.r, "CONTAINER_REPLACED", "A change by the root replacing roster with a new map");
  const text = change("C2_text_label", BASE, "OWNER", 3, "P0_genesis_i", (d) => { d.devices[pref("OWNER")].label = "Desktop (text)"; });
  changeCase("identity_doc_text_field", text.r, "INVALID_FIELD_TYPE", "A change by the root writing devices[p:OWNER].label as collaborative Text");
  const intKind = change("C2_int_kind", BASE, "OWNER", 3, "P0_genesis_i", (d) => { d.devices[pref("OWNER")].kind = 1; });
  changeCase("identity_doc_int_value", intKind.r, "INVALID_FIELD_TYPE", "A change by the root writing devices[p:OWNER].kind as an Automerge int, not a uint (§2.1)");
}

// ---- pairing writers (§3 AI4) ----

const asJ = (name, doc, unitSeq, fn, controlRef = "P2_pairing_device") => change(name, doc, "PAIR_J", unitSeq, controlRef, fn);
const own = asJ("J1_own_request", BASE, 1, (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_J")); });
changeCase("pairing_writes_own_request", own.r, null, "PAIR_J (control_ref P2) creates requests[p:<DEV_B>] with pairing = p:<PAIR_J>");
changeCase("pairing_writes_roster", asJ("J1_writes_roster", BASE, 1, (d) => { d.roster[rref("X")].name = S("Renamed"); }).r, "UNAUTHORIZED_WRITER", "PAIR_J writes roster[X].name");
changeCase("pairing_deletes_roster", asJ("J1_deletes_roster_entry", BASE, 1, (d) => { delete d.roster[rref("Y")]; }).r, "UNAUTHORIZED_WRITER", "PAIR_J deletes the roster entry of Y");
changeCase("pairing_deletes_roster.container", asJ("J1_deletes_roster_container", BASE, 1, (d) => { delete d.roster; }).r, "CONTAINER_REPLACED",
  "PAIR_J deletes the roster container itself: AI2 is reported before AI4");
changeCase("pairing_text_in_roster", asJ("J1_text_in_roster", BASE, 1, (d) => { d.roster[rref("X")].name = "renamed as text"; }).r, "UNAUTHORIZED_WRITER",
  "PAIR_J writes collaborative Text into roster[X]: AI4 is reported before AI3");
changeCase("pairing_writes_devices", asJ("J1_writes_devices", BASE, 1, (d) => { d.devices[pref("OWNER")].label = S("Hijacked"); }).r, "UNAUTHORIZED_WRITER", "PAIR_J relabels devices[p:<OWNER>]");
changeCase("pairing_writes_other_request", asJ("J1_two_requests", BASE, 1, (d) => {
  put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_J"));
  put(d.requests, pref("DEV_X"), reqEntry("DEV_X", "PAIR_J"));
}).r, "UNAUTHORIZED_WRITER", "PAIR_J creates two request entries in one change");
changeCase("pairing_wrong_pairing_field", asJ("J1_wrong_pairing", BASE, 1, (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "DEV_A")); }).r,
  "UNAUTHORIZED_WRITER", "PAIR_J creates requests[p:<DEV_B>] with pairing = p:<DEV_A>");
const foreign = change("K1_foreign_request", BASE, "PAIR_K", 1, "P2k_pairing_device_k", (d) => { put(d.requests, pref("DEV_X"), reqEntry("DEV_X", "PAIR_K")); });
changeCase("pairing_foreign_request.created", foreign.r, null, "PAIR_K (control_ref P2k) creates requests[p:<DEV_X>]: the foreign request of the next cases");
changeCase("pairing_edits_foreign_request_label", asJ("J1_edits_foreign_label", foreign.doc, 1, (d) => { d.requests[pref("DEV_X")].label = S("mine now"); }, "P2k_pairing_device_k").r,
  "UNAUTHORIZED_WRITER", "PAIR_J edits the label of PAIR_K's request");
changeCase("pairing_takes_over_foreign_request", asJ("J1_takes_over", foreign.doc, 1, (d) => {
  d.requests[pref("DEV_X")].pairing = S(pref("PAIR_J"));
  d.requests[pref("DEV_X")].label = S("taken");
}, "P2k_pairing_device_k").r, "UNAUTHORIZED_WRITER", "PAIR_J rewrites pairing and label of PAIR_K's request in one change");
changeCase("pairing_replaces_foreign_request_map", asJ("J1_replaces_map", foreign.doc, 1, (d) => { put(d.requests, pref("DEV_X"), reqEntry("DEV_X", "PAIR_J")); }, "P2k_pairing_device_k").r,
  "UNAUTHORIZED_WRITER", "PAIR_J replaces PAIR_K's request map with its own");
// Flow F08: PAIR_L's request in the Identity Resource rotated to epoch 1 (control_ref flow.pl_pairing_device_l).
{
  const asL = (name, doc, unitSeq, fn) => change(name, doc, "PAIR_L", unitSeq, "flow.pl_pairing_device_l", fn);
  const l1 = asL("L1_request", BASE, 1, (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_L")); });
  changeCase("pairing_l_writes_own_request", l1.r, null, "PAIR_L (control_ref flow.pl_pairing_device_l) creates requests[p:<DEV_B>] with pairing = p:<PAIR_L> (flow F08)");
  changeCase("pairing_l_second_installation", asL("L1_second_installation", BASE, 1, (d) => { put(d.requests, pref("DEV_X"), reqEntry("DEV_X", "PAIR_L")); }).r, null,
    "A second installation given the same link writes requests[p:<DEV_X>] as PAIR_L, also its unit 1: admitted by itself; the two units equivocate (W §26.2)");
  changeCase("pairing_l_reuse_seq2", asL("L2_reuse", l1.doc, 2, (d) => { put(d.requests, pref("DEV_X"), reqEntry("DEV_X", "PAIR_L")); }).r, null,
    "Sequential reuse: the second installation sees the first unit and writes its own request as PAIR_L unit 2");
}
const cont = asJ("J2_continues_own", own.doc, 2, (d) => { d.requests[pref("DEV_B")].platform = S("laptop"); });
changeCase("pairing_continues_own_request", cont.r, null, "PAIR_J writes platform into its own request (its second unit)");
{
  const k = change("K1_same_key", BASE, "PAIR_K", 1, "P2k_pairing_device_k", (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_K")); });
  check("pairing_concurrent_same_key.K", admit(k.r), null);
  check("pairing_concurrent_same_key.J", admit(own.r), null);
  const merged = replay(["C0_initial", "C1_fill", "J1_own_request", "K1_same_key"]).doc;
  const merged2 = replay(["C0_initial", "C1_fill", "K1_same_key", "J1_own_request"]).doc;
  const v = validateEntry(merged, "requests", pref("DEV_B"));
  check("pairing_concurrent_same_key", [v.valid, v.conflicted], [false, true]);
  check("pairing_concurrent_same_key.order", view(merged2), view(merged));
  scenario("pairing_concurrent_same_key", "PAIR_J and PAIR_K each create requests[p:<DEV_B>], neither having seen the other",
    ["IDENTITY-PROFILE-01 §3 AI4, §4 rule 2", "Each creation passes AI4; the merged entry holds two concurrent maps under one key: a conflicted request, invalid, never approved, neither map chosen."],
    { changes: [{ case: "change.J1_own_request" }, { case: "change.K1_same_key" }], history: [{ case: "change.C0_initial" }, { case: "change.C1_fill" }] },
    { admitted: ["J1_own_request", "K1_same_key"], entry: pref("DEV_B"), entry_conflicted: true, entry_valid: false, entry_diagnostic: "INVALID_FIELD_TYPE" },
    ["Both delivery orders give the same document and the same outcome."]);
}
{
  // The same change, received when the head is P3 (PAIR_J consumed): its class is taken at its control_ref, P2.
  const r = own.r;
  const ps = W.get("P3_consume_for_dev_b").expected.post_state;
  check("pairing_class_at_control_ref", [admit(r), writerClass("PAIR_J", r.controlRef), ps.devices.PAIR_J.active], [null, "pairing", false]);
  add({
    id: "pairing_class_at_control_ref", type: "validation", kind: "profile_change",
    description: "pairing_writes_own_request received after P3 (PAIR_J consumed): admitted, its class taken at control_ref P2",
    rule: { section: "IDENTITY-PROFILE-01 §2.3", text: "The class is taken at control_ref, never at the current head, so the decision does not change when the pairing device is later revoked." },
    inputs: { ...changeInputs(r), received_at_head: "P3_consume_for_dev_b" },
    context: { history: historyRefs(r).map((n) => ({ case: `change.${n}`, field: "automerge_change_hex", in: "inputs" })) },
    expected: { valid: true },
  });
}

// ---- state validation (§4) ----

function stateCase(id, doc, container, key, want, description, extra = {}) {
  const v = validateEntry(doc, container, key);
  // §4 rule 2: a conflicted entry reports the diagnostic of its first invalid value, else INVALID_FIELD_TYPE.
  const got = v.valid ? null : v.diagnostic ?? (v.conflicted ? "INVALID_FIELD_TYPE" : null);
  check(id, got, want);
  const conflictRule = "Rule 2: a field with concurrent values is valid only if every value is valid; for requests a conflicted field (an unknown one included) or two concurrent maps make the entry invalid; a kind conflict makes any entry invalid; the entry reports the diagnostic of its first invalid value, else INVALID_FIELD_TYPE.";
  return add({
    id, type: "validation", kind: "profile_entry", description,
    rule: { section: "IDENTITY-PROFILE-01 §4", text: v.conflicted ? conflictRule : "Validation is per entry; the first diagnostic in table order is reported." },
    inputs: { container, key, entry: view(values(doc[container], key).length > 1 ? doc[container] : doc[container][key]), snapshot: { b64url: b64u(A.save(doc)) }, ...extra },
    expected: want === null ? { valid: true } : { valid: false, error: { code: "PROFILE_INVALID", diagnostic: want, ...(v.conflicted ? { detail: "conflicted entry (§4 rule 2)" } : {}) } },
  });
}

const fp = (label) => {
  const d = sha(Buffer.from("LFCP-DEVICE-FP-v1"), principal(label).id).subarray(0, 10);
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0, value = 0, out = "";
  for (const byte of d) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out.match(/.{4}/g).join("-");
};

const docWith = (name, fn, writer = "OWNER") => change(name, BASE, writer, 3, "P0_genesis_i", fn).doc;
stateCase("request_valid", own.doc, "requests", pref("DEV_B"), null, "requests[p:<DEV_B>] with a matching descriptor, pairing = p:<PAIR_J>, kind 0", { fingerprint: fp("DEV_B") });
stateCase("request_service_valid", docWith("S_service_valid", (d) => { put(d.requests, pref("BRIDGE_O"), reqEntry("BRIDGE_O", "PAIR_J", { kind: 1, scope: [S(rref("X"))] })); }),
  "requests", pref("BRIDGE_O"), null, "A kind-1 request with scope [X]");
stateCase("request_service_without_scope", docWith("S_service_no_scope", (d) => { put(d.requests, pref("BRIDGE_O"), reqEntry("BRIDGE_O", "PAIR_J", { kind: 1 })); }),
  "requests", pref("BRIDGE_O"), "MISSING_REQUIRED_FIELD", "A kind-1 request without scope");
stateCase("request_personal_with_scope", docWith("S_personal_scope", (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_J", { scope: [S(rref("X"))] })); }),
  "requests", pref("DEV_B"), "INVALID_FIELD_TYPE", "A kind-0 request with scope");
stateCase("request_scope_64", docWith("S_scope_64", (d) => { put(d.requests, pref("BRIDGE_O"), reqEntry("BRIDGE_O", "PAIR_J", { kind: 1, scope: SCOPE_FILL.slice(0, 64).map(S) })); }),
  "requests", pref("BRIDGE_O"), null, "A kind-1 request with 64 Resources in scope");
stateCase("request_scope_65", docWith("S_scope_65", (d) => { put(d.requests, pref("BRIDGE_O"), reqEntry("BRIDGE_O", "PAIR_J", { kind: 1, scope: SCOPE_FILL.slice(0, 65).map(S) })); }),
  "requests", pref("BRIDGE_O"), "INVALID_FIELD_TYPE", "A kind-1 request with 65 Resources in scope");
stateCase("request_scope_repeat", docWith("S_scope_repeat", (d) => { put(d.requests, pref("BRIDGE_O"), reqEntry("BRIDGE_O", "PAIR_J", { kind: 1, scope: [S(rref("X")), S(rref("X"))] })); }),
  "requests", pref("BRIDGE_O"), "INVALID_FIELD_TYPE", "A kind-1 request whose scope repeats X");
stateCase("request_scope_empty", docWith("S_scope_empty", (d) => { put(d.requests, pref("BRIDGE_O"), reqEntry("BRIDGE_O", "PAIR_J", { kind: 1, scope: [] })); }),
  "requests", pref("BRIDGE_O"), "INVALID_FIELD_TYPE", "A kind-1 request with an empty scope");
stateCase("request_scope_bad_ref", docWith("S_scope_bad_ref", (d) => { put(d.requests, pref("BRIDGE_O"), reqEntry("BRIDGE_O", "PAIR_J", { kind: 1, scope: [S(rref("X").slice(0, 42))] })); }),
  "requests", pref("BRIDGE_O"), "INVALID_RESOURCE_REF", "A kind-1 request whose scope element has 42 characters");
stateCase("request_key_descriptor_mismatch", docWith("S_key_mismatch", (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_X", "PAIR_J")); }),
  "requests", pref("DEV_B"), "INVALID_DESCRIPTOR", "Key p:<DEV_B>, descriptor of DEV_X");
stateCase("request_bad_descriptor", docWith("S_bad_descriptor", (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_J", { descriptor: S(b64u(Buffer.from([0xa2, 0x00, 0x01, 0x01, 0x02]))) })); }),
  "requests", pref("DEV_B"), "INVALID_DESCRIPTOR", "A descriptor that is not the CBOR of a principal-descriptor");
stateCase("request_missing_label", docWith("S_missing_label", (d) => { const e = reqEntry("DEV_B", "PAIR_J"); delete e.label; put(d.requests, pref("DEV_B"), e); }),
  "requests", pref("DEV_B"), "MISSING_REQUIRED_FIELD", "A request without label");
stateCase("request_kind_2", docWith("S_kind_2", (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_J", { kind: 2 })); }),
  "requests", pref("DEV_B"), "INVALID_ENUM_VALUE", "A request with kind 2");
stateCase("request_bad_timestamp", docWith("S_bad_timestamp", (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_J", { requested_at: S("2026-11-03 10:00:00") })); }),
  "requests", pref("DEV_B"), "INVALID_TIMESTAMP", "requested_at '2026-11-03 10:00:00' (not RFC 3339 UTC)");
{
  // Concurrent values of one field: from a request PAIR_J wrote without kind, the root writes 1 and PAIR_J 0.
  const noKind = asJ("J1_request_without_kind", BASE, 1, (d) => { const e = reqEntry("DEV_B", "PAIR_J"); delete e.kind; put(d.requests, pref("DEV_B"), e); });
  const kindRoot = change("S_kind_root", noKind.doc, "OWNER", 3, "P2_pairing_device", (d) => { d.requests[pref("DEV_B")].kind = new A.Uint(1); });
  const kindJ = asJ("J2_kind_0", noKind.doc, 2, (d) => { d.requests[pref("DEV_B")].kind = new A.Uint(0); });
  for (const [suffix, order] of [["", ["kindRoot", "kindJ"]], [".reverse", ["kindJ", "kindRoot"]]]) {
    const parts = { kindRoot: kindRoot.r.bytes, kindJ: kindJ.r.bytes };
    const [m] = A.applyChanges(A.clone(noKind.doc), order.map((o) => parts[o]));
    stateCase(`request_conflicted_kind${suffix}`, m, "requests", pref("DEV_B"), "MISSING_REQUIRED_FIELD",
      `Concurrent kind values 1 (root) and 0 (PAIR_J), delivered ${order.join(" then ")}`, { changes: order.map((o) => (o === "kindRoot" ? "S_kind_root" : "J2_kind_0")).join(",") });
  }
  const noteJ = asJ("J2_note_unknown", own.doc, 2, (d) => { d.requests[pref("DEV_B")].note = S("from the laptop"); });
  const noteRoot = change("S_note_unknown_root", own.doc, "OWNER", 3, "P2_pairing_device", (d) => { d.requests[pref("DEV_B")].note = S("from the desktop"); });
  {
    const [m] = A.applyChanges(A.clone(own.doc), [noteJ.r.bytes, noteRoot.r.bytes]);
    stateCase("request_conflicted_unknown_field", m, "requests", pref("DEV_B"), "INVALID_FIELD_TYPE",
      "Concurrent values of the unknown field note of requests[p:<DEV_B>] (by PAIR_J and by the root)", { changes: "J2_note_unknown,S_note_unknown_root" });
  }
  const labelOk = asJ("J2_label_ok", own.doc, 2, (d) => { d.requests[pref("DEV_B")].label = S("Laptop"); });
  const labelBad = change("S_label_uint", own.doc, "OWNER", 3, "P2_pairing_device", (d) => { d.requests[pref("DEV_B")].label = new A.Uint(7); });
  for (const [suffix, order] of [["", [labelOk, labelBad]], [".reverse", [labelBad, labelOk]]]) {
    const [m] = A.applyChanges(A.clone(own.doc), order.map((o) => o.r.bytes));
    stateCase(`request_conflicted_valid_invalid${suffix}`, m, "requests", pref("DEV_B"), "INVALID_FIELD_TYPE",
      `Concurrent label values 'Laptop' and the uint 7, delivered ${order.map((o) => o.r.name).join(" then ")}`, { changes: order.map((o) => o.r.name).join(",") });
  }
  const merged = replay(["C0_initial", "C1_fill", "J1_own_request", "K1_same_key"]).doc;
  stateCase("request_conflicted_maps", merged, "requests", pref("DEV_B"), "INVALID_FIELD_TYPE", "Two concurrent maps under requests[p:<DEV_B>] (pairing_concurrent_same_key)");
}
stateCase("roster_bad_ref", docWith("S_roster_bad_ref", (d) => { d.roster[rref("X").slice(0, 42)] = ROSTER_X; }), "roster", rref("X").slice(0, 42), "INVALID_RESOURCE_REF", "A roster key of 42 characters");
{
  const n1 = change("S_name_root", BASE, "OWNER", 3, "P1_device_grant_dev_a_i", (d) => { d.roster[rref("X")].name = S("X (root)"); });
  const n2 = change("S_name_dev_a", BASE, "DEV_A", 1, "P1_device_grant_dev_a_i", (d) => { d.roster[rref("X")].name = S("X (laptop)"); });
  const [m] = A.applyChanges(A.clone(BASE), [n1.r.bytes, n2.r.bytes]);
  stateCase("roster_conflicted_name", m, "roster", rref("X"), null, "Concurrent names of roster[X] by OWNER and DEV_A: valid, a reader may show any value");
  const k1 = change("S_missing_keys_b", BASE, "OWNER", 3, "P4_register_dev_b_approved", (d) => { put(d.devices, pref("DEV_B"), { label: S("Phone"), kind: 0, missing_keys: { [rref("X")]: [0] } }); });
  const k2 = change("S_missing_keys_b2", k1.doc, "DEV_B", 1, "P4_register_dev_b_approved", (d) => { put(d.devices[pref("DEV_B")], "missing_keys", { [rref("X")]: [1], [rref("Y")]: [0] }); });
  const k3 = change("S_missing_keys_b3", k1.doc, "OWNER", 4, "P4_register_dev_b_approved", (d) => { put(d.devices[pref("DEV_B")], "missing_keys", { [rref("X")]: [0, 2] }); });
  const [mk] = A.applyChanges(A.clone(k1.doc), [k2.r.bytes, k3.r.bytes]);
  const vals = values(mk.devices[pref("DEV_B")], "missing_keys").map(view);
  const union = {};
  for (const v of vals) for (const [res, eps] of Object.entries(v)) union[res] = [...new Set([...(union[res] ?? []), ...eps])].sort((a, b) => a - b);
  check("device_entry_missing_keys_union", union, { [rref("X")]: [0, 1, 2], [rref("Y")]: [0] });
  check("device_entry_missing_keys_union.valid", validateEntry(mk, "devices", pref("DEV_B")).valid, true);
  scenario("device_entry_missing_keys_union", "Concurrent missing_keys maps of devices[p:<DEV_B>] (by DEV_B and by OWNER)",
    ["IDENTITY-PROFILE-01 §4 rule 2, §7.1", "missing_keys is read as the union of its concurrent values; it is a hint only."],
    { changes: [{ case: "change.S_missing_keys_b" }, { case: "change.S_missing_keys_b2" }, { case: "change.S_missing_keys_b3" }], snapshot: { b64url: b64u(A.save(mk)) } },
    { entry_valid: true, missing_keys_conflict_set: vals, missing_keys_read: union }, ["The reader seals the union of the listed epochs."]);
}

// ---- the missing_keys writer (§3 AI5, decision I8) ----
{
  const AT = "P4_register_dev_b_approved"; // OWNER root, DEV_A and DEV_B personal in I
  const B = pref("DEV_B");
  const X = rref("X");
  const ai5 = (id, r, want, description, rule = "AI5") => changeCase(id, r, want, description, { rule });
  const entry = change("M0_entry_dev_b", BASE, "OWNER", 3, AT, (d) => { put(d.devices, B, { label: S("Phone"), kind: 0 }); });
  ai5("missing_keys_entry_without_hint", entry.r, null, "OWNER creates devices[p:<DEV_B>] = {label, kind} without missing_keys: the base of the next cases");
  const own = change("M1_dev_b_writes_hint", entry.doc, "DEV_B", 1, AT, (d) => { put(d.devices[B], "missing_keys", { [X]: [1], [rref("Y")]: [0] }); });
  ai5("missing_keys_device_writes_own", own.r, null, "DEV_B writes its own hint devices[p:<DEV_B>].missing_keys = {X: [1], Y: [0]}");
  ai5("missing_keys_device_appends_own", change("M2_dev_b_appends_hint", own.doc, "DEV_B", 2, AT, (d) => { const l = d.devices[B].missing_keys[X]; put(l, l.length, 2); }).r, null,
    "DEV_B appends epoch 2 to its own missing_keys[X]");
  ai5("missing_keys_device_clears_own", change("M2_dev_b_clears_hint", own.doc, "DEV_B", 2, AT, (d) => { delete d.devices[B].missing_keys; }).r, null,
    "DEV_B deletes its own missing_keys once the packages arrived (§7.1 step 3)");
  ai5("missing_keys_root_writes_own_entry", change("M1_root_writes_own_hint", BASE, "OWNER", 3, AT, (d) => { put(d.devices[pref("OWNER")], "missing_keys", { [X]: [0] }); }).r, null,
    "OWNER writes missing_keys in its own entry devices[p:<OWNER>]: the root is the device of that entry");
  const rootForeign = change("M1_root_writes_dev_b_hint", entry.doc, "OWNER", 4, AT, (d) => { put(d.devices[B], "missing_keys", { [X]: [0, 2] }); });
  ai5("missing_keys_root_writes_device_hint", rootForeign.r, "UNAUTHORIZED_WRITER", "OWNER writes devices[p:<DEV_B>].missing_keys");
  ai5("missing_keys_root_creates_entry_with_hint", CHANGES.get("S_missing_keys_b"), "UNAUTHORIZED_WRITER",
    "OWNER creates devices[p:<DEV_B>] with missing_keys inside the new entry map (change S_missing_keys_b of device_entry_missing_keys_union)");
  ai5("missing_keys_root_clears_device_hint", change("M2_root_clears_dev_b_hint", own.doc, "OWNER", 4, AT, (d) => { delete d.devices[B].missing_keys; }).r, "UNAUTHORIZED_WRITER",
    "OWNER deletes the hint DEV_B wrote");
  ai5("missing_keys_root_appends_device_hint", change("M2_root_appends_dev_b_hint", own.doc, "OWNER", 4, AT, (d) => { const l = d.devices[B].missing_keys[X]; put(l, l.length, 3); }).r, "UNAUTHORIZED_WRITER",
    "OWNER appends epoch 3 to the list missing_keys[X] that DEV_B wrote");
  ai5("missing_keys_manager_writes_device_hint", change("M2_dev_a_writes_dev_b_hint", own.doc, "DEV_A", 1, AT, (d) => { put(d.devices[B].missing_keys, X, [0]); }).r, "UNAUTHORIZED_WRITER",
    "DEV_A (personal, Full) replaces missing_keys[X] in DEV_B's hint");
  ai5("missing_keys_root_relabels_and_writes_hint", change("M2_root_relabels_and_hints", entry.doc, "OWNER", 4, AT, (d) => {
    d.devices[B].label = S("Phone (A)");
    put(d.devices[B], "missing_keys", { [X]: [0] });
  }).r, "UNAUTHORIZED_WRITER", "OWNER relabels devices[p:<DEV_B>] and writes its missing_keys in one change: the whole change is refused");
  ai5("missing_keys_root_deletes_device_entry", change("M2_root_deletes_dev_b_entry", own.doc, "OWNER", 4, AT, (d) => { delete d.devices[B]; }).r, null,
    "OWNER deletes the entry devices[p:<DEV_B>] that holds DEV_B's hint: not a write of missing_keys");
  ai5("missing_keys_root_replaces_device_entry", change("M2_root_replaces_dev_b_entry", own.doc, "OWNER", 4, AT, (d) => { put(d.devices, B, { label: S("Phone"), kind: 0 }); }).r, null,
    "OWNER replaces the entry devices[p:<DEV_B>] with a new map without missing_keys: not a write of missing_keys");
  ai5("missing_keys_service_writes_own", change("M1_bridge_o_writes_own_hint", BASE, "BRIDGE_O", 1, "P4s_bind_bridge_o", (d) => {
    put(d.devices, pref("BRIDGE_O"), { label: S("Bridge"), kind: 1, missing_keys: { [X]: [0] } });
  }).r, "UNAUTHORIZED_WRITER", "BRIDGE_O (class other) creates its own devices entry with missing_keys: AI4 refuses it, and AI5 admits nothing AI4 refuses", "AI4");

  // Concurrent writes: DEV_B and OWNER write the hint, neither having seen the other; OWNER then writes on top of its own change.
  const after = change("M3_root_after_refused", rootForeign.doc, "OWNER", 5, AT, (d) => { d.devices[B].label = S("Phone (A)"); });
  const names = ["C0_initial", "C1_fill", "M0_entry_dev_b", "M1_dev_b_writes_hint", "M1_root_writes_dev_b_hint", "M3_root_after_refused"];
  const orders = { device_first: names, root_first: ["C0_initial", "C1_fill", "M0_entry_dev_b", "M1_root_writes_dev_b_hint", "M3_root_after_refused", "M1_dev_b_writes_hint"] };
  const want = { admitted: ["C0_initial", "C1_fill", "M0_entry_dev_b", "M1_dev_b_writes_hint"], refused: { M1_root_writes_dev_b_hint: "UNAUTHORIZED_WRITER" }, pending: ["M3_root_after_refused"] };
  const docs = [];
  for (const [k, order] of Object.entries(orders)) {
    const res = replay(order);
    check(`missing_keys_concurrent_device_and_root.${k}`, { admitted: names.filter((n) => res.admitted.includes(n)), refused: res.refused, pending: res.pending }, want);
    docs.push(res.doc);
  }
  check("missing_keys_concurrent_device_and_root.order", view(docs[1]), view(docs[0]));
  const m = docs[0];
  const vals = values(m.devices[B], "missing_keys").map(view);
  check("missing_keys_concurrent_device_and_root.state", [vals, validateEntry(m, "devices", B).valid], [[{ [X]: [1], [rref("Y")]: [0] }], true]);
  check("missing_keys_concurrent_device_and_root.after", admit(after.r), null);
  scenario("missing_keys_concurrent_device_and_root",
    "DEV_B and OWNER write devices[p:<DEV_B>].missing_keys concurrently, neither having seen the other; OWNER's next change depends on its own",
    ["IDENTITY-PROFILE-01 §3 AI5, SHARED-OBJECTS-PROFILE-01 §14.1", "Each change is decided by itself: the device's is admitted, the other writer's is PROFILE_INVALID (UNAUTHORIZED_WRITER), not merged, and blocks its dependants."],
    { changes: names.map((n) => ({ case: `change.${n}` })), orders },
    { ...want, refused: { M1_root_writes_dev_b_hint: { code: "PROFILE_INVALID", diagnostic: "UNAUTHORIZED_WRITER" } },
      state: { entry: B, entry_valid: true, missing_keys_conflict_set: vals, missing_keys_read: vals[0] } },
    ["Both delivery orders give the same document: missing_keys holds DEV_B's value only, with no concurrent value.",
     "M3_root_after_refused passes AI5 by itself (it writes only label) but waits forever: it depends on a refused change."]);
}
{
  const units = replay(["C0_initial", "C1_fill", "J1_own_request", "J2_continues_own"]).doc;
  const snap = A.load(A.save(units));
  const a = validateEntry(units, "requests", pref("DEV_B"));
  const b = validateEntry(snap, "requests", pref("DEV_B"));
  check("identity_snapshot_equivalence", [view(units), a], [view(snap), b]);
  scenario("identity_snapshot_equivalence", "The same document from its four units and from a Snapshot",
    ["IDENTITY-PROFILE-01 §2, SHARED-OBJECTS-PROFILE-01 §14", "A Snapshot is equivalent to the changes it holds: identical state and validation outcome."],
    { changes: ["C0_initial", "C1_fill", "J1_own_request", "J2_continues_own"].map((n) => ({ case: `change.${n}` })), snapshot: { b64url: b64u(A.save(units)) } },
    { state: view(units), root_valid: true, entries: { requests: { [pref("DEV_B")]: a.valid ? "valid" : a.diagnostic } } },
    ["From the units and from the Snapshot (after the root's unit 1 is verified) the state and every entry's validity are identical."]);
}

// ---- links, fingerprints, digests (§5.2, W §7.3) ----

const RFC3986 = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
const J = principal("PAIR_J").c;
const secretCbor = Buffer.concat([Buffer.from([0xa3, 0x00, 0x01, 0x01]), bstr(Buffer.from(J.inputs.ed25519_seed.hex, "hex")), Buffer.from([0x02]), bstr(Buffer.from(J.inputs.x25519_private.hex, "hex"))]);
const pairUri = (device = principal("PAIR_J").id) =>
  `lfcp://pair/${b64u(I)}?endpoint=${RFC3986(wire.fixtures.endpoint.url)}&device=${b64u(device)}#secret=${b64u(secretCbor)}`;
add({
  id: "pair_uri_roundtrip", type: "bytes", kind: "pair_uri", description: "The pairing link of PAIR_J for I",
  rule: { section: "IDENTITY-PROFILE-01 §5.2; LFCP-WIRE-01 §18.2", text: "lfcp://pair/<identity-resource-b64url>?endpoint=<escaped-wss-url>&device=<pairing-device-id-b64url>#secret=<secret-b64url>; the secret is the W §18.2 invite-secret structure." },
  inputs: { identity_resource: { hex: hex(I) }, endpoint: wire.fixtures.endpoint.url, device: "PAIR_J", pairing_device_id: { hex: hex(principal("PAIR_J").id) },
            ed25519_seed: J.inputs.ed25519_seed, x25519_private: J.inputs.x25519_private },
  expected: { secret_cbor: { hex: hex(secretCbor) }, uri: pairUri(), recomputed_principal_id: { hex: J.expected.principal_id.hex } },
});
{
  // The link of flow F08: PAIR_L, registered in I on the head flow.pl_pairing_device_l.
  const L = principal("PAIR_L").c;
  const sec = Buffer.concat([Buffer.from([0xa3, 0x00, 0x01, 0x01]), bstr(Buffer.from(L.inputs.ed25519_seed.hex, "hex")), Buffer.from([0x02]), bstr(Buffer.from(L.inputs.x25519_private.hex, "hex"))]);
  const uri = `lfcp://pair/${b64u(I)}?endpoint=${RFC3986(wire.fixtures.endpoint.url)}&device=${b64u(principal("PAIR_L").id)}#secret=${b64u(sec)}`;
  const binding = W.get("flow.pl_pairing_device_l").expected.post_state.devices.PAIR_L;
  check("pair_uri_pair_l.binding", [binding.kind, binding.active, binding.registered], [2, true, true]);
  add({
    id: "pair_uri_pair_l", type: "bytes", kind: "pair_uri", description: "The pairing link of PAIR_L for I (flow F08), registered and active at flow.pl_pairing_device_l",
    rule: { section: "IDENTITY-PROFILE-01 §5.2; LFCP-WIRE-01 §18.2", text: "The link names the pairing device whose binding the receiver verifies before using the secret." },
    inputs: { identity_resource: { hex: hex(I) }, endpoint: wire.fixtures.endpoint.url, device: "PAIR_L", pairing_device_id: { hex: hex(principal("PAIR_L").id) },
              ed25519_seed: L.inputs.ed25519_seed, x25519_private: L.inputs.x25519_private, binding_head: "flow.pl_pairing_device_l" },
    expected: { secret_cbor: { hex: hex(sec) }, uri, recomputed_principal_id: { hex: L.expected.principal_id.hex } },
  });
}
const joinUri = legacy.cases.find((c) => c.id === "invite_uri").expected.uri;
function parsePair(uri) {
  const m = /^lfcp:\/\/pair\/([A-Za-z0-9_-]{43})\?([^#]*)#secret=([A-Za-z0-9_-]+)$/.exec(uri);
  if (!m) return "not a pairing link";
  const params = new URLSearchParams(m[2]);
  const device = params.get("device");
  // The secret's Principal must be `device`.
  return device === b64u(principal("PAIR_J").id) && m[3] === b64u(secretCbor) ? null : "the secret's Principal is not device";
}
const parseJoin = (uri) => (uri.startsWith("lfcp://join/") ? null : "not an invitation link");
const linkCase = (id, uri, parser, description, rule) => {
  const err = parser === "pair" ? parsePair(uri) : parseJoin(uri);
  check(id, err !== null, true);
  add({ id, type: "validation", kind: "pair_uri", description, rule: { section: rule[0], text: rule[1] }, inputs: { uri, parser }, expected: { valid: false, error: { code: "PAIRING_LINK_REJECTED", detail: err } } });
};
linkCase("pair_uri_rejected_by_join_parser", pairUri(), "join", "An invitation parser receives the pairing link", ["IDENTITY-PROFILE-01 §5.2", "A receiver of invitation URIs that does not implement pairing rejects the link as not starting with lfcp://join/."]);
linkCase("join_uri_rejected_by_pair_parser", joinUri, "pair", "A pairing parser receives the invite_uri of LFCP-TEST-VECTORS-01", ["IDENTITY-PROFILE-01 §5.2", "A pairing parser rejects a lfcp://join/ link."]);
linkCase("pair_uri_device_mismatch", pairUri(principal("DEV_B").id), "pair", "A pairing link whose device parameter is DEV_B while the secret is PAIR_J's", ["IDENTITY-PROFILE-01 §5.2", "The receiving client recomputes J's descriptor from the secret and verifies that its ID equals device before using the secret."]);
add({
  id: "fingerprint_dev_b", type: "bytes", kind: "device_fingerprint", description: "The device fingerprint of DEV_B",
  rule: { section: "IDENTITY-PROFILE-01 §5.2", text: "fp = base32-lower-nopad(SHA-256(ASCII('LFCP-DEVICE-FP-v1') || principal_id)[0..10]) in four groups of four characters." },
  inputs: { principal_id: { hex: hex(principal("DEV_B").id) } },
  expected: { digest_prefix: { hex: hex(sha(Buffer.from("LFCP-DEVICE-FP-v1"), principal("DEV_B").id).subarray(0, 10)) }, fingerprint: fp("DEV_B") },
});
{
  const certB = wire.fixtures.certificates.CERT_B;
  const p3 = W.get("P3_consume_for_dev_b").expected.post_state.revoked["OWNER/PAIR_J"].approval.hex;
  check("approval_digest_cert_b", certB.payload_digest.hex, p3);
  add({
    id: "approval_digest_cert_b", type: "bytes", kind: "approval_digest", description: "The certificate payload digest of CERT_B, equal to P3's field 4",
    rule: { section: "LFCP-WIRE-01 §7.3 rule 6, §17.5", text: "The certificate payload digest is SHA-256 of the exact COSE payload; it is what a pairing approval commits to." },
    inputs: { certificate: "CERT_B", cose_sign1: certB.cose_sign1 },
    expected: { payload_digest: certB.payload_digest, consuming_record: "P3_consume_for_dev_b", consuming_record_id: { hex: recordId("P3_consume_for_dev_b") } },
  });
}
{
  const heads = { I2: "I2_device_grant_self_dev_b", I9: "I9_device_revoke_dev_a", I11: "I11_revoke_root_grant_bob", I13: "I13_owner_expels_dev_c" };
  scenario("root_of_corpus", "rootOf, actsFor, bound and active of every fixture Principal in X at I2, I9, I11 and I13",
    ["LFCP-WIRE-01 §80.1; IDENTITY-PROFILE-01 §10", "rootOf(P) is the root of a bound Principal, revoked or intermediate included, else P; actsFor(P) is the root of an active device, else P."],
    { resource: "X", heads, chain: "LFCP-IDENTITY-TEST-VECTORS-01 J0_genesis … I13_owner_expels_dev_c" },
    Object.fromEntries(Object.entries(heads).map(([k, v]) => [k, W.get(v).expected.post_state.queries])),
    ["The tables equal the queries of the corresponding cases of LFCP-IDENTITY-TEST-VECTORS-01."]);
  const q = W.get("I13_owner_expels_dev_c").expected.post_state.queries;
  const assignees = [pref("DEV_B"), pref("OWNER"), pref("BOB")];
  const display = [...new Set(assignees.map((p) => { const label = ["DEV_B", "OWNER", "BOB"].find((l) => pref(l) === p); return q[label].rootOf; }))];
  check("assignee_root_ref", display, ["OWNER", "BOB"]);
  scenario("assignee_root_ref", "A task in X with assignees p:<DEV_B>, p:<OWNER> and p:<BOB>, displayed at I13",
    ["IDENTITY-PROFILE-01 §10", "A reader treats p:<D> and p:<R> with rootOf(D) = R as the same human for display and filtering; the CRDT set is unchanged."],
    { resource: "X", head: "I13_owner_expels_dev_c", assignees },
    { crdt_set: assignees, display_humans: display, merged: { OWNER: [pref("DEV_B"), pref("OWNER")] } },
    ["Two keys for one human are two members of the set and are merged in display only."]);
}

// ---------------------------------------------------------------------------
// Output.
// ---------------------------------------------------------------------------

/** Remove the one dependency of a change and fix its length and checksum (a crafted negative). */
function dropDeps(bytes) {
  const b = Buffer.from(bytes);
  // Chunk: magic(4) checksum(4) type(1) length(uleb) body.
  let i = 9;
  let len = 0, shift = 0, start = i;
  for (;;) { const x = b[i++]; len |= (x & 0x7f) << shift; shift += 7; if (!(x & 0x80)) break; }
  const body = b.subarray(i, i + len);
  if (body[0] !== 1) throw new Error("expected one dependency");
  const newBody = Buffer.concat([Buffer.from([0]), body.subarray(33)]);
  const lenBytes = [];
  let n = newBody.length;
  do { let x = n & 0x7f; n >>>= 7; if (n) x |= 0x80; lenBytes.push(x); } while (n);
  const typeAndLen = Buffer.concat([Buffer.from([b[8]]), Buffer.from(lenBytes)]);
  const checksum = sha(typeAndLen, newBody).subarray(0, 4);
  const out = Buffer.concat([b.subarray(0, 4), checksum, typeAndLen, newBody]);
  const d = A.decodeChange(out);
  if (d.deps.length !== 0 || d.seq !== 2) throw new Error("crafted change did not decode as intended");
  void start;
  return out;
}

changeRecords();
const order = (c) => (c.id.startsWith("change.") ? 1 : 0);
CASES.sort((a, b) => order(a) - order(b));

const doc = {
  format: "lfcp-vector-format/1",
  suite: {
    id: SUITE_ID, version: "01",
    specification: { id: "IDENTITY-PROFILE-01", profile: PROFILE, revision: "working-draft" },
    description: "Identity Resource profile vectors (IDENTITY-PROFILE-01 §12.2 ID-05): the initial change, admission AI0 to AI5, per-entry state validation, pairing links, device fingerprints, the approval digest, rootOf tables and assignee display.",
    depends_on: ["IDENTITY-PROFILE-01", "SHARED-OBJECTS-PROFILE-01", "LFCP-WIRE-01", "LFCP-IDENTITY-TEST-VECTORS-01"],
    conventions: {
      engine_package: "@automerge/automerge", engine_version: "3.5.0",
      changes: "Every change is made with time 0 and no message by the SHARED-OBJECTS-PROFILE-01 §8 actor of its writer in the Identity Resource I; the change.* cases give their exact bytes and framing; validation cases reference their causal history by case.",
      writer_class: "inputs.writer_class is the class of §2.3 at inputs.control_ref, from the Control state of I in LFCP-IDENTITY-TEST-VECTORS-01.",
      diagnostics: "A refused change or an invalid entry is PROFILE_INVALID with the profile diagnostic; a conflicted entry (§4 rule 2) reports the diagnostic of its first invalid value, else INVALID_FIELD_TYPE.",
      links: "Pairing-link rejections are client-local (W §62): error.code PAIRING_LINK_REJECTED is a test convention, not a wire code.",
    },
    warning: "All private keys in this suite are public test fixtures. They MUST NOT be used in production.",
  },
  fixtures: {
    identity_resource: { hex: hex(I) }, owner: "OWNER", owner_ref: pref("OWNER"),
    actors: Object.fromEntries(["OWNER", "DEV_A", "DEV_B", "PAIR_J", "PAIR_K"].map((l) => [l, actorOf(l)])),
    refs: Object.fromEntries(["OWNER", "BOB", "DEV_A", "DEV_B", "DEV_X", "PAIR_J", "PAIR_K", "PAIR_L", "BRIDGE_O"].map((l) => [l, pref(l)])),
    resource_refs: { X: rref("X"), Y: rref("Y"), I: rref("I") },
  },
  cases: CASES,
};
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, `${SUITE_ID}.json`), JSON.stringify(doc, null, 2) + "\n");

const md = [`# ${SUITE_ID}`, "",
  "Generated by `generate_identity_profile_vectors_01.mjs` with the pinned `@automerge/automerge` 3.5.0; do not edit by hand.",
  `Machine-readable values are in \`${SUITE_ID}.json\` (\`lfcp-vector-format/1\`). Rules: IDENTITY-PROFILE-01 §§2–5, §10; vector list: §12.2 ID-05.`, "",
  "| Case | Type | Expected | Rule | Description |", "|---|---|---|---|---|"];
for (const c of CASES) {
  if (c.id.startsWith("change.")) continue;
  const e = c.type === "validation" ? (c.expected.valid ? "valid" : `\`${c.expected.error.diagnostic ?? c.expected.error.code}\``) : c.type === "bytes" ? "exact bytes" : "state";
  md.push(`| \`${c.id}\` | ${c.type} | ${e} | ${c.rule?.section ?? ""} | ${c.description} |`);
}
md.push("", "## Changes", "", "| Change | Writer | Unit seq | control_ref | Hash |", "|---|---|---|---|---|");
for (const r of CHANGES.values()) md.push(`| \`${r.name}\` | ${r.writer} | ${r.unitSeq} | ${r.controlRef} | \`${r.hash.slice(0, 16)}…\` |`);
md.push("", `Fingerprint of DEV_B: \`${fp("DEV_B")}\`.`, "", `Pairing link of PAIR_J: \`${pairUri()}\``, "");
writeFileSync(join(OUT, `${SUITE_ID}.md`), md.join("\n"));
console.log(join(OUT, `${SUITE_ID}.json`));
console.log(`${CASES.length} cases`);
