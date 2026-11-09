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
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
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

// Ed25519 point decoding (RFC 8032 §5.1.3) and the small-order test, as W §7 and §10.5.1 require of a descriptor's
// key; the same arithmetic as ed_decode and ed_small_order of ../lfcp-wire-01/generate_lfcp_test_vectors_01.py.
const ED_P = 2n ** 255n - 19n;
const modp = (a) => ((a % ED_P) + ED_P) % ED_P;
const powp = (b, e) => {
  let r = 1n;
  for (b = modp(b); e > 0n; e >>= 1n, b = (b * b) % ED_P) if (e & 1n) r = (r * b) % ED_P;
  return r;
};
const ED_D = modp(-121665n * powp(121666n, ED_P - 2n));
const ED_SQRT_M1 = powp(2n, (ED_P - 1n) / 4n);
function edDecode(bytes) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= ED_P) return null; // non-canonical y
  const u = modp(y * y - 1n), v = modp(ED_D * y * y + 1n);
  let x = modp(u * powp(v, 3n) * powp(u * powp(v, 7n), (ED_P - 5n) / 8n));
  if (modp(v * x * x) !== u) x = modp(x * ED_SQRT_M1);
  if (modp(v * x * x) !== u) return null; // not a curve point
  if (x === 0n && sign === 1n) return null; // x = 0 with the sign bit set
  if ((x & 1n) !== sign) x = ED_P - x;
  return [x, y];
}
function edAdd([x1, y1], [x2, y2]) {
  const t = modp(ED_D * x1 * x2 * y1 * y2);
  return [modp((x1 * y2 + y1 * x2) * powp(1n + t, ED_P - 2n)), modp((y1 * y2 + x1 * x2) * powp(1n - t, ED_P - 2n))];
}
const edSmallOrder = (pt) => {
  let q = pt;
  for (let k = 0; k < 3; k++) q = edAdd(q, q); // 8 * pt
  return q[0] === 0n && q[1] === 1n;
};
/** W §7 and §10.5.1: a canonical encoding of a curve point that is not of small order. */
const validEd25519Key = (bytes) => {
  const pt = edDecode(bytes);
  return pt !== null && !edSmallOrder(pt);
};

/** Decodes a principal-descriptor (W §7): a closed map {0, 1, 2} of 32-byte strings, its ID recomputed, its Ed25519 key valid; null if not one. */
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
  if (!validEd25519Key(out[1])) return null;
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
/**
 * Whether `parent[key]` is an Automerge map object. A list is a JS array and typeof "object" too, and a timestamp or
 * counter scalar is an object without keys: the object's own ID tells a map apart (§2.1, §2.2, §4).
 */
const isMapAt = (parent, key) => {
  const v = parent?.[key];
  if (!v || typeof v !== "object" || Array.isArray(v) || A.isImmutableString(v)) return false;
  const id = A.getObjectId(parent, key);
  return typeof id === "string" && /^\d+@[0-9a-f]+$/.test(id);
};

/** AI0's content rule: exactly the six root keys, profile and identity.root set, four empty containers. */
function initialContent(doc, rootLabel) {
  const keys = Object.keys(doc).sort();
  if (JSON.stringify(keys) !== JSON.stringify(["devices", "extensions", "identity", "profile", "requests", "roster"])) return false;
  if (!A.isImmutableString(doc.profile) || str(doc.profile) !== PROFILE) return false;
  if (!isMapAt(doc, "identity") || JSON.stringify(Object.keys(doc.identity)) !== '["root"]' || !A.isImmutableString(doc.identity.root)) return false;
  if (str(doc.identity.root) !== pref(rootLabel)) return false;
  return CONTAINERS.every((k) => isMapAt(doc, k) && Object.keys(doc[k]).length === 0);
}

// AI3 (§3, decision I27): the positions §2.1 defines and the values they admit. An object's position is the path of
// the operation that created it: map keys, and LIST for an element of a list.
const LIST = Symbol("list element");
const ENTRY_FIELDS = {
  roster: new Set(["profile", "endpoints", "coordinator", "name", "archived"]),
  devices: new Set(["label", "kind", "platform", "added_at", "revoked", "missing_keys"]),
  requests: new Set(["descriptor", "pairing", "label", "kind", "scope", "platform", "requested_at"]),
};
function indexPosition(positions, op, id) {
  if (!op.action.startsWith("make")) return;
  const parent = op.obj === "_root" ? [] : positions.get(op.obj)?.path;
  if (parent === undefined) throw new Error(`object ${op.obj} is not in the causal history`);
  positions.set(id, { path: [...parent, op.elemId !== undefined ? LIST : op.key], type: op.action });
}
/** "entry", "field", "hint" or "element" for a position §2.1 defines, else null (decision I27). */
function ai3Position(op, positions) {
  const parent = op.obj === "_root" ? { path: [], type: "makeMap" } : positions.get(op.obj);
  const inList = parent.type === "makeList";
  const p = [...parent.path, inList ? LIST : op.key];
  const [top, , field, hintKey] = p;
  if (!Object.hasOwn(ENTRY_FIELDS, top)) return null;
  if (p.length === 2) return "entry";
  if (p.length === 3 && !inList && ENTRY_FIELDS[top].has(field)) return "field";
  if (p.length === 4 && !inList && top === "devices" && field === "missing_keys") return "hint";
  if (inList && p.length === 4 && ((top === "roster" && field === "endpoints") || (top === "requests" && field === "scope"))) return "element";
  if (inList && p.length === 5 && top === "devices" && field === "missing_keys" && hintKey !== LIST) return "element";
  return null;
}
/** A scalar of §2.1: an ImmutableString, a boolean or a uint. */
const ai3Scalar = (op) =>
  op.action === "set" &&
  ((op.datatype === undefined && (typeof op.value === "string" || typeof op.value === "boolean")) || op.datatype === "uint");

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
  const history = A.getAllChanges(prev).map((b) => A.decodeChange(b));
  const latest = history.filter((d) => d.actor === r.actor).length;
  if (r.seq !== latest + 1) return "INVALID_AUTOMERGE_BYTES";
  const [next] = A.applyChanges(A.clone(prev), [r.bytes]);
  const found = new Set();
  const ops = r.decoded.ops;
  const idOf = (i) => `${r.decoded.startOp + i}@${r.actor}`;
  const identityOid = oid(prev, "identity");
  // AI2 (§3): the root containers are never written after the initial change, and a scalar replaces an object only
  // when its operation names that object as a predecessor (SOP §11.4 R6). Objects are indexed from the whole causal
  // history, hidden and deleted ones included, and from the earlier operations of this change.
  const madeObjects = new Set();
  const entryMaps = new Set();
  const entryContainers = ["roster", "devices", "requests"].map((k) => oid(prev, k));
  const index = (op, id) => {
    if (!op.action.startsWith("make")) return;
    madeObjects.add(id);
    if (op.action === "makeMap" && entryContainers.includes(op.obj)) entryMaps.add(id);
  };
  for (const d of history) d.ops.forEach((op, i) => index(op, `${d.startOp + i}@${d.actor}`));
  // AI3 positions: every object of the causal history, hidden and deleted ones included, by the path of its creation.
  const positions = new Map();
  for (const d of history) d.ops.forEach((op, i) => indexPosition(positions, op, `${d.startOp + i}@${d.actor}`));
  // Objects of entries (and the lists inside them) in the history: object id -> [container, key]. Only an entry map
  // has fields: a list, a scalar or a Text at an entry key is not one, and the engine cannot be asked for its fields.
  const entryOf = new Map();
  for (const k of ["roster", "devices", "requests"]) {
    for (const [key, entry] of Object.entries(prev[k] ?? {})) {
      const eid = oid(prev[k], key);
      if (eid) entryOf.set(eid, [k, key]);
      if (!entryMaps.has(eid)) continue;
      for (const [f, v] of Object.entries(entry)) {
        const lid = oid(entry, f);
        if (lid && v && typeof v === "object" && !A.isImmutableString(v)) entryOf.set(lid, [k, key, f]);
      }
    }
  }
  const replacesObject = (op) => op.action === "set" && (op.pred ?? []).some((p) => madeObjects.has(p));
  // AI2 protects two levels, never deeper: an entry map, and a list or map held in a field of an entry map. An entry
  // key that holds a list holds no entry map, so a scalar over that list replaces nothing AI2 protects.
  const replacesEntryMap = (op) => op.action === "set" && (op.pred ?? []).some((p) => entryMaps.has(p));
  // The extensions container itself is protected by the first test; a namespace value under it is not an entry map
  // (§2.1, SOP §18), so writing a scalar over a map held there replaces nothing AI2 protects.
  ops.forEach((op, i) => {
    if (op.obj === "_root" && CONTAINERS.includes(op.key)) found.add("CONTAINER_REPLACED");
    if (entryContainers.includes(op.obj) && replacesEntryMap(op)) found.add("CONTAINER_REPLACED");
    if (entryMaps.has(op.obj) && replacesObject(op)) found.add("CONTAINER_REPLACED");
    if ((op.obj === "_root" && (op.key === "profile" || op.key === "identity")) || (identityOid && op.obj === identityOid)) found.add("IMMUTABLE_FIELD_MUTATED");
    if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
    // AI3 (decision I27): at a position §2.1 defines, a scalar of §2.1; at an entry, a named field or a hint entry
    // also a map or a list. Other positions are not checked; §4 judges a field that holds the wrong kind of value.
    const at = ai3Position(op, positions);
    if (at !== null && op.action !== "del" && !(ai3Scalar(op) || (at !== "element" && (op.action === "makeMap" || op.action === "makeList"))))
      found.add("INVALID_FIELD_TYPE");
    index(op, idOf(i));
    indexPosition(positions, op, idOf(i));
  });
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
    const entryKey = new Map(); // every map ever created at devices[k] in this causal history -> k
    const made = new Map(); // object id -> creation operation, including hidden and deleted objects
    const remember = (op, id) => {
      if (!op.action.startsWith("make")) return;
      made.set(id, op);
      if (op.obj === devicesOid && op.action === "makeMap") entryKey.set(id, op.key);
    };
    // Do not traverse the engine's visible document: it omits conflicting values and their descendants.
    for (const d of history) d.ops.forEach((op, i) => remember(op, `${d.startOp + i}@${d.actor}`));
    const hintKey = (obj) => {
      for (let creation = made.get(obj); creation; creation = made.get(creation.obj)) {
        if (creation.key === "missing_keys" && entryKey.has(creation.obj)) return entryKey.get(creation.obj);
      }
      return undefined;
    };
    let foreign = false;
    ops.forEach((op, i) => {
      const key = entryKey.has(op.obj) && op.key === "missing_keys" ? entryKey.get(op.obj) : hintKey(op.obj);
      if (key !== undefined && key !== mine) foreign = true;
      // Entry deletion/replacement is not a hint write; new objects retain their creation ancestry.
      remember(op, idOf(i));
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
  for (const k of CONTAINERS) if (!isMapAt(doc, k)) return "INVALID_ROOT";
  if (!isMapAt(doc, "identity") || !isStr(doc.identity.root) || str(doc.identity.root) !== pref(owner)) return "INVALID_ROOT";
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
    if (field("platform") !== undefined && !isStr(field("platform"))) found.add("INVALID_FIELD_TYPE");
    if (field("revoked") !== undefined && typeof field("revoked") !== "boolean") found.add("INVALID_FIELD_TYPE");
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
    for (const f of ["descriptor", "pairing", "label", "platform"]) if (field(f) !== undefined && !isStr(field(f))) found.add("INVALID_FIELD_TYPE");
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
  AI2_HISTORY: ["IDENTITY-PROFILE-01 §3 AI2", "A change does not write a scalar over an entry map, or over a list or map field of one, whether or not the engine selects that value; the replaced objects are the operation's predecessors (SOP §11.4 R6)."],
  AI2_DEPTH: ["IDENTITY-PROFILE-01 §3 AI2", "AI2 protects an entry map of roster, devices or requests and a list or map held in a field of one, and nothing deeper: a scalar over a deeper list or map, or over a list held directly at an entry key, is admitted by AI2 and judged by §4."],
  AI2_EXT: ["IDENTITY-PROFILE-01 §3 AI2, §2.1; SHARED-OBJECTS-PROFILE-01 §18", "AI2 protects the extensions container, not a namespace value under it: a namespace value is not an entry map, and replacing it, a map by a scalar included, is admitted."],
  RESERVED: ["IDENTITY-PROFILE-01 §2.4", "Admission has no rule for the reserved root keys: a later change that writes them is admitted when §3 otherwise admits it; the value is preserved uninterpreted."],
  AI3_POS: ["IDENTITY-PROFILE-01 §3 AI3", "AI3 checks only the positions §2.1 defines: an entry of roster, devices or requests, a named field of an entry map, a key of a map held in devices[k].missing_keys, and an element of a list held in roster[k].endpoints, requests[k].scope or devices[k].missing_keys[X]. An element admits an ImmutableString, a boolean or a uint; the other positions also admit a map or a list. A value of extensions[ns], an unknown field and everything below a map or list held where §2.1 defines a scalar or a list are not checked; §4 judges the field. Collaborative Text is refused everywhere."],
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
// AI0 and §4: each of the four containers is an empty map, never an empty list (an Automerge list is a JS object too).
for (const k of CONTAINERS) {
  const lst = change(`C0l_initial_${k}_list`, A.init({ actor: actorOf("OWNER") }), "OWNER", 1, "P0_genesis_i", (d) => {
    d.profile = S(PROFILE);
    d.identity = { root: S(pref("OWNER")) };
    for (const c of CONTAINERS) d[c] = c === k ? [] : {};
  });
  changeCase(`identity_doc_initial_${k}_list`, lst.r, "INVALID_ROOT", `An initial change that creates ${k} as an empty list instead of an empty map`);
  const loaded = A.load(A.save(lst.doc));
  check(`identity_doc_initial_${k}_list.snapshot`, [rootDiagnostic(lst.doc), rootDiagnostic(loaded)], ["INVALID_ROOT", "INVALID_ROOT"]);
  scenario(`identity_doc_initial_${k}_list.snapshot`, `The state of identity_doc_initial_${k}_list loaded from a Snapshot: ${k} is a list`,
    ["IDENTITY-PROFILE-01 §4", "INVALID_ROOT: a root container is missing or not a map; the document is unusable."],
    { change: { case: `change.C0l_initial_${k}_list` }, snapshot: { b64url: b64u(A.save(lst.doc)) } },
    { root_diagnostic: "INVALID_ROOT", document_usable: false },
    [`The Snapshot's ${k} is an Automerge list: the root is INVALID_ROOT whether the state comes from the change or from the Snapshot.`]);
}

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
  const extReplaced = change("C2_extensions_replaced", BASE, "OWNER", 3, "P0_genesis_i", (d) => { d.extensions = {}; });
  changeCase("identity_doc_extensions_container_replaced", extReplaced.r, "CONTAINER_REPLACED", "A change by the root replacing the extensions container with a new map");
  const extMap = change("C2_extension_namespace_map", BASE, "OWNER", 3, "P0_genesis_i", (d) => { d.extensions["org.example.review"] = { a: S("a") }; });
  changeCase("identity_doc_extension_namespace_written", extMap.r, null, "The root writes extensions[\"org.example.review\"] = {a: \"a\"}", { rule: "AI2_EXT" });
  const extScalar = change("C3_extension_namespace_map_to_scalar", extMap.doc, "OWNER", 4, "P0_genesis_i", (d) => { d.extensions["org.example.review"] = S("done"); });
  if (!extScalar.r.decoded.ops.some((op) => op.action === "set" && (op.pred ?? []).length === 1)) throw new Error("the scalar does not name the map as its predecessor");
  changeCase("identity_doc_extension_namespace_map_to_scalar", extScalar.r, null,
    "Then the root replaces the value of extensions[\"org.example.review\"], a map, with the scalar \"done\": admitted (a namespace value is not an entry map)", { rule: "AI2_EXT" });
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
{
  // W §7: the descriptor's Ed25519 key is a canonical encoding of a point not of small order. Each crafted descriptor
  // has a correct ID for its keys and is stored under that ID, so only the key check can refuse it.
  const xOf = (label) => principal(label).descriptor.subarray(74, 106);
  const edOf = (label) => principal(label).descriptor.subarray(39, 71);
  const craft = (ed, x) => {
    const id = sha(Buffer.from("LFCP-PRINCIPAL-v1"), ed, x);
    return { id, cbor: Buffer.concat([Buffer.from([0xa3, 0x00, 0x58, 0x20]), id, Buffer.from([0x01, 0x58, 0x20]), ed, Buffer.from([0x02, 0x58, 0x20]), x]) };
  };
  const control = craft(edOf("DEV_B"), xOf("DEV_B"));
  check("request_descriptor_crafted.control", hex(control.cbor), hex(principal("DEV_B").descriptor));
  const keys = {
    small_order_identity: ["0100000000000000000000000000000000000000000000000000000000000000", "the identity point (order 1)"],
    small_order_8: ["c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "a point of order 8"],
    noncanonical_y: ["eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "y = p + 1, a non-canonical encoding of y = 1"],
    noncanonical_sign: ["0100000000000000000000000000000000000000000000000000000000000080", "y = 1 with the sign bit set (x = 0)"],
    not_on_curve: ["0200000000000000000000000000000000000000000000000000000000000000", "y = 2, which is not the y of a curve point"],
  };
  const decoded = Object.fromEntries(Object.entries(keys).map(([k, [h]]) => {
    const pt = edDecode(Buffer.from(h, "hex"));
    return [k, pt === null ? "undecodable" : edSmallOrder(pt) ? "small order" : "valid"];
  }));
  check("request_descriptor_keys", decoded, { small_order_identity: "small order", small_order_8: "small order", noncanonical_y: "undecodable", noncanonical_sign: "undecodable", not_on_curve: "undecodable" });
  check("request_descriptor_keys.control", validEd25519Key(edOf("DEV_B")), true);
  for (const [k, [h, what]] of Object.entries(keys)) {
    const c = craft(Buffer.from(h, "hex"), xOf("DEV_B"));
    const key = "p:" + b64u(c.id);
    stateCase(`request_descriptor_${k}`, docWith(`S_descriptor_${k}`, (d) => { put(d.requests, key, reqEntry("DEV_B", "PAIR_J", { descriptor: S(b64u(c.cbor)) })); }),
      "requests", key, "INVALID_DESCRIPTOR", `A descriptor whose Ed25519 key is ${what}; its ID is recomputed from its keys and is the entry's key`,
      { ed25519_key: { hex: h }, descriptor_id: { hex: hex(c.id) } });
  }
  stateCase("request_descriptor_crafted.control", docWith("S_descriptor_control", (d) => { put(d.requests, "p:" + b64u(control.id), reqEntry("DEV_B", "PAIR_J", { descriptor: S(b64u(control.cbor)) })); }),
    "requests", "p:" + b64u(control.id), null, "Control: the same construction with DEV_B's own keys gives DEV_B's descriptor and key; valid");
}
// §2.1, §4: platform is a scalar string in a device entry and in a request, revoked a scalar bool in a device entry.
stateCase("device_platform_and_revoked_valid", docWith("S_device_platform_revoked_ok", (d) => { put(d.devices, pref("DEV_B"), { label: S("Phone"), kind: 0, platform: S("mobile"), revoked: true }); }),
  "devices", pref("DEV_B"), null, "devices[p:<DEV_B>] with platform \"mobile\" and revoked = true");
stateCase("device_platform_wrong_type", docWith("S_device_platform_uint", (d) => { put(d.devices, pref("DEV_B"), { label: S("Phone"), kind: 0, platform: 7 }); }),
  "devices", pref("DEV_B"), "INVALID_FIELD_TYPE", "devices[p:<DEV_B>] with platform the uint 7");
stateCase("device_revoked_wrong_type", docWith("S_device_revoked_uint", (d) => { put(d.devices, pref("DEV_B"), { label: S("Phone"), kind: 0, revoked: 7 }); }),
  "devices", pref("DEV_B"), "INVALID_FIELD_TYPE", "devices[p:<DEV_B>] with revoked the uint 7");
stateCase("request_platform_wrong_type", docWith("S_request_platform_uint", (d) => { put(d.requests, pref("DEV_B"), reqEntry("DEV_B", "PAIR_J", { platform: 7 })); }),
  "requests", pref("DEV_B"), "INVALID_FIELD_TYPE", "requests[p:<DEV_B>] with platform the uint 7");
{
  // Concurrent platform values of a device entry: OWNER and DEV_A, each from the entry devices[p:<DEV_A>] the root wrote.
  const base = change("S_device_entry_dev_a", BASE, "OWNER", 3, "P1_device_grant_dev_a_i", (d) => { put(d.devices, pref("DEV_A"), { label: S("Laptop"), kind: 0 }); });
  const okRoot = change("S_device_platform_root", base.doc, "OWNER", 4, "P1_device_grant_dev_a_i", (d) => { d.devices[pref("DEV_A")].platform = S("desktop"); });
  const okDev = change("S_device_platform_dev_a", base.doc, "DEV_A", 1, "P1_device_grant_dev_a_i", (d) => { d.devices[pref("DEV_A")].platform = S("laptop"); });
  const badDev = change("S_device_platform_dev_a_uint", base.doc, "DEV_A", 1, "P1_device_grant_dev_a_i", (d) => { d.devices[pref("DEV_A")].platform = new A.Uint(7); });
  for (const r of [okRoot.r, okDev.r, badDev.r]) check(`device_conflicted_platform.${r.name}`, admit(r), null);
  {
    const [m] = A.applyChanges(A.clone(base.doc), [okRoot.r.bytes, okDev.r.bytes]);
    stateCase("device_conflicted_platform", m, "devices", pref("DEV_A"), null,
      "Concurrent platform values \"desktop\" (OWNER) and \"laptop\" (DEV_A) of devices[p:<DEV_A>]: valid, a reader may show either", { changes: "S_device_platform_root,S_device_platform_dev_a" });
  }
  for (const [suffix, order] of [["", [okRoot, badDev]], [".reverse", [badDev, okRoot]]]) {
    const [m] = A.applyChanges(A.clone(base.doc), order.map((o) => o.r.bytes));
    stateCase(`device_conflicted_platform_valid_invalid${suffix}`, m, "devices", pref("DEV_A"), "INVALID_FIELD_TYPE",
      `Concurrent platform values \"desktop\" and the uint 7 of devices[p:<DEV_A>], delivered ${order.map((o) => o.r.name).join(" then ")}`, { changes: order.map((o) => o.r.name).join(",") });
  }
}
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
  const platformBad = change("S_platform_uint", own.doc, "OWNER", 3, "P2_pairing_device", (d) => { d.requests[pref("DEV_B")].platform = new A.Uint(7); });
  for (const [suffix, order] of [["", [cont, platformBad]], [".reverse", [platformBad, cont]]]) {
    const [m] = A.applyChanges(A.clone(own.doc), order.map((o) => o.r.bytes));
    stateCase(`request_conflicted_platform_valid_invalid${suffix}`, m, "requests", pref("DEV_B"), "INVALID_FIELD_TYPE",
      `Concurrent platform values 'laptop' and the uint 7, delivered ${order.map((o) => o.r.name).join(" then ")}`, { changes: order.map((o) => o.r.name).join(",") });
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

/**
 * A change whose operations are written directly, so that they can address an object the engine does not
 * select (a hidden conflicting value). Every reference is into the causal history or an earlier operation of
 * the change (SOP §11.4); the change is checked to apply without missing dependencies.
 */
function encodeTargeted(name, doc, writer, unitSeq, controlRef, makeOps) {
  const history = A.getAllChanges(doc).map((b) => A.decodeChange(b));
  const actor = actorOf(writer);
  const startOp = 1 + Math.max(...history.map((d) => d.startOp + d.ops.length - 1));
  const bytes = A.encodeChange({ actor, seq: 1 + history.filter((d) => d.actor === actor).length,
    startOp, time: 0, message: "", deps: A.getHeads(doc), ops: makeOps((i) => `${startOp + i}@${actor}`) });
  const r = record(name, writer, bytes, unitSeq, controlRef);
  const [next] = A.applyChanges(A.clone(doc), [bytes]);
  check(`${name}.applied`, [A.getHeads(next).includes(r.hash), A.getMissingDeps(next)], [true, []]);
  return { r, doc: next };
}

// AI5 uses object creation history, including maps the engine does not select (REVIEW-403b R1).
{
  const AT = "P4_register_dev_b_approved", B = pref("DEV_B"), X = rref("X");
  const entry = CHANGES.get("M0_entry_dev_b");
  const left = historyOf([entry.hash]);
  const right = change("H0_dev_a_conflicting_entry", BASE, "DEV_A", 1, AT,
    (d) => { put(d.devices, B, { label: S("Other phone"), kind: 0 }); });
  check("hidden_entry.base", [admit(entry), admit(right.r)], [null, null]);
  const merged = A.merge(A.clone(left), A.clone(right.doc));
  const hidden = oid(left.devices, B), visible = oid(merged.devices, B);
  check("hidden_entry.conflicts", Object.keys(A.getConflicts(merged.devices, B)).sort(), [hidden, visible].sort());
  if (hidden === visible) throw new Error("the regression requires the original device map to be hidden");

  // The editor exposes only the selected map. Encode operations addressed to the hidden object instead;
  // every reference is into the causal history or an earlier operation of this change (SOP §11.4).
  const targeted = (name, doc, writer, unitSeq, makeOps) => encodeTargeted(name, doc, writer, unitSeq, AT, makeOps);
  const hintOps = (id) => [
    { action: "makeMap", obj: hidden, key: "missing_keys", pred: [] },
    { action: "makeList", obj: id(0), key: X, pred: [] },
    { action: "set", obj: id(1), elemId: "_head", insert: true, datatype: "uint", value: 5, pred: [] },
  ];
  const foreign = targeted("H1_root_hidden_hint", merged, "OWNER", 4, hintOps);
  const own = targeted("H1_dev_b_hidden_hint", merged, "DEV_B", 1, hintOps);
  changeCase("missing_keys_root_writes_hidden_device_hint", foreign.r, "UNAUTHORIZED_WRITER",
    "OWNER writes missing_keys = {X: [5]} into the hidden conflicting map of devices[p:<DEV_B>]", { rule: "AI5" });
  changeCase("missing_keys_device_writes_hidden_own_hint", own.r, null,
    "DEV_B writes missing_keys = {X: [5]} into its hidden conflicting entry map, created by OWNER", { rule: "AI5" });

  const list = `${own.r.decoded.startOp + 1}@${own.r.actor}`;
  const first = `${own.r.decoded.startOp + 2}@${own.r.actor}`;
  const appendOps = () => [{ action: "set", obj: list, elemId: first, insert: true, datatype: "uint", value: 6, pred: [] }];
  for (const [writer, unitSeq, suffix, want] of [["OWNER", 4, "root", "UNAUTHORIZED_WRITER"], ["DEV_B", 2, "device", null]]) {
    const appended = targeted(`H2_${suffix}_hidden_append`, own.doc, writer, unitSeq, appendOps);
    changeCase(`missing_keys_${suffix}_appends_hidden_hint`, appended.r, want,
      `${writer} appends epoch 6 inside the hidden device entry's missing_keys[X] list`, { rule: "AI5" });
  }
  const deleted = change("H2_root_deletes_conflicting_entries", own.doc, "OWNER", 4, AT, (d) => { delete d.devices[B]; });
  check("hidden_entry.delete", [admit(deleted.r), B in deleted.doc.devices], [null, false]);
  for (const [writer, unitSeq, suffix, want] of [["OWNER", 5, "root", "UNAUTHORIZED_WRITER"], ["DEV_B", 2, "device", null]]) {
    const appended = targeted(`H3_${suffix}_deleted_append`, deleted.doc, writer, unitSeq, appendOps);
    changeCase(`missing_keys_${suffix}_appends_deleted_entry_hint`, appended.r, want,
      `${writer} appends epoch 6 to missing_keys[X] after both conflicting devices[p:<DEV_B>] maps were deleted`, { rule: "AI5" });
  }

  // Resolve the entry conflict by removing only the selected map. The foreign branch must never expose its hint.
  const resolve = (name, branch) => targeted(name, branch.doc, "DEV_A", 2, () => [
    { action: "del", obj: oid(merged, "devices"), key: B, pred: [visible] },
  ]);
  const afterForeign = resolve("H2_resolve_after_foreign_hint", foreign);
  const afterOwn = resolve("H2_resolve_after_own_hint", own);
  const base = ["C0_initial", "C1_fill", entry.name, right.r.name];
  const orders = {
    foreign: [...base, foreign.r.name, afterForeign.r.name],
    device: [...base, own.r.name, afterOwn.r.name],
  };
  const expected = {};
  for (const [branch, order] of Object.entries(orders)) {
    const result = replay(order);
    const want = branch === "foreign"
      ? { admitted: base, refused: { [foreign.r.name]: "UNAUTHORIZED_WRITER" }, pending: [afterForeign.r.name] }
      : { admitted: order, refused: {}, pending: [] };
    check(`hidden_entry.${branch}`, { admitted: result.admitted, refused: result.refused, pending: result.pending }, want);
    expected[branch] = { ...want, state: view(result.doc) };
    if (branch === "device") {
      check("hidden_entry.resolved", [oid(result.doc.devices, B), view(result.doc.devices[B].missing_keys), validateEntry(result.doc, "devices", B).valid],
        [hidden, { [X]: [5] }, true]);
    } else {
      check("hidden_entry.foreign_not_merged", A.getAllChanges(result.doc).some((b) => A.decodeChange(b).hash === foreign.r.hash), false);
    }
  }
  expected.foreign.refused = { [foreign.r.name]: { code: "PROFILE_INVALID", diagnostic: "UNAUTHORIZED_WRITER" } };
  scenario("missing_keys_hidden_entry_resolution", "Resolving a device entry conflict after a foreign or an own hidden hint",
    ["IDENTITY-PROFILE-01 §3 AI5, SHARED-OBJECTS-PROFILE-01 §14.1", "AI5 checks every entry map in the causal history, selected or hidden; a refused change blocks its dependants."],
    { changes: [...new Set(Object.values(orders).flat())].map((n) => ({ case: `change.${n}` })), orders }, expected,
    ["OWNER's hidden hint is refused and its dependent conflict resolution stays pending.",
     "DEV_B's hidden hint is admitted; resolving the entry conflict exposes exactly its own {X: [5]} hint."]);
}
// AI5 on a replaced entry map: OWNER replaced devices[p:<DEV_B>] after DEV_B wrote its hint (review-spec-4b P3).
{
  const AT = "P4_register_dev_b_approved", B = pref("DEV_B"), X = rref("X");
  const replaced = CHANGES.get("M2_root_replaces_dev_b_entry");
  const doc = historyOf([replaced.hash]);
  const entry = CHANGES.get("M0_entry_dev_b"), hint = CHANGES.get("M1_dev_b_writes_hint");
  const at = (r, pred) => `${r.decoded.startOp + r.decoded.ops.findIndex(pred)}@${r.actor}`;
  const oldMap = at(entry, (op) => op.action === "makeMap" && op.key === B);
  const list = at(hint, (op) => op.action === "makeList" && op.key === X);
  const first = at(hint, (op) => op.obj === list && op.insert);
  check("replaced_entry.base", [oid(doc.devices, B) !== oldMap, admit(replaced)], [true, null]);
  const append = (value) => () => [{ action: "set", obj: list, elemId: first, insert: true, datatype: "uint", value, pred: [] }];
  changeCase("missing_keys_root_appends_replaced_entry_hint",
    encodeTargeted("H4_root_appends_replaced_hint", doc, "OWNER", 5, AT, append(7)).r, "UNAUTHORIZED_WRITER",
    "OWNER appends epoch 7 to missing_keys[X] that DEV_B wrote in the entry map OWNER has since replaced", { rule: "AI5" });
  changeCase("missing_keys_device_appends_replaced_entry_hint",
    encodeTargeted("H4_dev_b_appends_replaced_hint", doc, "DEV_B", 2, AT, append(7)).r, null,
    "DEV_B appends epoch 7 to its own missing_keys[X] in the entry map OWNER has since replaced", { rule: "AI5" });
}

// AI2 on the causal history: a scalar over a list of a hidden conflicting entry map (review-spec-4b P3).
{
  const AT = "P1_device_grant_dev_a_i"; // OWNER root, DEV_A personal
  const Z = SCOPE_FILL[0];
  const entryZ = (name) => ({ profile: S("org.lfcp.test.raw.v1"), endpoints: [S(wire.fixtures.endpoint.url)], coordinator: S(wire.fixtures.endpoint.coordinator), name: S(name) });
  const left = change("R0_root_creates_roster_z", BASE, "OWNER", 3, AT, (d) => { d.roster[Z] = entryZ("Z (desktop)"); });
  const right = change("R0_dev_a_creates_roster_z", BASE, "DEV_A", 1, AT, (d) => { d.roster[Z] = entryZ("Z (laptop)"); });
  check("hidden_roster.base", [admit(left.r), admit(right.r)], [null, null]);
  const merged = A.merge(A.clone(left.doc), A.clone(right.doc));
  const conflicts = Object.keys(A.getConflicts(merged.roster, Z)).sort();
  const visibleMap = oid(merged.roster, Z);
  const hiddenMap = conflicts.find((c) => c !== visibleMap);
  check("hidden_roster.conflicts", [conflicts.length, conflicts.includes(visibleMap)], [2, true]);
  const byActor = { [left.r.actor]: left.r, [right.r.actor]: right.r };
  // The operation that made the value of `key` in the entry map `map` (made by one of the two changes).
  const opIn = (map, key) => {
    const r = byActor[map.split("@")[1]];
    const i = r.decoded.ops.findIndex((op) => op.obj === map && op.key === key);
    if (i < 0) throw new Error(`no ${key} in ${map}`);
    return `${r.decoded.startOp + i}@${r.actor}`;
  };
  const scalarOver = (map, key, value) => () => [{ action: "set", obj: map, key, value, pred: [opIn(map, key)] }];
  const ai2 = (id, r, want, description) => changeCase(id, r, want, description, { rule: "AI2_HISTORY" });
  ai2("identity_doc_hidden_entry_list_replaced",
    encodeTargeted("R1_root_scalar_over_hidden_endpoints", merged, "OWNER", 4, AT, scalarOver(hiddenMap, "endpoints", "wss://replaced.invalid")).r,
    "CONTAINER_REPLACED", "OWNER writes a scalar over endpoints of the hidden conflicting map of roster[Z] (OWNER and DEV_A created roster[Z] concurrently)");
  ai2("identity_doc_entry_list_replaced",
    encodeTargeted("R1_root_scalar_over_visible_endpoints", merged, "OWNER", 4, AT, scalarOver(visibleMap, "endpoints", "wss://replaced.invalid")).r,
    "CONTAINER_REPLACED", "OWNER writes a scalar over endpoints of the selected map of roster[Z]: the same rule on the visible value");
  ai2("identity_doc_hidden_entry_scalar_written",
    encodeTargeted("R1_root_renames_hidden_entry", merged, "OWNER", 4, AT, scalarOver(hiddenMap, "name", "Z (renamed)")).r,
    null, "OWNER writes a scalar over the scalar name of the hidden map of roster[Z]: no object is replaced, admitted");
  // Only the predecessors decide (review-spec-5 R1): a scalar beside a list replaces nothing, and an object made
  // earlier in the same change is replaced like one of the history.
  ai2("identity_doc_scalar_beside_entry_list",
    encodeTargeted("R1_root_scalar_beside_endpoints", merged, "OWNER", 4, AT, () => [{ action: "set", obj: visibleMap, key: "endpoints", value: "wss://alternative.invalid", pred: [] }]).r,
    null, "OWNER writes a scalar endpoints beside the list of the selected map of roster[Z], naming no predecessor: a concurrent value, nothing replaced, admitted");
  ai2("identity_doc_list_made_in_change_replaced",
    encodeTargeted("R1_root_replaces_own_new_list", merged, "OWNER", 4, AT, (id) => [
      { action: "makeList", obj: hiddenMap, key: "endpoints", pred: [opIn(hiddenMap, "endpoints")] },
      { action: "set", obj: hiddenMap, key: "endpoints", value: "wss://replaced.invalid", pred: [id(0)] },
    ]).r,
    "CONTAINER_REPLACED", "OWNER replaces endpoints of the hidden map of roster[Z] with a new list, then that new list with a scalar, in one change");
  const W = SCOPE_FILL[1];
  ai2("identity_doc_entry_map_made_in_change_replaced",
    encodeTargeted("R1_root_replaces_own_new_entry", merged, "OWNER", 4, AT, (id) => [
      { action: "makeMap", obj: oid(merged, "roster"), key: W, pred: [] },
      { action: "set", obj: oid(merged, "roster"), key: W, value: "not an entry", pred: [id(0)] },
    ]).r,
    "CONTAINER_REPLACED", "OWNER creates a new entry map roster[W], then replaces it with a scalar, in one change");
}
// AI2 depth (sdk-rs#5 P2-1, sdk-ts#16 P1): only an entry map (depth 2) and a list or map held in a field of an
// entry map (depth 3) are protected. A scalar over an object one level deeper, or over a list held directly at
// devices[k], is admitted by AI2; §4 then judges the entry, and AI5 still decides who writes into missing_keys.
{
  const AT = "P4_register_dev_b_approved"; // OWNER root, DEV_A and DEV_B personal in I
  const B = pref("DEV_B"), X = rref("X"), O = pref("OWNER");
  const ai2 = (id, r, want, description, rule = "AI2_DEPTH") => changeCase(id, r, want, description, { rule });
  const hint = CHANGES.get("M1_dev_b_writes_hint");
  const withHint = historyOf([hint.hash]);
  const own = change("D1_dev_b_scalar_over_own_hint_list", withHint, "DEV_B", 2, AT, (d) => { d.devices[B].missing_keys[X] = true; });
  ai2("identity_doc_device_scalar_over_own_hint_list", own.r, null,
    "DEV_B writes the boolean true over its own list devices[p:<DEV_B>].missing_keys[X] (depth 4, after missing_keys_device_writes_own): not an entry map or a field of one, admitted");
  stateCase("identity_doc_device_scalar_over_own_hint_list.entry", own.doc, "devices", B, "INVALID_FIELD_TYPE",
    "The entry devices[p:<DEV_B>] after identity_doc_device_scalar_over_own_hint_list: missing_keys[X] is not a list of uint, so §4 marks the entry invalid");
  ai2("identity_doc_root_scalar_over_device_hint_list",
    change("D1_root_scalar_over_dev_b_hint_list", withHint, "OWNER", 4, AT, (d) => { d.devices[B].missing_keys[X] = true; }).r, "UNAUTHORIZED_WRITER",
    "OWNER writes the boolean true over DEV_B's list devices[p:<DEV_B>].missing_keys[X] (depth 4): AI2 does not apply, AI5 refuses the foreign writer", "AI5");

  const future = change("D0_root_writes_unknown_nested_field", BASE, "OWNER", 3, AT, (d) => { d.devices[O].future = { [X]: [S("a")] }; });
  ai2("identity_doc_unknown_nested_field_written", future.r, null,
    "OWNER writes an unknown field devices[p:<OWNER>].future = {X: [\"a\"]}: admitted, the base of the next case", "OK");
  const futureScalar = change("D1_root_scalar_over_unknown_nested_list", future.doc, "OWNER", 4, AT, (d) => { d.devices[O].future[X] = S("s"); });
  ai2("identity_doc_scalar_over_unknown_nested_list", futureScalar.r, null,
    "OWNER writes the string \"s\" over the list devices[p:<OWNER>].future[X] of an unknown field (depth 4): admitted");
  stateCase("identity_doc_scalar_over_unknown_nested_list.entry", futureScalar.doc, "devices", O, null,
    "The entry devices[p:<OWNER>] after identity_doc_scalar_over_unknown_nested_list: the unknown field is preserved and the entry stays valid");

  const ext = change("D0_root_writes_roster_ext", BASE, "OWNER", 3, AT, (d) => { d.roster[X].ext = { a: {} }; });
  ai2("identity_doc_unknown_nested_map_written", ext.r, null,
    "OWNER writes an unknown field roster[X].ext = {a: {}}: admitted, the base of the next two cases", "OK");
  ai2("identity_doc_scalar_over_unknown_nested_map",
    change("D1_root_scalar_over_roster_ext_a", ext.doc, "OWNER", 4, AT, (d) => { d.roster[X].ext.a = S("s"); }).r, null,
    "OWNER writes the string \"s\" over the map roster[X].ext.a (depth 4): admitted");
  ai2("identity_doc_scalar_over_entry_field_map",
    change("D1_root_scalar_over_roster_ext", ext.doc, "OWNER", 4, AT, (d) => { d.roster[X].ext = S("s"); }).r, "CONTAINER_REPLACED",
    "OWNER writes the string \"s\" over the map roster[X].ext, held in a field of an entry map (depth 3): the control of the previous case");

  const DX = pref("DEV_X");
  const listEntry = change("D0_root_writes_list_at_devices_key", BASE, "OWNER", 3, AT, (d) => { d.devices[DX] = [S("a")]; });
  ai2("identity_doc_list_at_entry_key_written", listEntry.r, null,
    "OWNER writes a list devices[p:<DEV_X>] = [\"a\"], not an entry map: admitted (§4 judges the entry), the base of the next case", "OK");
  const scalarEntry = change("D1_root_scalar_over_list_at_devices_key", listEntry.doc, "OWNER", 4, AT, (d) => { d.devices[DX] = S("s"); });
  ai2("identity_doc_scalar_over_list_at_entry_key", scalarEntry.r, null,
    "OWNER writes the string \"s\" over the list devices[p:<DEV_X>]: a list held directly in devices is not an entry map, admitted");
  // A later change beside an entry that is not a map is decided like any other (review of spec#6, R1): the invalid
  // entry is ignored by readers and the rest of the document stays usable (§4 rule 1).
  const relabel = (d) => { d.devices[O].label = S("Renamed"); };
  ai2("identity_doc_change_after_list_entry",
    change("D1_root_relabels_beside_list_entry", listEntry.doc, "OWNER", 4, AT, relabel).r, null,
    "OWNER relabels its own entry devices[p:<OWNER>] while devices[p:<DEV_X>] holds the list of identity_doc_list_at_entry_key_written: admitted", "OK");
  const after = change("D2_root_relabels_beside_scalar_entry", scalarEntry.doc, "OWNER", 5, AT, relabel);
  ai2("identity_doc_change_after_scalar_entry", after.r, null,
    "OWNER relabels its own entry devices[p:<OWNER>] after identity_doc_scalar_over_list_at_entry_key, while devices[p:<DEV_X>] holds the string \"s\": admitted", "OK");
  stateCase("identity_doc_change_after_scalar_entry.entry", after.doc, "devices", O, null,
    "The entry devices[p:<OWNER>] after identity_doc_change_after_scalar_entry: valid, with label \"Renamed\"; the entry devices[p:<DEV_X>] does not affect it (§4 rule 1)");
}
// AI3 positions (decision I27, from the cross-SDK review P2-1): the type check applies only where §2.1 defines a
// position. A value of extensions[ns], an unknown field and anything below a map written into a scalar field are not
// type-checked; a list element admits only a scalar of §2.1.
{
  const AT = "P4_register_dev_b_approved";
  const B = pref("DEV_B"), X = rref("X"), O = pref("OWNER");
  const ai3 = (id, r, want, description) => changeCase(id, r, want, description, { rule: "AI3_POS" });
  const byRoot = (name, fn) => change(name, BASE, "OWNER", 3, AT, fn);
  const datatypeOf = (r, key) => r.decoded.ops.find((op) => op.key === key)?.datatype ?? null;

  const extInt = byRoot("T1_root_extension_int", (d) => { d.extensions["com.example.n"] = new A.Int(5); });
  check("T1_root_extension_int.datatype", datatypeOf(extInt.r, "com.example.n"), "int");
  ai3("identity_doc_extension_int_value", extInt.r, null,
    "The root writes extensions[\"com.example.n\"] = 5 as a signed Automerge int: a namespace value is not type-checked (SOP §18), admitted");
  const extF64 = byRoot("T1_root_extension_f64", (d) => { d.extensions["com.example.f"] = new A.Float64(1.5); });
  check("T1_root_extension_f64.datatype", datatypeOf(extF64.r, "com.example.f"), "float64");
  ai3("identity_doc_extension_f64_value", extF64.r, null,
    "The root writes extensions[\"com.example.f\"] = 1.5 as an Automerge f64: admitted");
  ai3("identity_doc_extension_null_value", byRoot("T1_root_extension_null", (d) => { d.extensions["com.example.z"] = null; }).r, null,
    "The root writes extensions[\"com.example.z\"] = null: admitted");

  ai3("identity_doc_map_in_endpoints", byRoot("T1_root_map_in_endpoints", (d) => { d.roster[X].endpoints.push({}); }).r, "INVALID_FIELD_TYPE",
    "The root appends an empty map to the list roster[X].endpoints: an element of a list field admits only a scalar of §2.1");
  const name = byRoot("T1_root_int_below_name", (d) => { d.roster[X].name = {}; d.roster[X].name.x = new A.Int(-1); });
  check("T1_root_int_below_name.datatype", datatypeOf(name.r, "x"), "int");
  ai3("identity_doc_int_below_scalar_field", name.r, null,
    "The root writes roster[X].name = {x: -1}, a map holding a signed Automerge int, into a field whose §2.1 type is a scalar string: nothing below the map is type-checked, admitted");
  stateCase("identity_doc_int_below_scalar_field.entry", name.doc, "roster", X, "INVALID_FIELD_TYPE",
    "The entry roster[X] after identity_doc_int_below_scalar_field: name is not a scalar string, so §4 marks the entry invalid");
  const unknown = byRoot("T1_root_unknown_field_int", (d) => { d.roster[X].note = new A.Int(-5); });
  check("T1_root_unknown_field_int.datatype", datatypeOf(unknown.r, "note"), "int");
  ai3("identity_doc_unknown_field_int_value", unknown.r, null,
    "The root writes the unknown field roster[X].note = -5 as a signed Automerge int: an unknown field is not type-checked, admitted");
  stateCase("identity_doc_unknown_field_int_value.entry", unknown.doc, "roster", X, null,
    "The entry roster[X] after identity_doc_unknown_field_int_value: the unknown field is preserved and the entry stays valid");
  const label = byRoot("T1_root_f64_label", (d) => { d.devices[O].label = new A.Float64(1.5); });
  check("T1_root_f64_label.datatype", datatypeOf(label.r, "label"), "float64");
  ai3("identity_doc_f64_in_named_field", label.r, "INVALID_FIELD_TYPE",
    "The root writes devices[p:<OWNER>].label = 1.5 as an Automerge f64: a named field admits only a scalar of §2.1, a map or a list");
  ai3("identity_doc_null_in_named_field", byRoot("T1_root_null_platform", (d) => { d.devices[O].platform = null; }).r, "INVALID_FIELD_TYPE",
    "The root writes devices[p:<OWNER>].platform = null: null is not a scalar of §2.1");
  const listAsMap = byRoot("T1_root_map_for_endpoints", (d) => { d.roster[X].endpoints = {}; d.roster[X].endpoints.a = new A.Float64(1.5); });
  ai3("identity_doc_f64_below_map_in_list_field", listAsMap.r, null,
    "The root replaces the list roster[X].endpoints with a map {a: 1.5} holding an Automerge f64: a map is admitted in a named field, and a key of a map is not a list element, so nothing below it is type-checked; admitted");
  stateCase("identity_doc_f64_below_map_in_list_field.entry", listAsMap.doc, "roster", X, "INVALID_FIELD_TYPE",
    "The entry roster[X] after identity_doc_f64_below_map_in_list_field: endpoints is not a list of strings, so §4 marks the entry invalid");

  ai3("identity_doc_map_in_scope",
    change("T1_pair_j_map_in_scope", BASE, "PAIR_J", 1, "P2_pairing_device", (d) => {
      put(d.requests, pref("BRIDGE_O"), reqEntry("BRIDGE_O", "PAIR_J", { kind: 1, scope: [X, {}] }));
    }).r, "INVALID_FIELD_TYPE",
    "PAIR_J creates its own request requests[p:<BRIDGE_O>] of kind 1 whose scope holds X and an empty map: AI4 admits the writer, AI3 refuses the map in a list field");
  const withHint = historyOf([CHANGES.get("M1_dev_b_writes_hint").hash]);
  ai3("identity_doc_map_in_hint_list",
    change("T1_dev_b_map_in_own_hint", withHint, "DEV_B", 2, AT, (d) => { d.devices[B].missing_keys[X].push({}); }).r, "INVALID_FIELD_TYPE",
    "DEV_B appends an empty map to its own list devices[p:<DEV_B>].missing_keys[X] (after missing_keys_device_writes_own): AI5 admits the writer, AI3 refuses the map in a list field");
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
{
  // §5.2 applies W §18.2: a receiver rejects a link whose endpoint value is invalid, and W §16 says which are: a scheme
  // other than ws or wss, compared case-insensitively, or one not followed by "://". A sender writes wss, or ws for a
  // loopback address, so a link to a local server carries ws://127.0.0.1 and a receiver accepts it (cross-SDK review P3-1).
  const ENDPOINT_RULE = ["IDENTITY-PROFILE-01 §5.2; LFCP-WIRE-01 §18.2, §16", "A receiver rejects a pairing link whose endpoint value is invalid: its scheme, compared case-insensitively, is not ws or wss, or is not followed by \"://\". A sender uses wss, or ws for a loopback address."];
  const endpointError = (url) => {
    const m = /^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/s.exec(url);
    if (!m || !["ws", "wss"].includes(m[1].toLowerCase())) return "endpoint: the scheme is not ws or wss";
    if (!/^\/\/[^/?#]/.test(m[2])) return "endpoint: no authority after the scheme";
    return null;
  };
  const endpointCase = (id, url, description) => {
    const uri = pairUri().replace(`endpoint=${RFC3986(wire.fixtures.endpoint.url)}`, `endpoint=${RFC3986(url)}`);
    check(`${id}.uri`, [uri !== pairUri(), parsePair(uri), new URLSearchParams(uri.split("?")[1].split("#")[0]).getAll("endpoint")], [true, null, [url]]);
    const err = endpointError(url);
    add({ id, type: "validation", kind: "pair_uri", description, rule: { section: ENDPOINT_RULE[0], text: ENDPOINT_RULE[1] },
      inputs: { uri, parser: "pair", endpoint: url },
      expected: err === null ? { valid: true } : { valid: false, error: { code: "PAIRING_LINK_REJECTED", detail: err } } });
  };
  endpointCase("pair_uri_endpoint_ws_loopback", "ws://127.0.0.1:8787",
    "The link of PAIR_J for I with the endpoint ws://127.0.0.1:8787, what a sender writes for a loopback server: accepted on parse");
  endpointCase("pair_uri_endpoint_upper_case_scheme", "WSS://sync.example",
    "The link of PAIR_J for I with the endpoint WSS://sync.example: the scheme is compared case-insensitively, accepted on parse");
  endpointCase("pair_uri_endpoint_https", "https://sync.example",
    "The link of PAIR_J for I with the endpoint https://sync.example: not ws or wss, rejected");
  endpointCase("pair_uri_endpoint_without_authority", "wss:sync.example",
    "The link of PAIR_J for I with the endpoint wss:sync.example: the scheme is not followed by \"://\", rejected");
}
{
  // §5.2: the receiving client recomputes J's descriptor from the secret and checks it against device, opens the Resource
  // as J, verifies its Genesis profile and that J is a registered, active kind-2 device of its owner, before any other use.
  const GENESIS = { I: "P0_genesis_i", Z: "link.z_genesis" };
  const secretOf = (label) => {
    const c = principal(label).c;
    return Buffer.concat([Buffer.from([0xa3, 0x00, 0x01, 0x01]), bstr(Buffer.from(c.inputs.ed25519_seed.hex, "hex")), Buffer.from([0x02]), bstr(Buffer.from(c.inputs.x25519_private.hex, "hex"))]);
  };
  const linkOf = (label, res) => `lfcp://pair/${b64u(RES[res])}?endpoint=${RFC3986(wire.fixtures.endpoint.url)}&device=${b64u(principal(label).id)}#secret=${b64u(secretOf(label))}`;
  const rawPublic = (pkcs8Prefix, key) =>
    Buffer.from(createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from(pkcs8Prefix, "hex"), key]), format: "der", type: "pkcs8" })).export({ format: "jwk" }).x, "base64url");
  function checkLink(uri, head) {
    const m = /^lfcp:\/\/pair\/([A-Za-z0-9_-]{43})\?([^#]*)#secret=([A-Za-z0-9_-]+)$/.exec(uri);
    if (!m) return { detail: "not a pairing link" };
    const sec = Buffer.from(m[3], "base64url");
    if (sec.length !== 73 || sec[0] !== 0xa3 || sec[4] !== 0x58 || sec[38] !== 0x02 || sec[39] !== 0x58) return { detail: "the secret is not an invite-secret" };
    const ed = rawPublic("302e020100300506032b657004220420", sec.subarray(6, 38));
    const x = rawPublic("302e020100300506032b656e04220420", sec.subarray(41, 73));
    const id = sha(Buffer.from("LFCP-PRINCIPAL-v1"), ed, x);
    const device = new URLSearchParams(m[2]).get("device");
    if (device !== b64u(id)) return { detail: "check 1: the secret's Principal is not device" };
    const label = wire.cases.filter((c) => c.kind === "principal").map((c) => c.inputs.label).find((l) => principal(l).id.equals(id)) ?? null;
    const res = Object.keys(RES).find((k) => b64u(RES[k]) === m[1]);
    const ps = W.get(head).expected.post_state;
    const b = ps.devices[label];
    const revokedReader = b && b.registered && ps.revoked[`${b.root}/${label}`] !== undefined && !b.reads;
    if (!(b && b.reads) && !revokedReader) return { detail: "check 2: the session as J is refused (W §41): J is not a reader" };
    const profile = W.get(GENESIS[res]).inputs.body.data_profile;
    if (profile !== PROFILE) return { detail: `check 3: the Genesis profile is ${profile}` };
    if (!(b.kind === 2 && b.registered && b.active && b.root === ps.owner)) {
      return { detail: `check 4: J is not a registered, active kind-2 device of the owner (kind ${b.kind}, active ${b.active}, root ${b.root}, owner ${ps.owner})` };
    }
    return null;
  }
  const LINK_RULE = ["IDENTITY-PROFILE-01 §5.2", "Before using the secret for anything else the client recomputes J's descriptor and checks it against device, opens the Resource as J, verifies that its Genesis profile is org.openlfcp.identity.v1 and that J is a registered, active kind-2 device of its owner; a link that fails is rejected, with no request and nothing more sent as J."];
  const linkCheckCase = (id, label, res, head, want, description) => {
    const uri = linkOf(label, res);
    const got = checkLink(uri, head);
    check(id, got === null ? null : got.detail.slice(0, 7), want);
    add({ id, type: "validation", kind: "pair_uri", description, rule: { section: LINK_RULE[0], text: LINK_RULE[1] },
      inputs: { uri, parser: "pair", device: label, binding_head: head, genesis: GENESIS[res] },
      expected: got === null ? { valid: true } : { valid: false, error: { code: "PAIRING_LINK_REJECTED", detail: got.detail } } });
  };
  linkCheckCase("pair_uri_checks_pass", "PAIR_J", "I", "P2_pairing_device", null, "Control: the link of PAIR_J against I at P2: every check passes");
  linkCheckCase("pair_uri_genesis_not_identity", "PAIR_Z", "Z", "link.z_pairing_device", "check 3",
    "The link of PAIR_Z, a registered, active kind-2 device of OWNER in Z, whose Genesis profile is org.lfcp.test.raw.v1");
  linkCheckCase("pair_uri_device_kind_0", "DEV_A", "I", "P2_pairing_device", "check 4",
    "A link carrying the keys of DEV_A, a registered, active kind-0 device of OWNER in I, with device = DEV_A");
  linkCheckCase("pair_uri_device_of_other_root", "PAIR_B", "I", "link.pairing_device_of_bob", "check 4",
    "The link of PAIR_B, a registered, active kind-2 device of BOB in I, which OWNER owns");
  linkCheckCase("pair_uri_device_consumed", "PAIR_J", "I", "P3_consume_for_dev_b", "check 4",
    "The link of PAIR_J against I at P3, its session consumed: J opens through the revoked-reader prefix and is not active");
  linkCheckCase("pair_uri_device_suspended", "PAIR_J", "I", "device_revoke_bound_after_tombstone_limit", "check 2",
    "The link of PAIR_J against I after its issuer DEV_A was revoked: J is suspended and cannot open I");
  linkCheckCase("pair_uri_device_not_registered", "PAIR_M", "I", "P2_pairing_device", "check 2",
    "The link of PAIR_M, a pairing device not bound in I at P2");
}
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
