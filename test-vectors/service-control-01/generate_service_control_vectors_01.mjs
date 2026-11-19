#!/usr/bin/env node
// Generates SERVICE-CONTROL-TEST-VECTORS-01 (SERVICE-CONTROL-PROFILE-01 §12):
// admission of changes to a control Resource C (§§2–4), state validation of the
// entries a change writes (§5), and replica transitions across concurrent
// changes (§3, §6, §7.3).
//
// Conventions of the identity profile corpus: every change is made by the
// pinned @automerge/automerge 3.5.0 with time 0 and no message, by the actor of
// SHARED-OBJECTS-PROFILE-01 §8 for C, so the output is deterministic. C's
// Control states are given as fixtures (the writer classes of §2.3 need only
// who is bound, with which kind, root and scope); Principals are derived as in
// IDENTITY-PROFILE-01 §12.1 with the label prefix SC-.
//
// Every expectation below is written from the profile text and checked against
// the reference admission of this file; a disagreement stops the generator.
// The reference is test support, not a production validator.
//
//   node generate_service_control_vectors_01.mjs [--out-dir DIR]

import * as A from "@automerge/automerge";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SUITE_ID = "SERVICE-CONTROL-TEST-VECTORS-01";
const PROFILE = "org.openlfcp.service-control.v1";
const SPEC = "SERVICE-CONTROL-PROFILE-01";
const outArg = process.argv.indexOf("--out-dir");
const OUT = outArg > 0 ? process.argv[outArg + 1] : HERE;

const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
const hex = (b) => Buffer.from(b).toString("hex");
const b64u = (b) => Buffer.from(b).toString("base64url");

// ---------------------------------------------------------------------------
// Principals, Resources, Control states.
// ---------------------------------------------------------------------------

const rawPublic = (seed, oidHex) =>
  createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from(`302e020100300506032b65${oidHex}04220420`, "hex"), seed]), format: "der", type: "pkcs8" }))
    .export({ format: "der", type: "spki" }).subarray(-32);
const P = {};
for (const label of ["R", "A", "B", "B2", "D_X", "J_X", "BOB", "BOB_D"]) {
  const ed = rawPublic(sha(`LFCP-TV-SC-${label}-ED25519`), "70");
  const x = rawPublic(sha(`LFCP-TV-SC-${label}-X25519`), "6e");
  const id = sha("LFCP-PRINCIPAL-v1", ed, x);
  const field = (k, v) => Buffer.concat([Buffer.from([k, 0x58, 32]), v]);
  P[label] = { id, ref: `p:${b64u(id)}`, descriptor: Buffer.concat([Buffer.from([0xa3]), field(0, id), field(1, ed), field(2, x)]) };
}
const C = sha("LFCP-TV-SC-RESOURCE-C");
const RES = { C: b64u(C), X: b64u(sha("LFCP-TV-SC-RESOURCE-X")), Y: b64u(sha("LFCP-TV-SC-RESOURCE-Y")) };
const actorOf = (label) => hex(sha("OPENLFCP-SHARED-OBJECTS-ACTOR-v1", C, P[label].id));
const fp = (label) => {
  const d = sha("LFCP-DEVICE-FP-v1", P[label].id).subarray(0, 10);
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0, value = 0, out = "";
  for (const byte of d) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out.match(/.{4}/g).join("-");
};

// C's Control states at the control_ref of the cases: who is bound in C, with which kind, root and scope (W §80.1).
const dev = (kind, root, scope, active = true) => ({ kind, root, ...(scope ? { scope } : {}), bound_in_c: kind !== 2 && (!scope || scope.includes("C")), active });
const LIVE = {
  owner: "R", members: { BOB: "non-device member of C, root of BOB_D" },
  devices: { A: dev(0, "R"), B: dev(1, "R", ["C"]), B2: dev(1, "R", ["C"]), D_X: dev(1, "R", ["X"]), J_X: dev(2, "R"), BOB_D: dev(0, "BOB") },
};
const CONTROL = {
  CS0_genesis: { owner: "R", members: {}, devices: {} },
  CS1_live: LIVE,
  CS2_b_revoked: { ...LIVE, devices: { ...LIVE.devices, B: dev(1, "R", ["C"], false) } },
};

// ---------------------------------------------------------------------------
// Values and state validation (§2.1, §5).
// ---------------------------------------------------------------------------

const S = (v) => new A.ImmutableString(v);
const str = (v) => (A.isImmutableString(v) ? v.toString() : v);
const isStr = (v) => A.isImmutableString(v);
const isMap = (v) => v && typeof v === "object" && !Array.isArray(v) && !isStr(v);
/** Writes a plain value: numbers as uint, strings as ImmutableString, Text only when asked. */
function put(target, key, value) {
  if (value === undefined) return;
  if (typeof value === "number") target[key] = new A.Uint(value);
  else if (typeof value === "string") target[key] = S(value);
  else if (typeof value === "boolean") target[key] = value;
  else if (value instanceof Text) target[key] = value.s;
  else if (Array.isArray(value)) { target[key] = []; value.forEach((v, i) => put(target[key], i, v)); }
  else { target[key] = {}; for (const [k, v] of Object.entries(value)) put(target[key], k, v); }
}
class Text { constructor(s) { this.s = s; } }

const UUID7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const B64_32 = /^[A-Za-z0-9_-]{43}$/;
const isRef32 = (v) => B64_32.test(v) && b64u(Buffer.from(v, "base64url")) === v;
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const EVENT_STATES = ["received", "executing", "request-ready", "ready", "applied", "failed", "rejected", "stale", "cancelled"];
const FINAL = new Set(EVENT_STATES.slice(4));
const ORDER5 = ["INVALID_ROOT", "MISSING_REQUIRED_FIELD", "INVALID_FIELD_TYPE", "INVALID_RESOURCE_REF", "INVALID_PRINCIPAL_REF", "INVALID_KEY", "INVALID_ENUM_VALUE", "INVALID_TIMESTAMP", "INVALID_DESCRIPTOR", "LIMIT_EXCEEDED"];

// Field types: s string, u uint, b boolean, t timestamp, r ResourceRef, p PrincipalRef, h Hash32, id Uuid, x Example,
// m any map; [t] a list, {..} a map with these fields; "?" marks an optional field; an array of strings is an enum.
const SCHEMA = {
  approvals: { role: ["base", "section"], resource: "r", principal: "p", certDigest: "h", certId: "h", generation: "u", origin: "s", at: "t", "revoked?": { at: "t" } },
  service: { instance: "s", kind: "s", label: "s", platform: "s", app: "s", protocol: { v: "u", ops: ["s"], questionKinds: ["s"] }, artifactSliceId: "s", macos: "s", cert: { state: "s", manifestSeq: "u", certTestMode: "b" }, capacity: { sections: "u", max: "u", devicesFree: "u" } },
  status: { state: "s", since: "t", heartbeatAt: "t", "message?": "s" },
  bindings: { state: "s", generation: "u", list: "s", filter: "s", "lastCompleteCheckAt?": "t", pending: { toApple: "u", toLfcp: "u" }, refused: "u", unconfirmed: "u", "preview?": "m", "needsAttention?": { code: "s" }, "lifecycle?": "s" },
  pairing: { descriptor: "s", principal: "p", fp: "s" },
  questions: { binding: "r", generation: "u", kind: "s", anomalyId: "s", snapshotHash: "s", items: ["x"], counts: "m", "actor?": "s", options: ["s"], at: "t", "resolved?": { answerId: "id", choice: "s", at: "t" }, "superseded?": { by: "s" } },
  requests: { op: "op", "binding?": "r", "generation?": "u", args: "m", client: { app: "s", protocol: "u" }, at: "t" },
  answers: { qid: "id", snapshotHash: "s", choice: "s", at: "t" },
  cancels: { reason: ["user", "mismatch", "expired"], at: "t" },
  events: { state: EVENT_STATES, "code?": "s", "detail?": "s", at: "t" },
  lifecycle: { "op?": ["remove", "uninstall"], "bindings?": [{ binding: "r", generation: "u" }], "at?": "t" },
};
const sortKeys = (x) => (x && typeof x === "object" && !Array.isArray(x) && !A.isImmutableString(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x);
const json = (v) => JSON.stringify(v, (k, x) => (typeof x === "bigint" ? `${x}` : sortKeys(x)));
const UUID_KEYED = new Set(["pairing", "questions", "requests", "answers", "cancels", "events"]);

function checkValue(type, v, found) {
  if (typeof type === "string") {
    const scalar = { s: isStr(v), u: typeof v === "bigint" && v >= 0n, b: typeof v === "boolean", m: isMap(v) }[type];
    if (scalar !== undefined) return void (scalar || found.add("INVALID_FIELD_TYPE"));
    if (!isStr(v)) return void found.add("INVALID_FIELD_TYPE");
    const s = str(v);
    if (type === "t" && !TS.test(s)) found.add("INVALID_TIMESTAMP");
    if (type === "r" && !isRef32(s)) found.add("INVALID_RESOURCE_REF");
    if (type === "p" && !(s.startsWith("p:") && isRef32(s.slice(2)))) found.add("INVALID_PRINCIPAL_REF");
    if (type === "h" && !isRef32(s)) found.add("INVALID_FIELD_TYPE");
    if (type === "id" && !UUID7.test(s)) found.add("INVALID_FIELD_TYPE");
    if (type === "op" && !/^[a-z-]{1,32}$/.test(s)) found.add("INVALID_ENUM_VALUE");
    if (type === "x" && [...s].length > 80) found.add("LIMIT_EXCEEDED");
    return;
  }
  if (Array.isArray(type) && type.every((t) => typeof t === "string" && type.length > 1)) {
    return void (!isStr(v) ? found.add("INVALID_FIELD_TYPE") : type.includes(str(v)) || found.add("INVALID_ENUM_VALUE"));
  }
  if (Array.isArray(type)) {
    if (!Array.isArray(v)) return void found.add("INVALID_FIELD_TYPE");
    return v.forEach((e) => checkValue(type[0], e, found));
  }
  if (!isMap(v)) return void found.add("INVALID_FIELD_TYPE");
  for (const [k, t] of Object.entries(type)) {
    const name = k.replace(/\?$/, "");
    if (v[name] === undefined) { if (!k.endsWith("?")) found.add("MISSING_REQUIRED_FIELD"); } else checkValue(t, v[name], found);
  }
}
/** The first §5 diagnostic of `top[key]` (or of `top` for service, status, lifecycle), or null. */
function entryDiagnostic(top, key, v) {
  const found = new Set();
  if (["service", "status", "lifecycle"].includes(top) && isMap(v) && Object.keys(v).length === 0) return null; // §5 rule 1
  checkValue(SCHEMA[top], v, found);
  if (UUID_KEYED.has(top) && !UUID7.test(key)) found.add("INVALID_KEY");
  if (top === "bindings" && !isRef32(key)) found.add("INVALID_RESOURCE_REF");
  if (top === "approvals" && isMap(v)) {
    if (str(v.principal) !== key) found.add("INVALID_KEY");
    if (str(v.role) === "base" && str(v.resource) !== RES.C) found.add("INVALID_ENUM_VALUE");
  }
  if (top === "questions" && Array.isArray(v?.items) && v.items.length > 5) found.add("LIMIT_EXCEEDED");
  if (top === "pairing" && isMap(v) && isStr(v.descriptor)) {
    const label = Object.keys(P).find((l) => b64u(P[l].descriptor) === str(v.descriptor));
    if (!label || P[label].ref !== str(v.principal) || fp(label) !== str(v.fp)) found.add("INVALID_DESCRIPTOR");
  }
  return ORDER5.find((d) => found.has(d)) ?? null;
}

// ---------------------------------------------------------------------------
// Changes and the reference admission (§2.3, §3, §4).
// ---------------------------------------------------------------------------

const ROOT_KEYS = ["profile", "meta", "approvals", "service", "status", "bindings", "pairing", "questions", "requests", "answers", "cancels", "events", "lifecycle"];
const WHOLE = new Set(["service", "status", "lifecycle"]);
const ROW = { approvals: ["root", "personal"], service: ["service"], status: ["service"], lifecycle: ["service"], bindings: ["service"], pairing: ["service"], questions: ["service"], requests: ["root", "personal", "service"], answers: ["root", "personal", "service"], cancels: ["root", "personal", "service"], events: ["service"] };
const ADMISSION_ORDER = ["INVALID_AUTOMERGE_BYTES", "CHANGE_ACTOR_MISMATCH", "INVALID_ROOT", "CONTAINER_REPLACED", "IMMUTABLE_FIELD_MUTATED", "UNKNOWN_ROOT_KEY", "UNAUTHORIZED_WRITER", "FORBIDDEN_MUTATION", ...ORDER5.slice(1)];
const CHANGES = new Map();

function historyOf(deps) {
  const need = new Set();
  const byHash = new Map([...CHANGES.values()].map((r) => [r.hash, r]));
  const stack = [...deps];
  while (stack.length) {
    const h = stack.pop();
    if (!need.has(h)) { need.add(h); stack.push(...byHash.get(h).deps); }
  }
  return A.applyChanges(A.init(), [...CHANGES.values()].filter((r) => need.has(r.hash)).map((r) => r.bytes))[0];
}
const values = (obj, key) => {
  if (obj == null) return [];
  const c = A.getConflicts(obj, key);
  return c ? Object.values(c) : obj[key] === undefined ? [] : [obj[key]];
};
const eventState = (doc, id) => values(doc.events?.[id] ?? null, "state").map(str).sort((a, b) => EVENT_STATES.indexOf(b) - EVENT_STATES.indexOf(a))[0];
const isFinal = (doc, id) => doc.events?.[id] !== undefined && values(doc.events[id], "state").map(str).some((s) => FINAL.has(s));
const openRequests = (doc, op) => Object.keys(doc.requests ?? {}).filter((rid) => !isFinal(doc, rid) && (!op || str(doc.requests[rid].op) === op)).length;
function size(v) {
  if (isStr(v)) return Buffer.byteLength(str(v));
  if (Array.isArray(v)) return v.reduce((n, e) => n + size(e), 0);
  if (isMap(v)) return Object.keys(v).reduce((n, k) => n + values(v, k).reduce((m, e) => m + Buffer.byteLength(k) + size(e), 0), 0);
  return 8;
}

/** §2.3: the class of `label` at `controlRef`, and for a kind-1 device the approvals of the pre-state. */
function writerClass(label, controlRef, pre) {
  const ctl = CONTROL[controlRef];
  if (ctl.owner === label) return "root";
  const d = ctl.devices[label];
  if (!d || !d.bound_in_c || !d.active || d.root !== ctl.owner) return "other";
  if (d.kind === 0) return "personal";
  if (d.kind !== 1) return "other";
  const bases = Object.keys(pre.approvals ?? {}).filter((k) => {
    const v = pre.approvals[k];
    return values(pre.approvals, k).length === 1 && entryDiagnostic("approvals", k, v) === null && str(v.role) === "base" && v.revoked === undefined;
  });
  return bases.length === 1 && bases[0] === P[label].ref ? "service" : "other";
}

/** The §4 diagnostic of change `r` (null when admitted), and its writer class. */
function admit(r) {
  const found = new Set();
  const d = r.decoded;
  if (r.actor !== actorOf(r.writer)) return { diag: "CHANGE_ACTOR_MISMATCH", cls: null };
  if (r.deps.length === 0) {
    if (d.seq !== 1) return { diag: "INVALID_AUTOMERGE_BYTES", cls: null };
    r.tops = new Set(["profile, meta"]);
    if (r.writer !== CONTROL[r.controlRef].owner || r.unitSeq !== 1) return { diag: "INVALID_ROOT", cls: writerClass(r.writer, r.controlRef, {}) };
    const [doc] = A.applyChanges(A.init(), [r.bytes]);
    const ok = JSON.stringify(Object.keys(doc).sort()) === JSON.stringify([...ROOT_KEYS].sort()) && str(doc.profile) === PROFILE &&
      isMap(doc.meta) && JSON.stringify(Object.keys(doc.meta).sort()) === '["attemptId","createdAt"]' &&
      ROOT_KEYS.slice(2).every((k) => isMap(doc[k]) && Object.keys(doc[k]).length === 0);
    return { diag: ok ? null : "INVALID_ROOT", cls: "root" };
  }
  const pre = historyOf(r.deps);
  const [post] = A.applyChanges(A.clone(pre), [r.bytes]);
  const cls = writerClass(r.writer, r.controlRef, pre);
  // Positions: every object of the causal history, by the path of the operations that created it.
  const pos = new Map();
  const index = (op, id) => {
    if (!op.action.startsWith("make")) return;
    const parent = op.obj === "_root" ? [] : pos.get(op.obj).path;
    pos.set(id, { path: [...parent, op.key ?? "#"], madeHere: false });
  };
  for (const b of A.getAllChanges(pre)) { const h = A.decodeChange(b); h.ops.forEach((op, i) => index(op, `${h.startOp + i}@${h.actor}`)); }
  const everHeld = new Set();
  for (const b of A.getAllChanges(pre)) for (const op of A.decodeChange(b).ops) if (op.obj !== "_root" && pos.get(op.obj)?.path.length === 1) everHeld.add(`${pos.get(op.obj).path[0]}/${op.key}`);
  const created = new Set(), deleted = new Set(), touched = new Set();
  r.tops = new Set();
  const forbid = () => found.add("FORBIDDEN_MUTATION");
  if (cls === "other") found.add("UNAUTHORIZED_WRITER");
  d.ops.forEach((op, i) => {
    const id = `${d.startOp + i}@${d.actor}`;
    if (op.action === "makeText") found.add("INVALID_FIELD_TYPE");
    if (op.obj === "_root") {
      r.tops.add(["profile", "meta"].includes(op.key) ? "profile, meta" : "root keys");
      if (op.key === "profile" || op.key === "meta") found.add("IMMUTABLE_FIELD_MUTATED");
      else found.add(ROOT_KEYS.includes(op.key) ? "CONTAINER_REPLACED" : "UNKNOWN_ROOT_KEY");
      return index(op, id);
    }
    const at = pos.get(op.obj);
    const path = [...at.path, op.key ?? "#"];
    const [top, key, field] = path;
    index(op, id);
    r.tops.add(top === "meta" ? "profile, meta" : top);
    if (pos.has(id)) pos.get(id).madeHere = true;
    if (top === "meta") return void found.add("IMMUTABLE_FIELD_MUTATED");
    if (!ROW[top].includes(cls)) return void found.add("UNAUTHORIZED_WRITER");
    if (WHOLE.has(top)) return void touched.add(top);
    if (path.length === 2) {
      // An entry: created, deleted or replaced.
      const preEntry = pre[top][key];
      if (op.action === "set" && (op.pred ?? []).length > 0 && isMap(preEntry)) return void found.add("CONTAINER_REPLACED");
      touched.add(`${top}/${key}`);
      if (op.action === "del") {
        deleted.add(`${top}/${key}`);
        const absentAfter = (t) => post[t]?.[key] === undefined;
        const ok = {
          approvals: false, bindings: cls === "service",
          pairing: cls === "service" && absentAfter("requests") && preEntry && (pre.approvals[str(preEntry.principal)] !== undefined || ["cancelled", "rejected"].includes(eventState(pre, key)) && isFinal(pre, key)),
          questions: cls === "service" && preEntry && (preEntry.resolved !== undefined || preEntry.superseded !== undefined),
          requests: cls === "service" && isFinal(pre, key),
          answers: cls === "service" && preEntry && (pre.questions[str(preEntry.qid)] === undefined || pre.questions[str(preEntry.qid)].resolved !== undefined || pre.questions[str(preEntry.qid)].superseded !== undefined),
          cancels: cls === "service" && absentAfter("requests"),
          events: cls === "service" && isFinal(pre, key) && absentAfter("requests") && absentAfter("answers"),
        }[top];
        return void (ok || forbid());
      }
      if (created.has(`${top}/${key}`)) return forbid();
      created.add(`${top}/${key}`);
      const fresh = !everHeld.has(`${top}/${key}`);
      const ok = {
        approvals: fresh, bindings: cls === "service",
        pairing: fresh && str(pre.requests[key]?.op) === "pair-section",
        questions: fresh, requests: fresh && cls !== "service", answers: fresh && cls !== "service",
        cancels: fresh && cls !== "service" && pre.requests[key] !== undefined,
        events: fresh && (pre.requests[key] !== undefined || pre.answers[key] !== undefined),
      }[top];
      return void (ok || forbid());
    }
    // A write below an entry: part of a creation, or a mutation the row allows.
    touched.add(`${top}/${key}`);
    if (at.madeHere || created.has(`${top}/${key}`)) return;
    const preEntry = pre[top][key];
    const ok = {
      approvals: path.length === 3 && field === "revoked" && op.action === "makeMap" && values(preEntry, "revoked").length === 0,
      bindings: true,
      questions: path.length === 3 && ["resolved", "superseded"].includes(field) && op.action === "makeMap" && preEntry.resolved === undefined && preEntry.superseded === undefined,
      events: path.length === 3 && !isFinal(pre, key) && (op.action === "del" ? ["code", "detail"].includes(field) : op.action === "set" && (field === "state"
        ? EVENT_STATES.indexOf(str(op.value)) >= EVENT_STATES.indexOf(eventState(pre, key)) : ["code", "detail", "at"].includes(field))),
    }[top];
    if (!ok) forbid();
  });
  for (const k of created) if (deleted.has(k)) forbid();
  // SC4 and SC7 on the post-state of the entries the change creates or writes.
  for (const t of touched) {
    const [top, key] = t.split("/");
    const v = key === undefined ? post[top] : post[top][key];
    if (v === undefined) continue;
    const diag = entryDiagnostic(top, key, v);
    if (diag) found.add(diag);
    if (size(v) > (top === "pairing" ? 8192 : 4096)) found.add("LIMIT_EXCEEDED");
  }
  if ([...created].some((k) => k.startsWith("requests/")) && (openRequests(post) > 32 || openRequests(post, "pair-section") > 1)) found.add("LIMIT_EXCEEDED");
  return { diag: ADMISSION_ORDER.find((x) => found.has(x)) ?? null, cls };
}

/** Records a change by `writer` on `doc` (a document of its causal history) and its admission. */
function change(name, doc, writer, controlRef, fn) {
  const next = A.change(A.clone(doc, { actor: actorOf(writer) }), { time: 0 }, fn);
  const bytes = Buffer.from(A.getLastLocalChange(next));
  const d = A.decodeChange(bytes);
  const r = { name, writer, controlRef, bytes, decoded: d, hash: d.hash, deps: d.deps, actor: d.actor, unitSeq: d.seq };
  if (CHANGES.has(name) || [...CHANGES.values()].some((x) => x.hash === d.hash)) throw new Error(`${name}: duplicate or empty change`);
  CHANGES.set(name, r);
  Object.assign(r, admit(r));
  r.doc = r.diag === null ? next : null;
  return r;
}

// ---------------------------------------------------------------------------
// Cases.
// ---------------------------------------------------------------------------

const CASES = [];
const uid = (n) => `0196f2a0-0000-7000-8000-${String(n).padStart(12, "0")}`;
const T0 = "2026-11-19T10:00:00Z";
const RID = { r1: uid(1), r2: uid(2), r3: uid(3), r4: uid(4), r5: uid(5), r6: uid(6), q1: uid(11), q2: uid(12), a1: uid(21), a2: uid(22), none: uid(99) };
const approval = (label, role, resource, generation, origin) => ({ role, resource, principal: P[label].ref, certDigest: b64u(sha(`LFCP-TV-SC-DIGEST-${label}`)), certId: b64u(sha(`LFCP-TV-SC-CERT-${label}`)), generation, origin, at: T0 });
const SERVICE = { instance: "inst-1", kind: "apple-reminders", label: "MacBook Air", platform: "macos", app: "0.6.0", protocol: { v: 1, ops: ["preview", "turn-on", "turn-off", "resume-binding", "remove", "retry-helper", "pause", "resume", "check", "pair-section"], questionKinds: ["mass-delete"] }, artifactSliceId: "arm64", macos: "15.1", cert: { state: "certified", manifestSeq: 1, certTestMode: false }, capacity: { sections: 1, max: 8, devicesFree: 20 } };
const STATUS = { state: "running", since: T0, heartbeatAt: T0 };
const BINDING = { state: "on", generation: 1, list: "Groceries", filter: "all", pending: { toApple: 0, toLfcp: 0 }, refused: 0, unconfirmed: 0 };
const request = (op, extra = {}) => ({ op, binding: RES.X, generation: 1, args: {}, client: { app: "0.8.0", protocol: 1 }, at: T0, ...extra });
const QUESTION = { binding: RES.X, generation: 1, kind: "mass-delete", anomalyId: "an-1", snapshotHash: "sh-1", items: ["Milk", "Bread"], counts: { deleted: 12 }, options: ["apply", "restore"], at: T0 };
const LINK = "lfcp://pair/test-link-of-J_X";
const PAIRING = { descriptor: b64u(P.D_X.descriptor), principal: P.D_X.ref, fp: fp("D_X") };

function emit(r, want, section, description) {
  const got = r.diag;
  if (got !== want) throw new Error(`${r.name}: reference admission gives ${got}, the profile text ${want}`);
  const history = [...CHANGES.values()].filter((x) => x.doc !== null && x !== r && x.name !== r.name && isAncestor(x, r)).map((x) => ({ case: x.name, field: "automerge_change", in: "inputs" }));
  CASES.push({
    id: r.name, type: "validation", kind: "profile_change", description,
    rule: { section: `${SPEC} ${section}`, text: want === null ? "Admitted: every operation is one its row of §3 admits for the writer's class, and the entries it writes are valid (§5)." : `Refused whole as PROFILE_INVALID; the first diagnostic in the order of §4 is ${want}.` },
    inputs: { writer: r.writer, writer_ref: P[r.writer].ref, writer_class: r.cls ?? "other", control_ref: r.controlRef, automerge_actor: r.actor, automerge_seq: r.decoded.seq, unit_actor_seq: r.unitSeq, change_hash: r.hash, deps: r.deps, automerge_change: { hex: hex(r.bytes) } },
    context: { history },
    expected: want === null ? { valid: true } : { valid: false, disposition: "reject", error: { code: "PROFILE_INVALID", diagnostic: want } },
  });
  return r;
}
function isAncestor(x, r) {
  const byHash = new Map([...CHANGES.values()].map((c) => [c.hash, c]));
  const stack = [...r.deps], seen = new Set();
  while (stack.length) {
    const h = stack.pop();
    if (seen.has(h)) continue;
    seen.add(h);
    if (h === x.hash) return true;
    stack.push(...byHash.get(h).deps);
  }
  return false;
}
/** A change that the profile admits (want null) or refuses with `want`; `on` is the case whose post-state it builds on. */
const merged = (...rs) => ({ doc: rs.slice(1).reduce((d, r) => A.merge(d, A.clone(r.doc)), A.clone(rs[0].doc)) });
const ok = (name, on, writer, section, description, fn, ctl = "CS1_live") => emit(change(name, on.doc, writer, ctl, fn), null, section, description);
const no = (name, on, writer, want, section, description, fn, ctl = "CS1_live") => emit(change(name, on.doc, writer, ctl, fn), want, section, description);

// ---- The initial change and the root (§2.2, SC0–SC3) ----
const initial = (extra = (d) => d) => (d) => {
  put(d, "profile", PROFILE);
  put(d, "meta", { attemptId: "attempt-1", createdAt: T0 });
  for (const k of ROOT_KEYS.slice(2)) d[k] = {};
  extra(d);
};
const EMPTY = { doc: A.init() };
const M0 = emit(change("init", EMPTY.doc, "R", "CS0_genesis", initial()), null, "§2.2, §4 SC0", "The initial change of C by its Genesis owner R: profile, meta and eleven empty maps");
emit(change("init_by_personal", EMPTY.doc, "A", "CS1_live", initial()), "INVALID_ROOT", "§2.2, §4 SC0", "The same content written without dependencies by the personal device A");
emit(change("init_missing_lifecycle", EMPTY.doc, "R", "CS0_genesis", initial((d) => delete d.lifecycle)), "INVALID_ROOT", "§2.2, §4 SC0", "An initial change without the root key lifecycle");
emit(change("init_requests_not_empty", EMPTY.doc, "R", "CS0_genesis", initial((d) => put(d.requests, RID.r1, request("check")))), "INVALID_ROOT", "§2.2, §4 SC0", "An initial change whose requests map is not empty");
no("profile_rewritten", M0, "R", "IMMUTABLE_FIELD_MUTATED", "§4 SC1", "R writes profile = org.openlfcp.service-control.v2 after the initial change", (d) => put(d, "profile", "org.openlfcp.service-control.v2"));
no("meta_rewritten", M0, "A", "IMMUTABLE_FIELD_MUTATED", "§4 SC1", "A writes meta.attemptId", (d) => put(d.meta, "attemptId", "attempt-2"));
no("container_replaced", M0, "R", "CONTAINER_REPLACED", "§4 SC2", "R replaces the requests map with a new empty map", (d) => { d.requests = {}; });
no("unknown_root_key", M0, "A", "UNKNOWN_ROOT_KEY", "§4 SC3, §11", "A creates the root key extensions", (d) => { d.extensions = {}; });

// ---- Approvals and the class service (§2.3, §7) ----
const M1 = ok("base_approval", M0, "A", "§3 approvals, §7.1", "A writes approvals[p:<B>], the base approval of B (phase A3)", (d) => put(d.approvals, P.B.ref, approval("B", "base", RES.C, 0, "attempt-1")));
no("approval_by_service_device_before_class", M0, "B", "UNAUTHORIZED_WRITER", "§2.3, §4 SC5", "B writes its own base approval: without an approval in its pre-state B is of class other", (d) => put(d.approvals, P.B.ref, approval("B", "base", RES.C, 0, "attempt-1")));
const M2 = ok("service_fill", M1, "B", "§2.3, §3 service/status/bindings, §5 rule 1", "B, whose base approval is in the change's causal history, fills service and status and creates bindings[X]", (d) => { for (const [k, v] of Object.entries(SERVICE)) put(d.service, k, v); for (const [k, v] of Object.entries(STATUS)) put(d.status, k, v); put(d.bindings, RES.X, BINDING); });
no("service_without_approval_in_history", M0, "B", "UNAUTHORIZED_WRITER", "§2.3, §4 SC5", "B writes status on the initial change only: the approval exists elsewhere but not in this change's causal history", (d) => { for (const [k, v] of Object.entries(STATUS)) put(d.status, k, v); });
no("service_bound_but_revoked", M1, "B", "UNAUTHORIZED_WRITER", "§2.3, §4 SC5", "B writes status with control_ref CS2_b_revoked, where B is revoked in C's chain: the approval alone gives no class", (d) => { for (const [k, v] of Object.entries(STATUS)) put(d.status, k, v); }, "CS2_b_revoked");
no("service_device_without_own_approval", M1, "B2", "UNAUTHORIZED_WRITER", "§2.3, §4 SC5", "B2, bound in C with kind 1, writes status while the only base approval names B", (d) => put(d.status, "message", "hi"));
no("section_installation_writes", M1, "D_X", "UNAUTHORIZED_WRITER", "§2.3, §4 SC5", "The section installation D_X (scope [X]) writes status", (d) => put(d.status, "message", "hi"));
no("pairing_device_writes", M1, "J_X", "UNAUTHORIZED_WRITER", "§2.3, §4 SC5", "The pairing device J_X (kind 2) creates a request", (d) => put(d.requests, RID.r6, request("check")));
no("foreign_root_device_writes", M1, "BOB_D", "UNAUTHORIZED_WRITER", "§2.3, §4 SC5", "BOB_D, a personal device of another root, creates a request", (d) => put(d.requests, RID.r6, request("check")));
no("foreign_root_writes_approval", M1, "BOB", "UNAUTHORIZED_WRITER", "§2.3, §4 SC5", "BOB, another root and a non-device member of C, writes an approval", (d) => put(d.approvals, P.B2.ref, approval("B2", "base", RES.C, 0, "attempt-1")));
no("pairing_device_replaces_container", M1, "J_X", "CONTAINER_REPLACED", "§4 SC2, order", "J_X replaces the events map: SC2 is reported before SC5", (d) => { d.events = {}; });
no("approval_rewritten", M1, "A", "FORBIDDEN_MUTATION", "§3 approvals, §4 SC6", "A rewrites approvals[p:<B>].certId", (d) => put(d.approvals[P.B.ref], "certId", b64u(sha("other"))));
no("approval_deleted", M1, "R", "FORBIDDEN_MUTATION", "§3 approvals, §4 SC6", "R deletes approvals[p:<B>]", (d) => { delete d.approvals[P.B.ref]; });
no("approval_created_twice", M1, "R", "FORBIDDEN_MUTATION", "§3 approvals, §4 SC6", "R writes approvals[p:<B>] again as a new map", (d) => put(d.approvals, P.B.ref, approval("B", "base", RES.C, 0, "attempt-1")));
no("approval_base_wrong_resource", M0, "A", "INVALID_ENUM_VALUE", "§4 SC4, §5", "A writes a base approval whose resource is X, not C", (d) => put(d.approvals, P.B.ref, approval("B", "base", RES.X, 0, "attempt-1")));
no("approval_key_mismatch", M0, "A", "INVALID_KEY", "§4 SC4, §5", "A writes approvals[p:<B>] whose principal is p:<B2>", (d) => put(d.approvals, P.B.ref, approval("B2", "base", RES.C, 0, "attempt-1")));

// Two base approvals (§2.3, §7.3), revocation and the class at the change's causal history.
const T1 = ok("second_base_approval", M2, "R", "§3 approvals, §7.3", "R writes a second base approval, for B2", (d) => put(d.approvals, P.B2.ref, approval("B2", "base", RES.C, 0, "attempt-2")));
no("two_bases_service_refused", T1, "B", "UNAUTHORIZED_WRITER", "§2.3, §7.3", "B writes status.heartbeatAt with two valid base approvals in its pre-state", (d) => put(d.status, "heartbeatAt", "2026-11-19T10:30:00Z"));
no("two_bases_other_refused", T1, "B2", "UNAUTHORIZED_WRITER", "§2.3, §7.3", "B2 writes status.heartbeatAt with two valid base approvals in its pre-state", (d) => put(d.status, "heartbeatAt", "2026-11-19T10:30:00Z"));
const T2 = ok("revoke_second_base", T1, "A", "§3 approvals, §7.2", "A creates approvals[p:<B2>].revoked", (d) => put(d.approvals[P.B2.ref], "revoked", { at: T0 }));
ok("one_base_after_revocation", T2, "B", "§2.3, §7.3", "B writes status.heartbeatAt after the revocation of B2's approval", (d) => put(d.status, "heartbeatAt", "2026-11-19T10:30:00Z"));
no("revoked_twice", T2, "R", "FORBIDDEN_MUTATION", "§3 approvals, §4 SC6", "R creates revoked again in approvals[p:<B2>]", (d) => put(d.approvals[P.B2.ref], "revoked", { at: T0 }));
const T3 = ok("revoke_base_b", M2, "A", "§3 approvals, §7.2", "A revokes the base approval of B", (d) => put(d.approvals[P.B.ref], "revoked", { at: T0 }));
const Rc = ok("service_concurrent_with_revocation", M2, "B", "§2.3", "B writes status.message concurrently with revoke_base_b: its pre-state holds the approval unrevoked", (d) => put(d.status, "message", "syncing"));
no("service_after_revocation", merged(Rc, T3), "B", "UNAUTHORIZED_WRITER", "§2.3", "B, having received revoke_base_b, writes status.message on both heads", (d) => put(d.status, "message", "stopped"));

// ---- service, status, lifecycle, bindings (§3) ----
no("status_by_personal", M2, "A", "UNAUTHORIZED_WRITER", "§3 status, §4 SC5", "A writes status.state", (d) => put(d.status, "state", "paused"));
no("lifecycle_by_root", M2, "R", "UNAUTHORIZED_WRITER", "§3 lifecycle, §4 SC5", "R writes lifecycle.op", (d) => put(d.lifecycle, "op", "remove"));
ok("lifecycle_by_service", M2, "B", "§3 lifecycle, §7.2", "B writes lifecycle = {op: remove, bindings: [{X, 1}], at}", (d) => { put(d.lifecycle, "op", "remove"); put(d.lifecycle, "bindings", [{ binding: RES.X, generation: 1 }]); put(d.lifecycle, "at", T0); });
ok("status_field_deleted", M2, "B", "§3 status", "B deletes status.since and writes it again in one change", (d) => { delete d.status.since; put(d.status, "since", "2026-11-19T11:00:00Z"); });
no("status_first_write_incomplete", M1, "B", "MISSING_REQUIRED_FIELD", "§4 SC4, §5 rule 1", "B's first status write lacks heartbeatAt", (d) => { put(d.status, "state", "running"); put(d.status, "since", T0); });
no("status_replaced_by_scalar", M2, "B", "CONTAINER_REPLACED", "§4 SC2", "B replaces status with a string", (d) => put(d, "status", "running"));
ok("binding_rewritten", M2, "B", "§3 bindings", "B writes bindings[X].state and pending.toApple", (d) => { put(d.bindings[RES.X], "state", "partly-synced"); put(d.bindings[RES.X].pending, "toApple", 3); });
ok("binding_deleted", M2, "B", "§3 bindings", "B deletes bindings[X]", (d) => { delete d.bindings[RES.X]; });
no("binding_by_personal", M2, "A", "UNAUTHORIZED_WRITER", "§3 bindings, §4 SC5", "A creates bindings[Y]", (d) => put(d.bindings, RES.Y, BINDING));

// ---- Requests, events, unknown op (§3, §6) ----
const M3 = ok("request_created", M2, "A", "§3 requests, §6.1", "A creates requests[r1] = turn-off of X, generation 1", (d) => put(d.requests, RID.r1, request("turn-off")));
ok("request_by_root", M2, "R", "§3 requests", "R creates requests[r6] = check", (d) => put(d.requests, RID.r6, request("check", { binding: undefined })));
no("request_by_service", M2, "B", "FORBIDDEN_MUTATION", "§3 requests, §4 SC6", "B creates a request", (d) => put(d.requests, RID.r6, request("check")));
no("request_created_twice", M3, "R", "FORBIDDEN_MUTATION", "§3 requests, §4 SC6", "R writes requests[r1] again as a new map", (d) => put(d.requests, RID.r1, request("turn-on")));
no("request_rewritten", M3, "A", "FORBIDDEN_MUTATION", "§3 requests, §4 SC6", "A rewrites requests[r1].op", (d) => put(d.requests[RID.r1], "op", "turn-on"));
no("request_deleted_by_personal", M3, "A", "FORBIDDEN_MUTATION", "§3 requests, §4 SC6", "A deletes its own request", (d) => { delete d.requests[RID.r1]; });
no("request_deleted_without_event", M3, "B", "FORBIDDEN_MUTATION", "§3 requests, §4 SC6", "B deletes requests[r1], which has no event", (d) => { delete d.requests[RID.r1]; });
no("request_op_upper_case", M2, "A", "INVALID_ENUM_VALUE", "§4 SC4, §5", "A creates a request with op Turn-Off", (d) => put(d.requests, RID.r6, request("Turn-Off")));
no("request_op_33_chars", M2, "A", "INVALID_ENUM_VALUE", "§4 SC4, §5", "A creates a request whose op has 33 characters", (d) => put(d.requests, RID.r6, request("a".repeat(33))));
no("request_key_not_uuidv7", M2, "A", "INVALID_KEY", "§4 SC4, §5", "A creates requests[r-1]", (d) => put(d.requests, "r-1", request("check")));
no("request_text_field", M2, "A", "INVALID_FIELD_TYPE", "§4 SC4", "A creates a request whose args.note is collaborative Text", (d) => put(d.requests, RID.r6, request("check", { args: { note: new Text("hi") } })));
no("request_too_large", M2, "A", "LIMIT_EXCEEDED", "§4 SC7, Sizes", "A creates a request whose entry is larger than 4096 bytes", (d) => put(d.requests, RID.r6, request("check", { args: { pad: "x".repeat(4096) } })));
const M4 = ok("event_received", M3, "B", "§3 events, §6.2", "B creates events[r1] = received", (d) => put(d.events, RID.r1, { state: "received", at: T0 }));
no("event_by_personal", M3, "A", "UNAUTHORIZED_WRITER", "§3 events, §4 SC5", "A creates events[r1]", (d) => put(d.events, RID.r1, { state: "received", at: T0 }));
no("event_without_request", M2, "B", "FORBIDDEN_MUTATION", "§3 events, §4 SC6", "B creates events[none] for which there is no request or answer", (d) => put(d.events, RID.none, { state: "received", at: T0 }));
no("event_created_twice", M4, "B", "FORBIDDEN_MUTATION", "§3 events, §4 SC6", "B writes events[r1] again as a new map", (d) => put(d.events, RID.r1, { state: "executing", at: T0 }));
no("event_bad_state", M3, "B", "INVALID_ENUM_VALUE", "§4 SC4, §5", "B creates events[r1] with state done", (d) => put(d.events, RID.r1, { state: "done", at: T0 }));
const M4b = ok("event_executing_retryable", M4, "B", "§3 events, §6.2", "B writes executing with the retryable code network", (d) => { put(d.events[RID.r1], "state", "executing"); put(d.events[RID.r1], "code", "network"); });
ok("event_same_state_again", M4b, "B", "§3 events, §6.2", "B writes executing again with code helper_unavailable (same state, later at)", (d) => { put(d.events[RID.r1], "state", "executing"); put(d.events[RID.r1], "code", "helper_unavailable"); put(d.events[RID.r1], "at", "2026-11-19T10:05:00Z"); });
no("event_backward", M4b, "B", "FORBIDDEN_MUTATION", "§3 events, §4 SC6, §6.2", "B writes received over executing", (d) => put(d.events[RID.r1], "state", "received"));
no("event_unknown_field_write", M4b, "B", "FORBIDDEN_MUTATION", "§3 events, §4 SC6", "B writes an unnamed field into an existing event", (d) => put(d.events[RID.r1], "progress", 50));
no("request_deleted_before_final", M4b, "B", "FORBIDDEN_MUTATION", "§3 requests, §4 SC6", "B deletes requests[r1] and events[r1] while the event is executing", (d) => { delete d.requests[RID.r1]; delete d.events[RID.r1]; });
const M5 = ok("event_applied", M4b, "B", "§3 events, §6.2", "B writes applied (final)", (d) => { put(d.events[RID.r1], "state", "applied"); delete d.events[RID.r1].code; });
ok("event_code_deleted", M4b, "B", "§3 events, §6.2", "B deletes the retryable code of a non-final event", (d) => { delete d.events[RID.r1].code; });
no("event_after_final", M5, "B", "FORBIDDEN_MUTATION", "§3 events, §4 SC6, §6.2", "B writes failed over applied", (d) => put(d.events[RID.r1], "state", "failed"));
no("event_detail_after_final", M5, "B", "FORBIDDEN_MUTATION", "§3 events, §4 SC6", "B writes detail into a final event", (d) => put(d.events[RID.r1], "detail", "late"));
no("event_deleted_with_request_present", M5, "B", "FORBIDDEN_MUTATION", "§3 events, §4 SC6", "B deletes the final events[r1] while requests[r1] stays", (d) => { delete d.events[RID.r1]; });
const M6 = ok("request_deleted_after_final", M5, "B", "§3 requests, events, §9", "B deletes requests[r1] and events[r1] after the final event", (d) => { delete d.requests[RID.r1]; delete d.events[RID.r1]; });
no("request_recreated_after_deletion", M6, "A", "FORBIDDEN_MUTATION", "§3 requests, §10", "A creates requests[r1] again after its deletion: the rid once held a value", (d) => put(d.requests, RID.r1, request("turn-off")));
no("create_and_delete_same_entry", M2, "B", "FORBIDDEN_MUTATION", "§3", "B creates bindings[Y] and deletes it in the same change", (d) => { put(d.bindings, RES.Y, BINDING); delete d.bindings[RES.Y]; });
const U1 = ok("unknown_op_request", M2, "A", "§4, §6.1, §11", "A creates requests[r2] with the unknown op export-logs: admitted", (d) => put(d.requests, RID.r2, request("export-logs", { args: { days: 7 } })));
const U2 = ok("unknown_op_rejected", U1, "B", "§6.1, §11", "B writes events[r2] = rejected{unsupported_op} and nothing else", (d) => put(d.events, RID.r2, { state: "rejected", code: "unsupported_op", at: T0 }));

// ---- Cancellation (§6.3) ----
const K1 = ok("request_turn_on", M2, "A", "§3 requests", "A creates requests[r4] = turn-on", (d) => put(d.requests, RID.r4, request("turn-on", { args: { previewId: "pv-1", planHash: "ph-1" } })));
const K2 = ok("cancel_created", K1, "A", "§3 cancels, §6.3", "A creates cancels[r4] = {user}", (d) => put(d.cancels, RID.r4, { reason: "user", at: T0 }));
no("cancel_without_request", M2, "A", "FORBIDDEN_MUTATION", "§3 cancels, §4 SC6", "A cancels a rid that has no request", (d) => put(d.cancels, RID.none, { reason: "user", at: T0 }));
no("cancel_by_service", K1, "B", "FORBIDDEN_MUTATION", "§3 cancels, §4 SC6", "B creates cancels[r4]", (d) => put(d.cancels, RID.r4, { reason: "user", at: T0 }));
no("cancel_by_pairing_device", K1, "J_X", "UNAUTHORIZED_WRITER", "§3 cancels, §4 SC5", "J_X creates cancels[r4]", (d) => put(d.cancels, RID.r4, { reason: "user", at: T0 }));
no("cancel_created_twice", K2, "R", "FORBIDDEN_MUTATION", "§3 cancels, §4 SC6", "R writes cancels[r4] again", (d) => put(d.cancels, RID.r4, { reason: "user", at: T0 }));
no("cancel_bad_reason", K1, "A", "INVALID_ENUM_VALUE", "§4 SC4, §5", "A creates cancels[r4] with reason oops", (d) => put(d.cancels, RID.r4, { reason: "oops", at: T0 }));
no("cancel_deleted_with_request_present", K2, "B", "FORBIDDEN_MUTATION", "§3 cancels, §4 SC6", "B deletes cancels[r4] while requests[r4] stays", (d) => { delete d.cancels[RID.r4]; });
const K3 = ok("event_cancelled", K2, "B", "§6.3", "B writes events[r4] = cancelled (the cancel was seen before received)", (d) => put(d.events, RID.r4, { state: "cancelled", at: T0 }));
ok("cancelled_request_deleted", K3, "B", "§3 requests, cancels, events", "B deletes requests[r4], cancels[r4] and events[r4] in one change", (d) => { delete d.requests[RID.r4]; delete d.cancels[RID.r4]; delete d.events[RID.r4]; });

// ---- Questions and answers (§3, §10) ----
const Q1 = ok("question_created", M2, "B", "§3 questions", "B creates questions[q1]", (d) => put(d.questions, RID.q1, QUESTION));
no("question_by_personal", M2, "A", "UNAUTHORIZED_WRITER", "§3 questions, §4 SC5", "A creates a question", (d) => put(d.questions, RID.q1, QUESTION));
no("question_rewritten", Q1, "B", "FORBIDDEN_MUTATION", "§3 questions, §4 SC6", "B rewrites questions[q1].kind", (d) => put(d.questions[RID.q1], "kind", "other"));
no("question_deleted_open", Q1, "B", "FORBIDDEN_MUTATION", "§3 questions, §4 SC6", "B deletes questions[q1], which holds neither resolved nor superseded", (d) => { delete d.questions[RID.q1]; });
no("question_six_items", M2, "B", "LIMIT_EXCEEDED", "§4 SC7, §5", "B creates a question with six items", (d) => put(d.questions, RID.q2, { ...QUESTION, items: ["a", "b", "c", "d", "e", "f"] }));
no("question_example_81", M2, "B", "LIMIT_EXCEEDED", "§4 SC7, §5", "B creates a question whose item has 81 Unicode scalar values", (d) => put(d.questions, RID.q2, { ...QUESTION, items: ["é".repeat(81)] }));
ok("question_example_80", M2, "B", "§4 SC7, §5", "B creates a question whose item has 80 Unicode scalar values (160 bytes)", (d) => put(d.questions, RID.q2, { ...QUESTION, items: ["é".repeat(80)] }));
const Q2 = ok("answer_created", Q1, "A", "§3 answers", "A creates answers[a1] for q1", (d) => put(d.answers, RID.a1, { qid: RID.q1, snapshotHash: "sh-1", choice: "restore", at: T0 }));
no("answer_by_service", Q1, "B", "FORBIDDEN_MUTATION", "§3 answers, §4 SC6", "B creates an answer", (d) => put(d.answers, RID.a1, { qid: RID.q1, snapshotHash: "sh-1", choice: "restore", at: T0 }));
no("answer_by_foreign_root", Q1, "BOB_D", "UNAUTHORIZED_WRITER", "§3 answers, §4 SC5", "BOB_D creates an answer", (d) => put(d.answers, RID.a1, { qid: RID.q1, snapshotHash: "sh-1", choice: "restore", at: T0 }));
no("answer_rewritten", Q2, "A", "FORBIDDEN_MUTATION", "§3 answers, §4 SC6", "A rewrites answers[a1].choice", (d) => put(d.answers[RID.a1], "choice", "apply"));
no("answer_deleted_open_question", Q2, "B", "FORBIDDEN_MUTATION", "§3 answers, §4 SC6", "B deletes answers[a1] while q1 is open", (d) => { delete d.answers[RID.a1]; });
const ans = (aid, choice) => ({ qid: RID.q1, snapshotHash: "sh-1", choice, at: T0 });
const Q2b = ok("answer_concurrent", Q1, "R", "§3 answers, §10", "R creates answers[a2] for q1 concurrently with answer_created", (d) => put(d.answers, RID.a2, ans(RID.a2, "apply")));
const Q3 = ok("question_resolved", merged(Q2, Q2b), "B", "§3 questions, events, §10", "B, holding both answers, writes questions[q1].resolved with a1, events[a1] = applied and events[a2] = rejected{already_answered}", (d) => {
  put(d.events, RID.a1, { state: "applied", at: T0 });
  put(d.events, RID.a2, { state: "rejected", code: "already_answered", at: T0 });
  put(d.questions[RID.q1], "resolved", { answerId: RID.a1, choice: "restore", at: T0 });
});
no("question_superseded_after_resolved", Q3, "B", "FORBIDDEN_MUTATION", "§3 questions, §4 SC6", "B writes superseded into a resolved question", (d) => put(d.questions[RID.q1], "superseded", { by: "an-2" }));
ok("answered_question_deleted", Q3, "B", "§3 questions, answers, events, §9", "B deletes questions[q1], both answers and their events", (d) => { delete d.questions[RID.q1]; for (const id of [RID.a1, RID.a2]) { delete d.answers[id]; delete d.events[id]; } });
const Qs = ok("question_superseded", Q1, "B", "§3 questions", "B writes questions[q1].superseded (the anomaly changed) concurrently with answer_created", (d) => put(d.questions[RID.q1], "superseded", { by: "an-2" }));
const Qs2 = ok("answer_to_superseded_rejected", merged(Qs, Q2), "B", "§3 events, §6.2, §10", "B, having received answer_created after superseding q1, writes events[a1] = rejected{snapshot_changed}", (d) => put(d.events, RID.a1, { state: "rejected", code: "snapshot_changed", at: T0 }));
no("question_resolved_after_superseded", merged(Qs, Q2), "B", "FORBIDDEN_MUTATION", "§3 questions, §4 SC6", "B writes resolved into a superseded question", (d) => put(d.questions[RID.q1], "resolved", { answerId: RID.a1, choice: "restore", at: T0 }));
ok("superseded_answer_deleted", Qs2, "B", "§3 answers, events", "B deletes answers[a1] and events[a1]: the question is superseded", (d) => { delete d.answers[RID.a1]; delete d.events[RID.a1]; });

// ---- Section pairing (§3 pairing, §8) ----
const S1 = ok("pair_section_request", M2, "A", "§8.1 step 1", "A creates requests[r3] = pair-section of X with args.link", (d) => put(d.requests, RID.r3, request("pair-section", { args: { link: LINK } })));
const S2 = ok("pairing_created", S1, "B", "§3 pairing, §8.1 step 2", "B writes pairing[r3] for D_X and events[r3] = request-ready", (d) => { put(d.pairing, RID.r3, PAIRING); put(d.events, RID.r3, { state: "request-ready", at: T0 }); });
no("pairing_by_personal", S1, "A", "UNAUTHORIZED_WRITER", "§3 pairing, §4 SC5", "A writes pairing[r3]", (d) => put(d.pairing, RID.r3, PAIRING));
no("pairing_for_other_op", M3, "B", "FORBIDDEN_MUTATION", "§3 pairing, §4 SC6", "B writes pairing[r1], whose request is turn-off", (d) => put(d.pairing, RID.r1, PAIRING));
no("pairing_rewritten", S2, "B", "FORBIDDEN_MUTATION", "§3 pairing, §4 SC6", "B rewrites pairing[r3].fp", (d) => put(d.pairing[RID.r3], "fp", fp("B2")));
no("pairing_bad_fingerprint", S1, "B", "INVALID_DESCRIPTOR", "§4 SC4, §5", "B writes pairing[r3] whose fp is B2's", (d) => put(d.pairing, RID.r3, { ...PAIRING, fp: fp("B2") }));
ok("pairing_entry_over_4096", S1, "B", "§4 SC7, Sizes", "B writes pairing[r3] with an unnamed field of 5000 bytes: within the pairing limit of 8192", (d) => put(d.pairing, RID.r3, { ...PAIRING, note: "x".repeat(5000) }));
no("second_open_pair_section", S1, "A", "LIMIT_EXCEEDED", "§4 SC7, §8.2", "A creates a second pair-section request while r3 is open", (d) => put(d.requests, RID.r5, request("pair-section", { binding: RES.Y, args: { link: LINK } })));
const S3 = ok("section_approval", S2, "A", "§7.1, §8.1 step 4", "A writes approvals[p:<D_X>], the section approval (A3)", (d) => put(d.approvals, P.D_X.ref, approval("D_X", "section", RES.X, 1, RID.r3)));
no("pairing_deleted_with_request_present", S3, "B", "FORBIDDEN_MUTATION", "§3 pairing, §4 SC6", "B deletes pairing[r3] while requests[r3] stays", (d) => { delete d.pairing[RID.r3]; });
const S4 = ok("pair_section_applied", S3, "B", "§8.1 step 4", "B writes events[r3] = applied", (d) => put(d.events[RID.r3], "state", "applied"));
ok("pairing_deleted_with_request", S4, "B", "§3 pairing, §9", "B deletes requests[r3], events[r3] and pairing[r3] in one change", (d) => { delete d.requests[RID.r3]; delete d.events[RID.r3]; delete d.pairing[RID.r3]; });
const S6 = ok("pair_section_cancel", S2, "A", "§6.3, §8.1 step 3", "A cancels r3 with reason mismatch before the consume", (d) => put(d.cancels, RID.r3, { reason: "mismatch", at: T0 }));
const S7 = ok("pair_section_cancelled", S6, "B", "§6.3", "B writes events[r3] = cancelled and forgets D_X", (d) => put(d.events[RID.r3], "state", "cancelled"));
ok("pairing_deleted_after_cancel", S7, "B", "§3 pairing, §9", "B deletes requests[r3], events[r3], cancels[r3] and pairing[r3]: no approval, the event is cancelled", (d) => { for (const k of ["requests", "events", "cancels", "pairing"]) delete d[k][RID.r3]; });
const S8 = ok("pair_section_applied_without_approval", S2, "B", "§6.2", "B writes events[r3] = applied although approvals[p:<D_X>] is absent", (d) => put(d.events[RID.r3], "state", "applied"));
no("pairing_deleted_without_approval", S8, "B", "FORBIDDEN_MUTATION", "§3 pairing, §4 SC6", "B deletes requests[r3], events[r3] and pairing[r3]: no approval and the final state is applied", (d) => { for (const k of ["requests", "events", "pairing"]) delete d[k][RID.r3]; });

// ---- Open-request limit (§4 SC7) ----
const L1 = ok("thirty_two_open_requests", M2, "A", "§4 SC7", "A creates 32 check requests in one change", (d) => { for (let k = 0; k < 32; k++) put(d.requests, uid(1000 + k), request("check")); });
no("thirty_third_open_request", L1, "R", "LIMIT_EXCEEDED", "§4 SC7", "R creates a 33rd open request", (d) => put(d.requests, RID.r6, request("check")));

// Concurrent creations may exceed the open-request limits; only a change that creates a request is refused for it.
const Pa = ok("pair_section_by_root", M2, "R", "§8.2, §4 SC7", "R creates requests[r5] = pair-section of Y concurrently with pair_section_request", (d) => put(d.requests, RID.r5, request("pair-section", { binding: RES.Y, args: { link: LINK } })));
ok("heartbeat_with_two_open_pair_sections", merged(S1, Pa), "B", "§4 SC7", "B writes status.heartbeatAt while two concurrent pair-section requests are open", (d) => put(d.status, "heartbeatAt", "2026-11-19T10:45:00Z"));
no("third_pair_section_after_merge", merged(S1, Pa), "A", "LIMIT_EXCEEDED", "§4 SC7", "A creates a third pair-section request on the merged state", (d) => put(d.requests, RID.r6, request("pair-section", { args: { link: LINK } })));
ok("request_unknown_field", M2, "A", "§2.1 Unknown fields, §11", "A creates a request with a field priority that version 1 does not name", (d) => put(d.requests, RID.r6, request("check", { priority: "high" })));

// ---- The remaining cells of the mutation table: each writer class at each position (§3, §4 SC1, SC5) ----
no("meta_by_service", M2, "B", "IMMUTABLE_FIELD_MUTATED", "§4 SC1", "B writes meta.createdAt", (d) => put(d.meta, "createdAt", "2026-11-20T00:00:00Z"));
no("profile_by_foreign_root_device", M2, "BOB_D", "IMMUTABLE_FIELD_MUTATED", "§4 SC1, order", "BOB_D writes profile: SC1 is reported before SC5", (d) => put(d, "profile", "org.openlfcp.service-control.v2"));
no("approval_by_service", M2, "B", "UNAUTHORIZED_WRITER", "§3 approvals, §4 SC5", "B, of class service, writes approvals[p:<D_X>]", (d) => put(d.approvals, P.D_X.ref, approval("D_X", "section", RES.X, 1, RID.r3)));
for (const [w, label] of [["R", "root"], ["A", "personal"], ["D_X", "section_installation"]]) {
  no(`service_info_by_${label}`, M2, w, "UNAUTHORIZED_WRITER", "§3 service, §4 SC5", `${w} writes service.label`, (d) => put(d.service, "label", "Mac"));
}
no("status_by_root", M2, "R", "UNAUTHORIZED_WRITER", "§3 status, §4 SC5", "R writes status.state", (d) => put(d.status, "state", "paused"));
no("binding_by_root", M2, "R", "UNAUTHORIZED_WRITER", "§3 bindings, §4 SC5", "R deletes bindings[X]", (d) => { delete d.bindings[RES.X]; });
no("binding_by_foreign_root_device", M2, "BOB_D", "UNAUTHORIZED_WRITER", "§3 bindings, §4 SC5", "BOB_D writes bindings[X].state", (d) => put(d.bindings[RES.X], "state", "off"));
no("pairing_by_root", S1, "R", "UNAUTHORIZED_WRITER", "§3 pairing, §4 SC5", "R writes pairing[r3]", (d) => put(d.pairing, RID.r3, PAIRING));
no("pairing_by_pairing_device", S1, "J_X", "UNAUTHORIZED_WRITER", "§3 pairing, §4 SC5", "J_X writes pairing[r3] for the device it pairs", (d) => put(d.pairing, RID.r3, PAIRING));
no("question_by_root", M2, "R", "UNAUTHORIZED_WRITER", "§3 questions, §4 SC5", "R creates a question", (d) => put(d.questions, RID.q2, QUESTION));
no("question_by_section_installation", Q1, "D_X", "UNAUTHORIZED_WRITER", "§3 questions, §4 SC5", "D_X writes questions[q1].superseded", (d) => put(d.questions[RID.q1], "superseded", { by: "an-2" }));
no("answer_deleted_by_root", Q3, "R", "FORBIDDEN_MUTATION", "§3 answers, §4 SC6", "R deletes answers[a1] of a resolved question", (d) => { delete d.answers[RID.a1]; });
no("event_by_root", M3, "R", "UNAUTHORIZED_WRITER", "§3 events, §4 SC5", "R creates events[r1]", (d) => put(d.events, RID.r1, { state: "cancelled", at: T0 }));
no("event_by_second_service_device", M3, "B2", "UNAUTHORIZED_WRITER", "§3 events, §4 SC5", "B2, without an approval, creates events[r1]", (d) => put(d.events, RID.r1, { state: "received", at: T0 }));
no("lifecycle_by_personal", M2, "A", "UNAUTHORIZED_WRITER", "§3 lifecycle, §4 SC5", "A writes lifecycle.op", (d) => put(d.lifecycle, "op", "uninstall"));
no("lifecycle_by_pairing_device", M2, "J_X", "UNAUTHORIZED_WRITER", "§3 lifecycle, §4 SC5", "J_X writes lifecycle.op", (d) => put(d.lifecycle, "op", "uninstall"));

// ---------------------------------------------------------------------------
// Replica transitions (behavioral).
// ---------------------------------------------------------------------------

/** Delivers the named changes in order to a replica holding `base`, as SOP §14.1: a change waits for its dependencies. */
function replay(names) {
  let doc = A.init();
  const admitted = [], refused = {};
  const all = [...CHANGES.values()];
  let queue = [...names];
  for (let progress = true; progress && queue.length;) {
    progress = false;
    for (const n of [...queue]) {
      const r = CHANGES.get(n) ?? all.find((x) => x.name === n);
      const heads = new Set(A.getAllChanges(doc).map((b) => A.decodeChange(b).hash));
      if (!r.deps.every((h) => heads.has(h))) continue;
      queue = queue.filter((x) => x !== n);
      progress = true;
      if (r.diag) refused[n] = r.diag;
      else { [doc] = A.applyChanges(doc, [r.bytes]); admitted.push(n); }
    }
  }
  return { doc, admitted, refused, pending: queue };
}
const ancestry = (...names) => {
  const want = new Set();
  for (const n of names) { want.add(n); for (const x of CHANGES.values()) if (x.diag === null && isAncestor(x, CHANGES.get(n))) want.add(x.name); }
  return [...CHANGES.keys()].filter((n) => want.has(n));
};
function behavioral(id, section, text, description, orders, expected, read, assertions) {
  const results = orders.map((o) => replay(o));
  for (const res of results) {
    const got = { admitted: [...res.admitted].sort(), refused: res.refused, ...read(res.doc) };
    const want = { admitted: [...expected.admitted].sort(), refused: expected.refused ?? {}, ...expected.state };
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`${id}: replica gives ${JSON.stringify(got)}, the profile text ${JSON.stringify(want)}`);
  }
  CASES.push({
    id, type: "behavioral", kind: "control_document", description, rule: { section: `${SPEC} ${section}`, text },
    inputs: { orders: orders.map((o) => o.map((n) => ({ case: n }))) },
    expected: { admitted: expected.admitted, refused: expected.refused ?? {}, state: expected.state },
    assertions,
  });
}
const readQ = (doc) => {
  const q = doc.questions[RID.q1];
  const ev = (id) => (doc.events[id] ? `${str(doc.events[id].state)}${doc.events[id].code ? `{${str(doc.events[id].code)}}` : ""}` : "absent");
  return { question: q.resolved !== undefined ? `resolved by ${str(q.resolved.answerId)}` : q.superseded !== undefined ? "superseded" : "open", event_a1: ev(RID.a1), event_a2: ev(RID.a2) };
};
const sup = ancestry("answer_to_superseded_rejected");
behavioral("answer_concurrent_with_superseded", "§3 questions, answers, events, §10", "The service's superseded and a human's answer are made concurrently and both admitted; the service then rejects the answer with snapshot_changed and can no longer resolve the question.",
  "question_superseded and answer_created, each made on question_created, delivered in both orders, then the service's rejection",
  [sup, [...sup.filter((n) => n !== "question_superseded" && n !== "answer_to_superseded_rejected"), "question_superseded", "answer_to_superseded_rejected"].filter((n, i, a) => a.indexOf(n) === i)],
  { admitted: sup, state: { question: "superseded", event_a1: "rejected{snapshot_changed}", event_a2: "absent" } }, readQ,
  ["Both delivery orders give the same document.", "question_resolved_after_superseded (refused) shows that a superseded question is never resolved: resolved and superseded are exclusive."]);
const two = ancestry("question_resolved");
behavioral("two_concurrent_answers", "§3 questions, answers, §10", "Two answers to one question are made concurrently and both admitted; the service accepts the first it executes and rejects the other with already_answered.",
  "answer_created (A) and answer_concurrent (R), each made on question_created, delivered in both orders, then question_resolved",
  [two, [...two.filter((n) => n !== "answer_created" && n !== "question_resolved"), "answer_created", "question_resolved"]],
  { admitted: two, state: { question: `resolved by ${RID.a1}`, event_a1: "applied", event_a2: "rejected{already_answered}" } }, readQ,
  ["Both delivery orders give the same document."]);

const twoBase = ancestry("second_base_approval", "two_bases_other_refused", "revoke_second_base", "one_base_after_revocation");
behavioral("two_base_approvals", "§2.3, §7.3", "Two valid base approvals without revoked give the class service to nobody; after root or personal revokes one, the other device's changes are admitted again.",
  "A second base approval, B2's refused heartbeat, the revocation of B2's approval and B's admitted heartbeat",
  [twoBase], { admitted: twoBase.filter((n) => n !== "two_bases_other_refused"), refused: { two_bases_other_refused: "UNAUTHORIZED_WRITER" }, state: { base_approvals_unrevoked: 1, heartbeatAt: "2026-11-19T10:30:00Z" } },
  (doc) => ({ base_approvals_unrevoked: Object.values(doc.approvals).filter((v) => str(v.role) === "base" && v.revoked === undefined).length, heartbeatAt: str(doc.status.heartbeatAt) }),
  ["The refused change is not merged and blocks its dependants (SOP §14.1)."]);

const unk = ancestry("unknown_op_rejected");
behavioral("unknown_op_no_effect", "§6.1, §11", "An unknown op is admitted; a version-1 service answers rejected{unsupported_op} and writes nothing else.",
  "The unknown op export-logs and its rejection", [unk],
  { admitted: unk, state: { event: "rejected", code: "unsupported_op", bindings_unchanged: true, service_unchanged: true, status_unchanged: true } },
  (doc) => ({ event: str(doc.events[RID.r2].state), code: str(doc.events[RID.r2].code), bindings_unchanged: json(doc.bindings) === json(M2.doc.bindings), service_unchanged: json(doc.service) === json(M2.doc.service), status_unchanged: json(doc.status) === json(M2.doc.status) }),
  ["unknown_op_rejected changes only events[r2]: the request has no effect.", "The client shows the update text of §11 for the code unsupported_op."]);

const rev = ancestry("revoke_base_b", "service_concurrent_with_revocation", "service_after_revocation");
behavioral("revocation_keeps_decisions", "§2.3", "The class is taken on the causal history: a change made before the revocation stays admitted wherever it is delivered; one made on the revocation is refused.",
  "revoke_base_b, B's concurrent status write and B's write made on the revocation, in both orders",
  [rev, [...rev.filter((n) => n !== "revoke_base_b" && n !== "service_after_revocation"), "revoke_base_b", "service_after_revocation"]],
  { admitted: rev.filter((n) => n !== "service_after_revocation"), refused: { service_after_revocation: "UNAUTHORIZED_WRITER" }, state: { message: "syncing" } },
  (doc) => ({ message: str(doc.status.message) }), ["A replica never re-judges an admitted change at its current head."]);

const del = ancestry("request_deleted_after_final");
behavioral("request_deleted_before_and_after_final", "§3 requests, events", "A request is deleted only by the service and only once its event is final; the rid is never reused.",
  "The life of r1: created, received, executing, applied, deleted with its event", [del],
  { admitted: del, state: { request: "absent", event: "absent" } },
  (doc) => ({ request: doc.requests[RID.r1] === undefined ? "absent" : "present", event: doc.events[RID.r1] === undefined ? "absent" : "present" }),
  ["request_deleted_without_event and request_deleted_before_final (refused) show the deletion before the final event.", "request_recreated_after_deletion (refused) shows that the rid is never reused (§10)."]);

// ---------------------------------------------------------------------------
// Output.
// ---------------------------------------------------------------------------

const doc = {
  format: "lfcp-vector-format/1",
  suite: {
    id: SUITE_ID, version: "01",
    specification: { id: SPEC, profile: PROFILE, revision: "working-draft" },
    description: "Control Resource profile vectors (SERVICE-CONTROL-PROFILE-01 §12): the initial change, admission SC0 to SC7 for every cell of the mutation table of §3 and every writer class of §2.3, state validation of written entries, and replica transitions (a superseded question concurrent with an answer, two concurrent answers, two base approvals, revocation, an unknown op, deletion of a request).",
    depends_on: [SPEC, "IDENTITY-PROFILE-01", "SHARED-OBJECTS-PROFILE-01", "LFCP-WIRE-01"],
    conventions: {
      engine_package: "@automerge/automerge", engine_version: "3.5.0",
      changes: "Every change is made with time 0 and no message by the SHARED-OBJECTS-PROFILE-01 §8 actor of its writer in C (fixtures.resources.C); each change is carried by its writer's Data Unit whose actor sequence equals the change's Automerge sequence. A validation case gives the change and its causal history (context.history, in delivery order).",
      control: "inputs.control_ref names a fixtures.control_states entry: C's Control state at the Data Unit's control_ref. inputs.writer_class is the class of §2.3 derived from it and, for a kind-1 device, from the approvals of the change's pre-state; an implementation derives it itself.",
      principals: "Principal keys are h('LFCP-TV-SC-' + label + '-ED25519') and h('LFCP-TV-SC-' + label + '-X25519') as Ed25519 and X25519 seeds; Resource IDs are h('LFCP-TV-SC-RESOURCE-' + name). Only descriptors and IDs are published.",
      diagnostics: "A refused change is PROFILE_INVALID with the first diagnostic in the order of §4; an admitted change is valid.",
      links: "args.link of a pair-section request is an opaque test string, not a pairing link of IDENTITY-PROFILE-01 §5.2.",
    },
    warning: "All keys in this suite are public test fixtures. They MUST NOT be used in production.",
  },
  fixtures: {
    resources: RES,
    principals: Object.fromEntries(Object.entries(P).map(([l, p]) => [l, { id_hex: hex(p.id), ref: p.ref, actor_hex: actorOf(l), descriptor_b64url: b64u(p.descriptor), fingerprint: fp(l) }])),
    control_states: CONTROL,
  },
  cases: CASES,
};
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, `${SUITE_ID}.json`), JSON.stringify(doc, null, 2) + "\n");

const md = [`# ${SUITE_ID}`, "",
  "Generated by `generate_service_control_vectors_01.mjs` with the pinned `@automerge/automerge` 3.5.0; do not edit by hand.",
  `Machine-readable values are in \`${SUITE_ID}.json\` (\`lfcp-vector-format/1\`). Rules: ${SPEC} §§2–8, §11; vector list: §12.`, "",
  "| Case | Type | Writer | Class | Expected | Rule | Description |", "|---|---|---|---|---|---|---|"];
for (const c of CASES) {
  const e = c.type === "validation" ? (c.expected.valid ? "valid" : `\`${c.expected.error.diagnostic}\``) : "state";
  md.push(`| \`${c.id}\` | ${c.type} | ${c.inputs.writer ?? ""} | ${c.inputs.writer_class ?? ""} | ${e} | ${c.rule.section} | ${c.description} |`);
}
md.push("", "## Coverage of the mutation table (§3)", "", "Each cell lists the admitted (+) and refused (−) validation cases whose change writes at that position, by the writer's class of §2.3; for class other, the writer follows the case.", "", "| Position | root | personal | service | other |", "|---|---|---|---|---|");
for (const top of ["profile, meta", "root keys", ...ROOT_KEYS.slice(2)]) {
  const cell = (cls) => CASES.filter((c) => c.type === "validation" && c.inputs.writer_class === cls && CHANGES.get(c.id).tops.has(top))
    .map((c) => `${c.expected.valid ? "+" : "−"}\`${c.id}\`${cls === "other" ? ` (${c.inputs.writer})` : ""}`).join(", ");
  md.push(`| ${top === "root keys" ? "other root keys" : `\`${top}\``} | ${cell("root")} | ${cell("personal")} | ${cell("service")} | ${cell("other")} |`);
}
md.push("");
writeFileSync(join(OUT, `${SUITE_ID}.md`), md.join("\n"));
console.log(join(OUT, `${SUITE_ID}.json`));
console.log(`${CASES.length} cases`);
