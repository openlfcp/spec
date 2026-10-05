// Structural checks for Shared Objects logical state (SHARED-OBJECTS-PROFILE-01),
// LFCP-006. The JSON Schema in profiles/shared-objects-01/schema/ carries
// every rule it can express; this module adds the rest:
//
//   bad-date        a Local Date is not a real Gregorian date (§35)
//   bad-timestamp   created_at is not a real RFC 3339 UTC date-time (§28)
//   id-mismatch     an object's id differs from its key in `objects` (§20, §24)
//   immutable       id, type or created_by changed between two states (§24, §25, §27, §75)
//
// Problems are { pointer, reason } with reason codes `schema/<keyword>` or the
// codes above.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import { relevant, schemaReason } from "./ajv-errors.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const SCHEMA_PATH = "profiles/shared-objects-01/schema/shared-objects-state.schema.json";
const schema = JSON.parse(readFileSync(join(root, SCHEMA_PATH), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateRoot = ajv.compile(schema);

const DATE_FIELDS = ["due", "scheduled", "completion_date"];
const IMMUTABLE = ["id", "type", "created_by"];
const escape = (key) => String(key).replace(/~/g, "~0").replace(/\//g, "~1");

export function isGregorianDate(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!m) return false;
  const [y, mo, d] = m.slice(1).map(Number);
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return mo >= 1 && mo <= 12 && d >= 1 && d <= days[mo - 1];
}

function isUtcTimestamp(s) {
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/.exec(s);
  // RFC 3339 allows second 60 (leap second).
  return Boolean(m) && isGregorianDate(m[1]) && Number(m[2]) <= 23 && Number(m[3]) <= 59 && Number(m[4]) <= 60;
}

// Problems for a whole Shared Objects root.
export function rootProblems(state) {
  const problems = [];
  if (!validateRoot(state)) {
    // A bad map key is reported once, at the key: drop the propertyNames
    // sub-errors and move the propertyNames error itself onto the key.
    // A bad map key is reported once, at the key. Its sub-errors (e.g. the
    // key pattern) are reported by ajv at the map's path, so non-key errors
    // at the same path as a key error are dropped. Key errors are kept even
    // when the value under the key also fails.
    const keyErrors = validateRoot.errors.filter((e) => e.keyword === "propertyNames");
    const keyMaps = new Set(keyErrors.map((e) => e.instancePath));
    const others = validateRoot.errors.filter((e) => e.keyword !== "propertyNames" && !keyMaps.has(e.instancePath));
    const keyed = keyErrors.map((e) => ({ ...e, instancePath: `${e.instancePath}/${escape(e.params.propertyName)}` }));
    const seen = new Set();
    for (const e of [...relevant(others), ...keyed]) {
      const pointer = e.instancePath || "/";
      const reason = schemaReason(e);
      if (seen.has(`${pointer} ${reason}`)) continue;
      seen.add(`${pointer} ${reason}`);
      problems.push({ pointer, reason });
    }
  }
  const objects = state && typeof state.objects === "object" && !Array.isArray(state.objects) ? state.objects : {};
  for (const [key, obj] of Object.entries(objects)) {
    if (!obj || typeof obj !== "object") continue;
    const base = `/objects/${escape(key)}`;
    if ("id" in obj && obj.id !== key) problems.push({ pointer: `${base}/id`, reason: "id-mismatch: id differs from the objects key (§20)" });
    if (obj.type !== "task") continue;
    for (const f of DATE_FIELDS) {
      if (typeof obj[f] === "string" && /^\d{4}-\d{2}-\d{2}$/.test(obj[f]) && !isGregorianDate(obj[f])) {
        problems.push({ pointer: `${base}/${f}`, reason: "bad-date: not a valid Gregorian calendar date (§35)" });
      }
    }
    if (typeof obj.created_at === "string" && /Z$/.test(obj.created_at) && !isUtcTimestamp(obj.created_at)) {
      problems.push({ pointer: `${base}/created_at`, reason: "bad-timestamp: not a valid RFC 3339 UTC date-time (§28)" });
    }
  }
  return problems;
}

// Problems for one object, checked inside a minimal root under `key`.
export function objectProblems(obj, key = obj?.id) {
  const state = { profile: "org.openlfcp.shared-objects.v1", objects: { [key]: obj }, extensions: {} };
  const prefix = `/objects/${escape(key)}`;
  return rootProblems(state).map((p) => ({ ...p, pointer: p.pointer.startsWith(prefix) ? p.pointer.slice(prefix.length) || "/" : p.pointer }));
}

// Problems for one Task field value, checked inside a known-valid Task.
export function fieldProblems(baseTask, field, value) {
  return objectProblems({ ...baseTask, [field]: value }).filter((p) => p.pointer === `/${field}` || p.pointer.startsWith(`/${field}/`));
}

// Immutable-field violations between two states of the same root (§75).
export function transitionProblems(before, after) {
  const problems = [];
  for (const [key, old] of Object.entries(before?.objects ?? {})) {
    const now = after?.objects?.[key];
    if (!now || typeof now !== "object") continue;
    for (const f of IMMUTABLE) {
      if (f in old && JSON.stringify(old[f]) !== JSON.stringify(now[f])) {
        problems.push({ pointer: `/objects/${escape(key)}/${f}`, reason: `immutable: ${f} changed (§75)` });
      }
    }
  }
  return problems;
}
