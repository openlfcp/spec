// SHARED-OBJECTS-PROFILE-01 §11.1 on the raw bytes of a change, as a
// receiver applies it before its Automerge engine decodes anything: the
// chunk structure, the change header, and the value counts of the
// operation columns read from their run headers. The reference admission
// (admission.mjs) runs it first, so a change above a limit is refused
// without being decoded; the generator reads a change's hash, actor,
// sequence number and dependencies from its header the same way.

import { createHash } from 'node:crypto';

/** §11.1. */
export const LIMITS = { rows: 16384, groupSum: 262144, stringBytes: 4194304, deps: 1024, actors: 1024 };
const BIG = 2 ** 53; // a number this large is above every limit

class Malformed extends Error {}

/** A cursor over `bytes` with the readers of the Automerge encoding. */
function reader(bytes, start = 0, end = bytes.length) {
  let pos = start;
  const need = (n) => {
    if (n < 0 || pos + n > end) throw new Malformed('truncated');
  };
  const uleb = () => {
    let v = 0, scale = 1;
    for (;;) {
      need(1);
      const b = bytes[pos++];
      v += (b & 0x7f) * scale;
      if ((b & 0x80) === 0) return v;
      scale *= 128;
      if (scale > BIG * 128) throw new Malformed('number too long');
    }
  };
  const sleb = () => {
    let v = 0, scale = 1, b;
    do {
      need(1);
      b = bytes[pos++];
      v += (b & 0x7f) * scale;
      scale *= 128;
      if (scale > BIG * 128) throw new Malformed('number too long');
    } while (b & 0x80);
    return b & 0x40 ? v - scale : v;
  };
  const take = (n) => {
    need(n);
    const out = bytes.subarray(pos, pos + n);
    pos += n;
    return out;
  };
  return { uleb, sleb, take, at: () => pos, done: () => pos >= end };
}

const hex = (b) => Buffer.from(b).toString('hex');

/**
 * The change chunk's header and column table (§11.1 rules 1 and 2), or a
 * Malformed error. `hash` is the change hash: the SHA-256 of the chunk from
 * its type byte on, computed without decoding any operation.
 */
export function changeHeader(bytes) {
  if (bytes.length < 9 || hex(bytes.subarray(0, 4)) !== '856f4a83') throw new Malformed('not a chunk');
  const outer = reader(bytes, 8);
  const type = outer.take(1)[0];
  const length = outer.uleb();
  const bodyStart = outer.at();
  if (bodyStart + length !== bytes.length) throw new Malformed('chunk length');
  const hash = createHash('sha256').update(bytes.subarray(8)).digest('hex');
  if (type !== 1) return { type, hash };
  const r = reader(bytes, bodyStart);
  const depCount = r.uleb();
  if (depCount > LIMITS.deps) return { type, hash, depCount };
  const deps = Array.from({ length: depCount }, () => hex(r.take(32)));
  const actor = hex(r.take(r.uleb()));
  const seq = r.uleb();
  const startOp = r.uleb();
  r.sleb(); // time
  r.take(r.uleb()); // message
  const otherCount = r.uleb();
  if (otherCount > LIMITS.actors) return { type, hash, depCount, deps, actor, seq, startOp, otherCount };
  const others = Array.from({ length: otherCount }, () => hex(r.take(r.uleb())));
  const columnCount = r.uleb();
  const meta = [];
  for (let i = 0; i < columnCount; i++) meta.push({ spec: r.uleb(), length: r.uleb() });
  const columns = meta.map((m) => ({ ...m, start: r.at(), data: r.take(m.length) }));
  return { type, hash, depCount, deps, actor, seq, startOp, otherCount, others, columns };
}

/** A column's values (§11.1 rule 4): counts, and the values when they are needed. */
function walkColumn(column) {
  const type = column.spec & 7;
  const r = reader(column.data);
  let count = 0, sum = 0, strings = 0, maxValue = 0;
  const value = () => {
    if (type === 3) return r.sleb();
    if (type === 5) {
      const n = r.uleb();
      r.take(n);
      return n;
    }
    return r.uleb();
  };
  const add = (v, n) => {
    count += n;
    if (type === 0) sum += v * n;
    if (type === 5) strings += v * n;
    if ((type === 0 || type === 1) && v > maxValue) maxValue = v;
  };
  if (type === 7) return { count: 0, sum: 0, strings: 0, maxValue: 0 };
  if (type === 4) {
    while (!r.done()) count += r.uleb();
    return { count, sum, strings, maxValue };
  }
  while (!r.done()) {
    const n = r.sleb();
    if (n > 0) add(value(), n);
    else if (n < 0) for (let i = 0; i < -n; i++) add(value(), 1);
    else count += r.uleb();
  }
  return { count, sum, strings, maxValue };
}

/**
 * The name of refused bytes (SHARED-SECTIONS-PROFILE-01 §14.1): the change
 * hash of one type 1 change chunk whose length field covers exactly the
 * rest, computed without decoding; null for anything else, a compressed
 * chunk (type 2) included, which is never inflated to be named.
 */
export function refusalName(bytes) {
  try {
    const h = changeHeader(bytes);
    return h.type === 1 ? h.hash : null;
  } catch (e) {
    if (e instanceof Malformed) return null;
    throw e;
  }
}

/**
 * §11.1: null when `bytes` is one uncompressed change chunk within every
 * limit and the structural rules 7 to 9; otherwise the reason. Linear in
 * the length of `bytes`; nothing is decoded into a document.
 */
export function expansionRefusal(bytes) {
  try {
    const h = changeHeader(bytes);
    if (h.type !== 1) return 'not an uncompressed change chunk';
    if (h.depCount > LIMITS.deps) return 'dependencies';
    if (h.otherCount > LIMITS.actors) return 'other actors';
    const actors = 1 + h.otherCount;
    const seen = new Set();
    let groupSum = 0, strings = 0;
    const groupIds = new Set(h.columns.filter((c) => (c.spec & 7) === 0).map((c) => c.spec >> 4));
    for (const c of h.columns) {
      if (c.spec & 8) return 'deflated column'; // rule 3
      if (seen.has(c.spec)) return 'duplicate column'; // rule 7
      seen.add(c.spec);
      const w = walkColumn(c);
      if (w.count >= BIG || w.sum >= BIG || w.strings >= BIG) return 'number above every limit';
      const type = c.spec & 7;
      if (type === 0) {
        if (w.count > LIMITS.rows) return 'rows'; // one value per operation
        groupSum += w.sum;
        if (w.maxValue > actors) return 'more predecessors than actors'; // rule 9
      } else if (!groupIds.has(c.spec >> 4) && w.count > LIMITS.rows) return 'rows'; // rule 4, limit 1
      if (type === 1 && w.maxValue >= actors) return 'actor index'; // rule 8
      strings += w.strings;
    }
    if (groupSum > LIMITS.groupSum) return 'group sum';
    if (strings > LIMITS.stringBytes) return 'string bytes';
    return null;
  } catch (e) {
    if (e instanceof Malformed) return `malformed: ${e.message}`;
    throw e;
  }
}
