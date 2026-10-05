// SHARED-OBJECTS-TEST-VECTORS-01 Automerge reference corpus generator
// Compatibility target: @automerge/automerge 3.5.0
// Run in a clean directory:
//   npm install @automerge/automerge@3.5.0
//   node generate_automerge_reference_01.mjs
//
// This generator is supplementary. Conformance does NOT require independently
// generated changes to have identical bytes. The generated corpus is useful for
// cross-binding apply/load tests.

import * as A from "@automerge/automerge";
import fs from "node:fs";
import crypto from "node:crypto";

const vectors = JSON.parse(fs.readFileSync(new URL("./SHARED-OBJECTS-TEST-VECTORS-01.json", import.meta.url)));
const hex = s => Buffer.from(s, "hex");
const outHex = u8 => Buffer.from(u8).toString("hex");

const actor = vectors.fixtures.principals.andrey.actor_a_hex;
const pavelActor = vectors.fixtures.principals.pavel.actor_a_hex;
const id = vectors.fixtures.objects.task_1;
const andreyRef = vectors.fixtures.principals.andrey.ref;

function init(actorId) { return A.init({ actor: actorId }); }
function oneChange(oldDoc, newDoc) {
  const changes = A.getChanges(oldDoc, newDoc);
  if (changes.length !== 1) throw new Error(`expected exactly one change, got ${changes.length}`);
  return changes[0];
}

let d0 = init(actor);
let d1 = A.change(d0, "profile init", d => {
  d.schema = "org.openlfcp.shared-objects.v1";
  d.objects = {};
});
const c0 = oneChange(d0, d1);

let d2 = A.change(d1, "task.create", d => {
  d.objects[id] = {
    id,
    type: "task",
    lifecycle: "active",
    created_by: andreyRef,
    created_at: "2026-10-04T05:30:00Z",
    title: "Prepare API contract",
    status: "todo",
    priority: "normal",
    tags: {}, assignees: {}, extensions: {}
  };
});
const c1 = oneChange(d1, d2);

// Fork two actors from common ancestry for a status conflict.
let aBase = A.clone(d2, { actor });
let pBase = A.clone(d2, { actor: pavelActor });
let aDone = A.change(aBase, "task.complete", d => { d.objects[id].status = "done"; d.objects[id].completion_date = "2026-10-08"; });
let pCancel = A.change(pBase, "task.cancel", d => { d.objects[id].status = "cancelled"; });
const cDone = oneChange(aBase, aDone);
const cCancel = oneChange(pBase, pCancel);
let merged = A.merge(aDone, pCancel);
const conflicts = A.getConflicts(merged.objects[id], "status");

const save = A.save(merged);
const reloaded = A.load(save, { actor });

const corpus = {
  automerge_version_target: "3.5.0",
  changes: {
    init: outHex(c0),
    create_task: outHex(c1),
    status_done: outHex(cDone),
    status_cancelled: outHex(cCancel)
  },
  hashes: {
    init: crypto.createHash("sha256").update(c0).digest("hex"),
    create_task: crypto.createHash("sha256").update(c1).digest("hex"),
    status_done: crypto.createHash("sha256").update(cDone).digest("hex"),
    status_cancelled: crypto.createHash("sha256").update(cCancel).digest("hex"),
    snapshot: crypto.createHash("sha256").update(save).digest("hex")
  },
  status_conflicts: Object.values(conflicts ?? {}).sort(),
  snapshot_hex: outHex(save),
  reloaded_status: reloaded.objects[id].status
};
fs.writeFileSync("SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json", JSON.stringify(corpus, null, 2) + "\n");
console.log("wrote SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json");
