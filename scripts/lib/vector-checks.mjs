// Protocol vector validator checks (LFCP-007) that go beyond the
// lfcp-vector-format/1 JSON Schema. The schema itself (shape, required fields
// per case type, hex/b64url character sets) is enforced by validate-vectors.mjs.
//
// Every problem is reported as { caseId, pointer, reason } where `reason`
// starts with a stable code:
//
//   duplicate-key        a JSON object repeats a key
//   duplicate-id         two cases share an id
//   bad-hex              a free-form *_hex string is not lowercase even-length hex
//   bad-b64url           a b64url value does not decode, or does not re-encode
//                        to the same string (padding, non-zero trailing bits)
//   hash-mismatch        a recomputed SHA-256 differs from the published value
//   encoding-mismatch    a recomputed deterministic encoding differs
//   unresolved-ref       a field that names another case or fixture does not resolve
//
// Only plain SHA-256 hashes over bytes present in the vector are recomputed,
// using formulas stated in LFCP-WIRE-01 or SHARED-OBJECTS-PROFILE-01. No
// signature, AEAD, HPKE, HKDF or key derivation is attempted here.

import { createHash } from "node:crypto";

const HEX = /^([0-9a-f]{2})*$/;
const B64URL = /^[A-Za-z0-9_-]*$/;

const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest("hex");
};
const bytes = (hex) => Buffer.from(hex, "hex");
const ascii = (s) => Buffer.from(s, "ascii");
const b64url = (buf) => buf.toString("base64url");
const escape = (key) => String(key).replace(/~/g, "~0").replace(/\//g, "~1");

// Minimal deterministic CBOR for [uint < 24, bstr], as used by the Shared
// Objects framing (SHARED-OBJECTS-PROFILE-01 §11, §13).
function cborUintBstrPair(n, payload) {
  const len = payload.length;
  let head;
  if (len < 24) head = Buffer.from([0x40 | len]);
  else if (len < 0x100) head = Buffer.from([0x58, len]);
  else if (len < 0x10000) head = Buffer.from([0x59, len >> 8, len & 0xff]);
  else head = Buffer.from([0x5a, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff]);
  return Buffer.concat([Buffer.from([0x82, n]), head, payload]);
}

// Hash recomputations. `section` cites the defining formula; `applies`
// selects the case; `pairs` yields [pointer-suffix, published hex, recomputed hex].
export const HASH_RULES = [
  {
    field: "principal_id",
    section: 'LFCP-WIRE-01 §7: SHA-256(ASCII("LFCP-PRINCIPAL-v1") || ed25519_public_key || x25519_public_key)',
    applies: (c) => c.type === "bytes" && c.kind === "principal",
    pairs: (c) => [[
      "/expected/principal_id/hex",
      c.expected.principal_id?.hex,
      sha256(ascii("LFCP-PRINCIPAL-v1"), bytes(c.expected.ed25519_public.hex), bytes(c.expected.x25519_public.hex)),
    ]],
  },
  {
    field: "dek0_commitment, dek1_commitment",
    section:
      'LFCP-WIRE-01 §11: SHA-256(ASCII("LFCP-DEK-v1") || resource_id || uint64_be(E) || DEK), with resource_id and DEKs from fixtures.resource',
    applies: (c, doc) =>
      c.type === "bytes" && c.kind === "dek_commitment" && Number.isInteger(c.inputs?.dek0_epoch) && doc.fixtures?.resource?.id,
    pairs: (c, doc) =>
      ["dek0", "dek1"]
        .filter((d) => Number.isInteger(c.inputs[`${d}_epoch`]) && doc.fixtures.resource[d])
        .map((d) => {
          const epoch = Buffer.alloc(8);
          epoch.writeBigUInt64BE(BigInt(c.inputs[`${d}_epoch`]));
          return [
            `/expected/${d}_commitment/hex`,
            c.expected[`${d}_commitment`]?.hex,
            sha256(ascii("LFCP-DEK-v1"), bytes(doc.fixtures.resource.id.hex), epoch, bytes(doc.fixtures.resource[d].hex)),
          ];
        }),
  },
  {
    field: "record_id",
    section: "LFCP-WIRE-01 §13 and §10.6: SHA-256(exact COSE_Sign1 bytes)",
    applies: (c) => c.type === "bytes" && c.kind === "control_record",
    pairs: (c) => [["/expected/record_id/hex", c.expected.record_id?.hex, sha256(bytes(c.expected.cose_sign1.hex))]],
  },
  {
    field: "offer_id, accept_id",
    section: "LFCP-WIRE-01 §10.6: object_id = SHA-256(exact COSE_Sign1 bytes); §23.2 names the transfer offer id",
    applies: (c) => c.type === "bytes" && c.kind === "owner_transfer",
    pairs: (c) => [
      ["/expected/offer_id/hex", c.expected.offer_id?.hex, sha256(bytes(c.expected.offer_cose_sign1.hex))],
      ["/expected/accept_id/hex", c.expected.accept_id?.hex, sha256(bytes(c.expected.accept_cose_sign1.hex))],
    ],
  },
  {
    field: "package_id",
    section: "LFCP-WIRE-01 §10.6: object_id = SHA-256(exact COSE_Sign1 bytes)",
    applies: (c) => c.type === "bytes" && c.kind === "key_package",
    pairs: (c) => [["/expected/package_id/hex", c.expected.package_id?.hex, sha256(bytes(c.expected.cose_sign1.hex))]],
  },
  {
    field: "unit_id",
    section: "LFCP-WIRE-01 §26 and §10.6: SHA-256(exact COSE_Sign1 bytes)",
    applies: (c) => c.type === "bytes" && c.kind === "data_unit",
    pairs: (c) => [["/expected/unit_id/hex", c.expected.unit_id?.hex, sha256(bytes(c.expected.cose_sign1.hex))]],
  },
  {
    field: "snapshot_id",
    section: "LFCP-WIRE-01 §29: snapshot_id = SHA-256(exact COSE_Sign1 bytes)",
    applies: (c) => c.type === "bytes" && c.kind === "snapshot",
    pairs: (c) => [["/expected/snapshot_id/hex", c.expected.snapshot_id?.hex, sha256(bytes(c.expected.cose_sign1.hex))]],
  },
  {
    field: "conflicting_D2_id",
    section: "LFCP-WIRE-01 §26 and §10.6: SHA-256(exact COSE_Sign1 bytes)",
    applies: (c) => c.inputs?.conflicting_D2_cose && c.inputs?.conflicting_D2_id,
    pairs: (c) => [[
      "/inputs/conflicting_D2_id/hex",
      c.inputs.conflicting_D2_id.hex,
      sha256(bytes(c.inputs.conflicting_D2_cose.hex)),
    ]],
  },
  {
    field: "actor_id",
    section:
      'SHARED-OBJECTS-PROFILE-01 §8: SHA-256(ASCII("OPENLFCP-SHARED-OBJECTS-ACTOR-v1") || resource_id || principal_id)',
    applies: (c) => c.type === "bytes" && c.kind === "actor_id",
    pairs: (c) => [[
      "/expected/actor_id/hex",
      c.expected.actor_id?.hex,
      sha256(ascii("OPENLFCP-SHARED-OBJECTS-ACTOR-v1"), bytes(c.inputs.resource_hex.hex), bytes(c.inputs.principal_hex.hex)),
    ]],
  },
  {
    field: "sha256",
    section: 'SHARED-OBJECTS-TEST-VECTORS-01 D04/D05: "SHA-256" of the expected deterministic CBOR',
    applies: (c) => c.type === "bytes" && /^profile_(change|snapshot)_framing$/.test(c.kind),
    pairs: (c) => [["/expected/sha256/hex", c.expected.sha256?.hex, sha256(bytes(c.expected.framed_cbor.hex))]],
  },
];

// Hash-like fields deliberately not recomputed, with the reason. Reported so
// the gap is visible rather than silent.
export const NOT_VERIFIED = [
  ["actor_key, hpke_shared_secret, hpke_key, hpke_base_nonce, hpke_enc, hpke_ciphertext, ciphertext", "HKDF/HPKE/AEAD derivations; implementation work (LFCP-017, LFCP-070)"],
  ["cose_sign1 signatures, auth_proof_cose_sign1", "Ed25519 signature verification; implementation work"],
  ["prev_control_id and other hashes inside payload CBOR", "needs CBOR decoding; Control Chain linkage is a semantic check (LFCP-016)"],
  ["server_id, session_id, nonces, message ids, seeds", "generated as SHA-256 of generator labels that are not part of the vector"],
  ["fixtures.principals.*.id_hex (Shared Objects)", "LFCP-WIRE-01 §7 needs the public keys, which the Shared Objects suite does not carry"],
];

export const ENCODING_RULES = [
  'PrincipalRef = "p:" || base64url-no-padding(principal_id): SHARED-OBJECTS-PROFILE-01 §27',
  "framed_cbor = deterministic CBOR [1, bstr]: SHARED-OBJECTS-PROFILE-01 §11 (change), §13 (snapshot)",
  "invite URI components: LFCP-WIRE-01 §18.2 (Base64url resource, grant and secret)",
  "plaintext_hex = UTF-8 bytes of plaintext_utf8 (vector-internal redundancy)",
];

// Reports every key repeated within one JSON object, which JSON.parse hides.
export function duplicateKeys(text) {
  const problems = [];
  const stack = []; // { type: 'object'|'array', keys: Set, path: [], index, key }
  let i = 0;
  const pointer = () =>
    "/" +
    stack
      .slice(1)
      .map((f) => escape(f.label))
      .join("/");
  const readString = () => {
    let j = i + 1;
    let out = "";
    while (text[j] !== '"') {
      if (text[j] === "\\") {
        out += JSON.parse(`"${text.slice(j, j + (text[j + 1] === "u" ? 6 : 2))}"`);
        j += text[j + 1] === "u" ? 6 : 2;
      } else {
        out += text[j];
        j += 1;
      }
    }
    i = j + 1;
    return out;
  };
  let expectKey = false;
  while (i < text.length) {
    const ch = text[i];
    const top = stack[stack.length - 1];
    if (ch === "{" || ch === "[") {
      const label = top ? (top.type === "object" ? top.key : top.index) : "";
      stack.push({ type: ch === "{" ? "object" : "array", keys: new Set(), label, index: 0, key: null });
      expectKey = ch === "{";
      i += 1;
    } else if (ch === "}" || ch === "]") {
      stack.pop();
      i += 1;
    } else if (ch === '"') {
      const s = readString();
      if (expectKey && top?.type === "object") {
        if (top.keys.has(s)) {
          const where = (pointer() === "/" ? "" : pointer()) + "/" + escape(s);
          problems.push({ caseId: null, pointer: where, reason: `duplicate-key: "${s}" appears twice in one object` });
        }
        top.keys.add(s);
        top.key = s;
        expectKey = false;
      }
    } else if (ch === ",") {
      if (top?.type === "object") expectKey = true;
      else if (top) top.index += 1;
      i += 1;
    } else {
      i += 1;
    }
  }
  return problems;
}

function walk(value, path, visit) {
  visit(value, path);
  if (Array.isArray(value)) value.forEach((v, k) => walk(v, `${path}/${k}`, visit));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) walk(v, `${path}/${escape(k)}`, visit);
  }
}

const canonicalB64url = (s) => B64URL.test(s) && s.length % 4 !== 1 && b64url(Buffer.from(s, "base64url")) === s;

// Checks for one suite document that already passed the schema.
export function semanticProblems(doc) {
  const problems = [];
  const stats = new Map(); // HASH_RULES field -> verified count
  const cases = Array.isArray(doc.cases) ? doc.cases : [];
  const add = (caseId, pointer, reason) => problems.push({ caseId, pointer, reason });

  // Case-id uniqueness (fixture-key uniqueness is covered by duplicateKeys).
  const seen = new Map();
  cases.forEach((c, k) => {
    if (seen.has(c.id)) add(c.id, `/cases/${k}/id`, `duplicate-id: also used by /cases/${seen.get(c.id)}`);
    else seen.set(c.id, k);
  });
  const byId = new Map(cases.map((c) => [c.id, c]));

  // Encodings everywhere: {"b64url"} wrappers, free-form *_hex / *_b64url
  // keys (e.g. Shared Objects fixtures), and PrincipalRef strings.
  walk(doc, "", (value, path) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      for (const [k, v] of Object.entries(value)) {
        if (typeof v !== "string") continue;
        const where = `${path}/${escape(k)}`;
        const caseId = /^\/cases\/(\d+)/.exec(where)?.[1];
        const id = caseId !== undefined ? cases[Number(caseId)]?.id ?? null : null;
        if (k === "b64url" || /_b64url$/.test(k)) {
          if (!canonicalB64url(v)) add(id, where, "bad-b64url: not canonical unpadded base64url");
        } else if (/_hex$/.test(k) && !HEX.test(v)) {
          add(id, where, "bad-hex: not lowercase even-length hex");
        }
      }
    }
  });

  // Hash recomputation.
  cases.forEach((c, k) => {
    for (const rule of HASH_RULES) {
      if (!rule.applies(c, doc)) continue;
      for (const [suffix, published, computed] of rule.pairs(c, doc)) {
        if (published === undefined) continue; // missing field: schema/required territory
        if (published !== computed) {
          add(c.id, `/cases/${k}${suffix}`, `hash-mismatch: recomputed ${computed} (${rule.section})`);
        } else {
          stats.set(rule.field, (stats.get(rule.field) ?? 0) + 1);
        }
      }
    }
  });

  // Shared Objects fixtures: actor IDs and PrincipalRefs (Profile §8, §27).
  const fx = doc.fixtures ?? {};
  const principals = fx.principals && typeof fx.principals === "object" ? fx.principals : {};
  const knownRefs = new Set();
  for (const [name, p] of Object.entries(principals)) {
    if (!p || typeof p.id_hex !== "string" || !HEX.test(p.id_hex)) continue;
    const base = `/fixtures/principals/${escape(name)}`;
    if (typeof p.ref === "string") {
      knownRefs.add(p.ref);
      const expected = `p:${b64url(bytes(p.id_hex))}`;
      if (p.ref !== expected) add(null, `${base}/ref`, `encoding-mismatch: expected ${expected} (SHARED-OBJECTS-PROFILE-01 §27)`);
    }
    for (const [field, resourceKey] of [["actor_a_hex", "resource_a_hex"], ["actor_b_hex", "resource_b_hex"]]) {
      if (typeof p[field] !== "string" || typeof fx[resourceKey] !== "string") continue;
      const computed = sha256(ascii("OPENLFCP-SHARED-OBJECTS-ACTOR-v1"), bytes(fx[resourceKey]), bytes(p.id_hex));
      if (p[field] !== computed) {
        add(null, `${base}/${field}`, `hash-mismatch: recomputed ${computed} (SHARED-OBJECTS-PROFILE-01 §8)`);
      } else {
        stats.set("fixtures actor_*_hex", (stats.get("fixtures actor_*_hex") ?? 0) + 1);
      }
    }
  }

  // Deterministic encodings inside cases.
  cases.forEach((c, k) => {
    const at = (suffix) => `/cases/${k}${suffix}`;
    if (c.type === "bytes" && c.kind === "principal_ref" && c.inputs?.principal_id && c.expected?.principal_ref) {
      const expected = `p:${b64url(bytes(c.inputs.principal_id.hex))}`;
      if (c.expected.principal_ref !== expected) {
        add(c.id, at("/expected/principal_ref"), `encoding-mismatch: expected ${expected} (SHARED-OBJECTS-PROFILE-01 §27)`);
      }
    }
    if (c.type === "bytes" && /^profile_(change|snapshot)_framing$/.test(c.kind) && c.expected?.framed_cbor) {
      const input = c.inputs?.automerge_change_hex ?? c.inputs?.automerge_save_hex;
      if (input) {
        const expected = cborUintBstrPair(1, bytes(input.hex)).toString("hex");
        if (c.expected.framed_cbor.hex !== expected) {
          add(c.id, at("/expected/framed_cbor/hex"), `encoding-mismatch: expected ${expected} (SHARED-OBJECTS-PROFILE-01 §11/§13)`);
        }
      }
    }
    if (c.type === "bytes" && c.inputs?.plaintext_utf8 !== undefined && c.inputs?.plaintext_hex) {
      const expected = Buffer.from(c.inputs.plaintext_utf8, "utf8").toString("hex");
      if (c.inputs.plaintext_hex.hex !== expected) {
        add(c.id, at("/inputs/plaintext_hex/hex"), "encoding-mismatch: not the UTF-8 bytes of plaintext_utf8");
      }
    }
    if (c.type === "bytes" && c.kind === "invite_uri") {
      const e = c.expected;
      if (e.secret_cbor && e.secret_b64url && b64url(bytes(e.secret_cbor.hex)) !== e.secret_b64url.b64url) {
        add(c.id, at("/expected/secret_b64url/b64url"), "encoding-mismatch: not base64url of secret_cbor (LFCP-WIRE-01 §18.2)");
      }
      const resource = fx.resource?.id?.hex;
      if (resource && e.resource_b64url && b64url(bytes(resource)) !== e.resource_b64url.b64url) {
        add(c.id, at("/expected/resource_b64url/b64url"), "encoding-mismatch: not base64url of fixtures.resource.id (LFCP-WIRE-01 §18.2)");
      }
      if (e.grant_id_b64url) {
        const grant = Buffer.from(e.grant_id_b64url.b64url, "base64url").toString("hex");
        const isRecord = cases.some((x) => x.kind === "control_record" && x.expected?.record_id?.hex === grant);
        if (!isRecord) add(c.id, at("/expected/grant_id_b64url/b64url"), "unresolved-ref: no control_record case has this record_id");
      }
      if (typeof e.uri === "string") {
        const m = /^lfcp:\/\/join\/([^?#]+)\?([^#]*)(?:#secret=(.*))?$/.exec(e.uri);
        const params = m ? new URLSearchParams(m[2]) : null;
        const ok =
          m &&
          m[1] === e.resource_b64url?.b64url &&
          params.get("grant") === e.grant_id_b64url?.b64url &&
          params.getAll("endpoint").length > 0 &&
          (m[3] === undefined || m[3] === e.secret_b64url?.b64url);
        if (!ok) add(c.id, at("/expected/uri"), "encoding-mismatch: URI components do not match the case values (LFCP-WIRE-01 §18.2)");
      }
    }
  });

  // Cross-references.
  const unitIds = new Set(cases.filter((x) => x.type === "bytes" && x.kind === "data_unit").map((x) => x.expected?.unit_id?.hex));
  cases.forEach((c, k) => {
    const at = (suffix) => `/cases/${k}${suffix}`;
    if (c.type === "bytes" && typeof c.inputs?.signer === "string") {
      const target = `principal_${c.inputs.signer.toLowerCase()}`;
      if (!byId.has(target)) add(c.id, at("/inputs/signer"), `unresolved-ref: no case ${target}`);
    }
    for (const field of ["original_D2_id", "unit_id"]) {
      const v = c.type === "validation" ? c.inputs?.[field]?.hex : undefined;
      if (v !== undefined && !unitIds.has(v)) add(c.id, at(`/inputs/${field}/hex`), "unresolved-ref: no data_unit case has this unit_id");
    }
    if (c.type === "behavioral") {
      const derived = c.inputs?.base_state?.derived_from;
      if (typeof derived === "string") {
        const target = derived.split(/\s+/)[0];
        if (!byId.has(target)) add(c.id, at("/inputs/base_state/derived_from"), `unresolved-ref: no case ${target}`);
      }
      (c.inputs?.branches ?? []).forEach((b, j) => {
        if (typeof b?.actor === "string" && !(b.actor in principals)) {
          add(c.id, at(`/inputs/branches/${j}/actor`), `unresolved-ref: no fixtures.principals.${b.actor}`);
        }
      });
      walk(c, at(""), (value, path) => {
        if (typeof value === "string" && value.startsWith("p:") && knownRefs.size > 0 && !knownRefs.has(value)) {
          add(c.id, path, "unresolved-ref: PrincipalRef is not a fixtures principal");
        }
      });
    }
  });

  return { problems, stats };
}
