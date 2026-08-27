#!/usr/bin/env node

// Independent public-integrity verifier for OpenLine field-tier receipts.

import crypto from "node:crypto";
import fs from "node:fs";

const HASH = /^[0-9a-f]{64}$/;
const NAME = /^[A-Za-z_][A-Za-z0-9_.:/-]*$/;
const TIERS = new Set(["policy", "derived", "payload"]);
const TYPES = new Set(["string", "integer", "boolean", "array", "object"]);
const DECISIONS = new Set(["COMMIT", "QUARANTINE", "DENY"]);

function asciiCompare(left, right) {
  return left < right ? -1 : (left > right ? 1 : 0);
}

function sameKeys(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join("\u001f") === [...expected].sort().join("\u001f");
}

function rejectDuplicateKeys(text) {
  let index = 0;
  const whitespace = () => { while (/\s/.test(text[index] || "")) index += 1; };
  function stringToken() {
    const start = index;
    if (text[index] !== '"') throw new Error("expected string");
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") index += 2;
      else if (text[index] === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index));
      } else index += 1;
    }
    throw new Error("unterminated string");
  }
  function value() {
    whitespace();
    if (text[index] === "{") {
      index += 1;
      const keys = new Set();
      whitespace();
      if (text[index] === "}") { index += 1; return; }
      while (index < text.length) {
        whitespace();
        const key = stringToken();
        if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
        keys.add(key);
        whitespace();
        if (text[index] !== ":") throw new Error("expected colon");
        index += 1;
        value();
        whitespace();
        if (text[index] === "}") { index += 1; return; }
        if (text[index] !== ",") throw new Error("expected comma");
        index += 1;
      }
      throw new Error("unterminated object");
    }
    if (text[index] === "[") {
      index += 1;
      whitespace();
      if (text[index] === "]") { index += 1; return; }
      while (index < text.length) {
        value();
        whitespace();
        if (text[index] === "]") { index += 1; return; }
        if (text[index] !== ",") throw new Error("expected comma");
        index += 1;
      }
      throw new Error("unterminated array");
    }
    if (text[index] === '"') { stringToken(); return; }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(index));
    if (!match) throw new Error("invalid JSON value");
    index += match[0].length;
  }
  value();
  whitespace();
  if (index !== text.length) throw new Error("trailing JSON data");
}

function quoteAscii(value) {
  let output = '"';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x22) output += '\\"';
    else if (code === 0x5c) output += "\\\\";
    else if (code === 0x08) output += "\\b";
    else if (code === 0x0c) output += "\\f";
    else if (code === 0x0a) output += "\\n";
    else if (code === 0x0d) output += "\\r";
    else if (code === 0x09) output += "\\t";
    else if (code < 0x20 || code > 0x7e) output += `\\u${code.toString(16).padStart(4, "0")}`;
    else output += value[index];
  }
  return output + '"';
}

function canonical(value, path = "$") {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return quoteAscii(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${path}: non-interoperable number`);
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonical(item, `${path}[${index}]`)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.some((key) => !/^[\x00-\x7f]*$/.test(key))) throw new Error(`${path}: non-ASCII key`);
    keys.sort();
    return `{${keys.map((key) => `${quoteAscii(key)}:${canonical(value[key], `${path}.${key}`)}`).join(",")}}`;
  }
  throw new Error(`${path}: unsupported value`);
}

function canonicalHash(value) {
  return crypto.createHash("sha256").update(Buffer.from(canonical(value), "ascii")).digest("hex");
}

function checkedName(value, label) {
  if (typeof value !== "string" || value.length > 128 || !NAME.test(value)) throw new Error(`${label}_invalid`);
  return value;
}

function normalizeDefinition(definition) {
  if (!sameKeys(definition, ["profile", "definition_id", "version", "action_type", "fields"])) {
    throw new Error("definition_shape_invalid");
  }
  if (definition.profile !== "openline.field_tier_definition/v1") throw new Error("definition_profile_invalid");
  const definitionId = checkedName(definition.definition_id, "definition_id");
  const actionType = checkedName(definition.action_type, "action_type");
  if (typeof definition.version !== "string" || !definition.version || definition.version.length > 64) {
    throw new Error("definition_version_invalid");
  }
  if (!Array.isArray(definition.fields) || definition.fields.length > 128) throw new Error("definition_fields_invalid");
  const fieldNames = new Set();
  const attributes = new Set();
  const fields = definition.fields.map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw) || !TIERS.has(raw.tier)) {
      throw new Error("definition_field_invalid");
    }
    const keys = ["field", "tier", "type", "optional"];
    if (raw.tier === "policy") keys.push("attribute");
    if (raw.tier === "derived") keys.push("projections");
    if (!sameKeys(raw, keys)) throw new Error(`definition_field_shape_invalid:${raw.tier}`);
    const field = checkedName(raw.field, "field_name");
    if (fieldNames.has(field)) throw new Error(`definition_field_duplicate:${field}`);
    fieldNames.add(field);
    if (!TYPES.has(raw.type)) throw new Error(`definition_field_type_invalid:${field}`);
    if (typeof raw.optional !== "boolean") throw new Error(`definition_optional_invalid:${field}`);
    const normalized = { field, tier: raw.tier, type: raw.type, optional: raw.optional };
    if (raw.tier === "policy") {
      const attribute = checkedName(raw.attribute, "attribute_name");
      if (attributes.has(attribute)) throw new Error(`definition_attribute_duplicate:${attribute}`);
      attributes.add(attribute);
      normalized.attribute = attribute;
    }
    if (raw.tier === "derived") {
      if (!Array.isArray(raw.projections) || raw.projections.length === 0 || raw.projections.length > 16) {
        throw new Error(`definition_projections_invalid:${field}`);
      }
      normalized.projections = raw.projections.map((projection) => {
        if (!sameKeys(projection, ["attribute", "projector", "type"])) {
          throw new Error(`definition_projection_shape_invalid:${field}`);
        }
        const attribute = checkedName(projection.attribute, "attribute_name");
        const projector = checkedName(projection.projector, "projector_name");
        if (!TYPES.has(projection.type)) throw new Error(`definition_projection_type_invalid:${attribute}`);
        if (attributes.has(attribute)) throw new Error(`definition_attribute_duplicate:${attribute}`);
        attributes.add(attribute);
        return { attribute, projector, type: projection.type };
      }).sort((left, right) => asciiCompare(left.attribute, right.attribute));
    }
    return normalized;
  }).sort((left, right) => asciiCompare(left.field, right.field));
  return {
    profile: "openline.field_tier_definition/v1",
    definition_id: definitionId,
    version: definition.version,
    action_type: actionType,
    fields,
  };
}

function tierView(definition) {
  const checked = normalizeDefinition(definition);
  return {
    profile: "openline.applied_field_tiers/v1",
    action_type: checked.action_type,
    fields: checked.fields.map((field) => ({
      field: field.field,
      tier: field.tier,
      optional: field.optional,
      projections: field.tier === "derived"
        ? field.projections.map((projection) => projection.projector).sort()
        : [],
    })),
  };
}

function verifyReceipt(receipt, trustedKeys) {
  const errors = [];
  const body = { ...receipt };
  const signature = body.signature;
  const payloadHash = body.payload_hash;
  delete body.signature;
  delete body.payload_hash;
  try {
    const bytes = Buffer.from(canonical(body), "ascii");
    if (payloadHash !== crypto.createHash("sha256").update(bytes).digest("hex")) errors.push("payload_hash_mismatch");
    if (!sameKeys(signature, ["algorithm", "public_key", "value"]) || signature.algorithm !== "Ed25519") {
      errors.push("unsupported_signature_algorithm");
    } else {
      const raw = Buffer.from(signature.public_key, "hex");
      const value = Buffer.from(signature.value, "hex");
      if (raw.length !== 32 || value.length !== 64) errors.push("invalid_signature_encoding");
      else {
        const prefix = Buffer.from("302a300506032b6570032100", "hex");
        const key = crypto.createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" });
        if (!crypto.verify(null, bytes, key, value)) errors.push("signature_invalid");
      }
    }
  } catch (error) {
    errors.push(`canonicalization_error:${error.message}`);
  }
  const embeddedKey = signature?.public_key;
  if (!trustedKeys.has(embeddedKey)) errors.push("gate_key_not_trusted");
  if (!sameKeys(receipt, [
    "kind", "receipt_version", "canonicalization_id", "issuer", "created_at",
    "action", "disclosure", "decision", "authority", "payload_hash", "signature",
  ])) errors.push("field_tier_receipt_shape_invalid");
  if (receipt.kind !== "openline_field_tier_receipt") errors.push("field_tier_receipt_kind_invalid");
  if (receipt.receipt_version !== "1") errors.push("field_tier_receipt_version_invalid");
  if (receipt.canonicalization_id !== "olp-canonical-json-int-v1") errors.push("field_tier_canonicalization_invalid");
  if (typeof receipt.created_at !== "string" || Number.isNaN(Date.parse(receipt.created_at))) errors.push("field_tier_timestamp_invalid");
  if (!sameKeys(receipt.issuer, ["id"]) || typeof receipt.issuer.id !== "string" || !receipt.issuer.id) {
    errors.push("field_tier_issuer_invalid");
  }

  if (!sameKeys(receipt.action, ["type", "parameters_hash", "parameters_size_bytes"])) {
    errors.push("field_tier_action_invalid");
  } else {
    try { checkedName(receipt.action.type, "action_type"); } catch { errors.push("field_tier_action_type_invalid"); }
    if (!HASH.test(receipt.action.parameters_hash || "")) errors.push("field_tier_parameters_hash_invalid");
    if (!Number.isSafeInteger(receipt.action.parameters_size_bytes) || receipt.action.parameters_size_bytes < 2) {
      errors.push("field_tier_parameters_size_invalid");
    }
  }

  if (!sameKeys(receipt.disclosure, [
    "definition", "definition_hash", "applied_tiers_hash", "attributes_hash",
    "raw_parameters_stored", "minimized_attributes_stored",
  ])) {
    errors.push("field_tier_disclosure_invalid");
  } else {
    if (receipt.disclosure.raw_parameters_stored !== false) errors.push("raw_parameters_retained");
    if (receipt.disclosure.minimized_attributes_stored !== false) errors.push("minimized_attributes_retained");
    for (const name of ["definition_hash", "applied_tiers_hash", "attributes_hash"]) {
      if (!HASH.test(receipt.disclosure[name] || "")) errors.push(`field_tier_${name}_invalid`);
    }
    try {
      const definition = normalizeDefinition(receipt.disclosure.definition);
      if (canonicalHash(definition) !== receipt.disclosure.definition_hash) errors.push("field_tier_definition_hash_mismatch");
      if (canonicalHash(tierView(definition)) !== receipt.disclosure.applied_tiers_hash) errors.push("field_tier_applied_tiers_hash_mismatch");
      if (definition.action_type !== receipt.action?.type) errors.push("field_tier_definition_action_mismatch");
    } catch (error) {
      errors.push(`field_tier_definition_invalid:${error.message}`);
    }
  }

  if (!sameKeys(receipt.decision, ["value", "policy_id", "receiver_decision_hash"])) {
    errors.push("field_tier_decision_binding_invalid");
  } else {
    if (!DECISIONS.has(receipt.decision.value)) errors.push("field_tier_decision_invalid");
    try { checkedName(receipt.decision.policy_id, "policy_id"); } catch { errors.push("field_tier_policy_id_invalid"); }
    if (!HASH.test(receipt.decision.receiver_decision_hash || "")) errors.push("field_tier_receiver_decision_hash_invalid");
  }
  if (!sameKeys(receipt.authority, ["status", "portable_execution_authority"])
      || receipt.authority.status !== "EVIDENCE_ONLY"
      || receipt.authority.portable_execution_authority !== false) {
    errors.push("field_tier_authority_boundary_invalid");
  }
  const unique = [...new Set(errors)].sort();
  return {
    valid: unique.length === 0,
    public_integrity_valid: unique.length === 0,
    errors: unique,
    payload_hash: receipt.payload_hash,
    gate_public_key: embeddedKey,
    gate_key_trusted: trustedKeys.has(embeddedKey),
    candidate_parameters_status: "NOT_CHECKED_BY_NODE_VERIFIER",
    authority: "EVIDENCE_ONLY",
  };
}

function usage() {
  console.error("usage: node verify-field-tier-node.mjs <receipt.json> --gate-key <hex> [--gate-key <hex> ...]");
}

const args = process.argv.slice(2);
if (args.length < 3) { usage(); process.exit(2); }
const trustedKeys = new Set();
for (let index = 1; index < args.length; index += 1) {
  if (args[index] !== "--gate-key" || index + 1 >= args.length) { usage(); process.exit(2); }
  const key = args[index + 1].replace(/^ed25519:/, "");
  if (!HASH.test(key)) { console.error("gate key must be 32-byte lowercase hex"); process.exit(2); }
  trustedKeys.add(key);
  index += 1;
}
if (trustedKeys.size === 0) { usage(); process.exit(2); }

let result;
try {
  const text = fs.readFileSync(args[0], "utf8");
  rejectDuplicateKeys(text);
  result = verifyReceipt(JSON.parse(text), trustedKeys);
} catch {
  result = {
    valid: false,
    public_integrity_valid: false,
    errors: ["json_parse_error"],
    candidate_parameters_status: "NOT_CHECKED_BY_NODE_VERIFIER",
    authority: "EVIDENCE_ONLY",
  };
}
console.log(JSON.stringify(result, null, 2));
process.exit(result.valid ? 0 : 1);
