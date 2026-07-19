#!/usr/bin/env node

// Independent verifier for OpenLine proof-to-policy decision receipts.

import crypto from "node:crypto";
import fs from "node:fs";

// JSON.parse keeps the final value of a duplicate key.  Signed protocols must
// reject that ambiguity before parsing, so this small recursive scanner checks
// every object scope independently.
function rejectDuplicateKeys(text) {
  let index = 0;
  const whitespace = () => { while (/\s/.test(text[index] || '')) index += 1; };
  function stringToken() {
    const start = index;
    if (text[index] !== '"') throw new Error('expected string');
    index += 1;
    while (index < text.length) {
      if (text[index] === '\\') index += 2;
      else if (text[index] === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index));
      } else index += 1;
    }
    throw new Error('unterminated string');
  }
  function value() {
    whitespace();
    if (text[index] === '{') {
      index += 1;
      const keys = new Set();
      whitespace();
      if (text[index] === '}') { index += 1; return; }
      while (index < text.length) {
        whitespace();
        const key = stringToken();
        if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
        keys.add(key);
        whitespace();
        if (text[index] !== ':') throw new Error('expected colon');
        index += 1;
        value();
        whitespace();
        if (text[index] === '}') { index += 1; return; }
        if (text[index] !== ',') throw new Error('expected comma');
        index += 1;
      }
      throw new Error('unterminated object');
    }
    if (text[index] === '[') {
      index += 1;
      whitespace();
      if (text[index] === ']') { index += 1; return; }
      while (index < text.length) {
        value();
        whitespace();
        if (text[index] === ']') { index += 1; return; }
        if (text[index] !== ',') throw new Error('expected comma');
        index += 1;
      }
      throw new Error('unterminated array');
    }
    if (text[index] === '"') { stringToken(); return; }
    const tail = text.slice(index);
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(tail);
    if (!match) throw new Error('invalid JSON value');
    index += match[0].length;
  }
  value();
  whitespace();
  if (index !== text.length) throw new Error('trailing JSON data');
}

function quoteAscii(value) {
  let output = '"';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x22) output += '\\"';
    else if (code === 0x5c) output += '\\\\';
    else if (code === 0x08) output += '\\b';
    else if (code === 0x0c) output += '\\f';
    else if (code === 0x0a) output += '\\n';
    else if (code === 0x0d) output += '\\r';
    else if (code === 0x09) output += '\\t';
    else if (code < 0x20 || code > 0x7e) output += `\\u${code.toString(16).padStart(4, '0')}`;
    else output += value[index];
  }
  return output + '"';
}

function canonical(value, path = '$') {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'string') return quoteAscii(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error(`${path}: non-interoperable number`);
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map((item, i) => canonical(item, `${path}[${i}]`)).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.some((key) => !/^[\x00-\x7f]*$/.test(key))) throw new Error(`${path}: non-ASCII key`);
    keys.sort();
    return `{${keys.map((key) => `${quoteAscii(key)}:${canonical(value[key], `${path}.${key}`)}`).join(',')}}`;
  }
  throw new Error(`${path}: unsupported value`);
}

function chooseDecision(receipt) {
  const policy = receipt.policy?.snapshot;
  const assessments = receipt.assessments;
  const action = receipt.action;
  if (!policy || !assessments || !action) throw new Error('decision semantic inputs missing');
  const noBadge = (policy.no_badge_action_types || ['eval_score_claim']).includes(action.type);
  const outcome = assessments.outcome;
  const harmful = outcome.status === 'pass' && outcome.details?.harmful === true;
  if (harmful) {
    if (policy.rollback_on_harm === true && outcome.details?.rollback_supported === true) {
      return ['REJECTED', 'ROLLBACK_REQUEST'];
    }
    return ['REJECTED', 'DENY'];
  }
  const sourceSignalNames = ['0.3', '0.4'].includes(receipt.receipt_version) ? ['source_signal'] : [];
  const verifiedCommitNames = receipt.receipt_version === '0.4' ? ['verified_commit'] : [];
  if (['integrity', 'profile', 'freshness', ...sourceSignalNames, ...verifiedCommitNames].some((name) => assessments[name]?.status === 'fail')) {
    return ['REJECTED', noBadge ? 'NO_BADGE' : 'DENY'];
  }
  if ((policy.deny_risk_levels || []).includes(action.risk_level)) return ['REJECTED', 'DENY'];
  if (assessments.evidence?.status === 'fail' || assessments.outcome?.status === 'fail') {
    return ['REJECTED', noBadge ? 'NO_BADGE' : 'DENY'];
  }
  const required = ['integrity', 'profile', 'freshness', ...sourceSignalNames];
  if (policy.require_trusted_source === true) required.push('provenance');
  if (policy.require_independent_source === true) required.push('independence');
  if (policy.require_declared_coverage === true) required.push('coverage');
  if (policy.require_evidence === true) required.push('evidence');
  if (policy.require_outcome_witness === true) required.push('outcome');
  if (assessments.verified_commit?.details?.required === true) required.push('verified_commit');
  if (required.some((name) => assessments[name]?.status !== 'pass')) {
    return ['UNDECIDABLE', noBadge ? 'NO_BADGE' : 'QUARANTINE'];
  }
  return ['VERIFIED', 'COMMIT'];
}

function sha256Canonical(value) {
  return crypto.createHash('sha256').update(Buffer.from(canonical(value), 'ascii')).digest('hex');
}

function isHash(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function validateCommitAuthorization(receipt) {
  const errors = [];
  const details = receipt.assessments?.verified_commit?.details || {};
  const required = details.required === true;
  const authorization = receipt.commit_authorization;
  if (!required) {
    if (authorization !== null && authorization !== undefined) errors.push('unexpected_commit_authorization');
    return errors;
  }
  if (receipt.decision !== 'COMMIT' || receipt.verdict !== 'VERIFIED') {
    if (authorization !== null && authorization !== undefined) errors.push('noncommit_authorization_present');
    return errors;
  }
  if (!authorization || typeof authorization !== 'object' || Array.isArray(authorization)) {
    return ['commit_authorization_missing'];
  }
  const expectedAuthorizationFields = [
    'profile', 'tool', 'target', 'settings_hash', 'run_id', 'capsule_hash',
    'evidence_hashes', 'policy_hash', 'expires_at', 'one_use_code_hash',
    'action_hash', 'authorization_hash',
  ].sort();
  if (Object.keys(authorization).sort().join('\u001f') !== expectedAuthorizationFields.join('\u001f')) {
    errors.push('commit_authorization_shape_invalid');
  }
  if (authorization.profile !== 'verified_commit/v1') errors.push('commit_authorization_profile_invalid');
  for (const name of ['tool', 'target', 'run_id']) {
    if (typeof authorization[name] !== 'string' || !authorization[name]) errors.push(`commit_authorization_${name}_invalid`);
  }
  for (const name of [
    'settings_hash', 'capsule_hash', 'policy_hash', 'one_use_code_hash',
    'action_hash', 'authorization_hash',
  ]) if (!isHash(authorization[name])) errors.push(`commit_authorization_${name}_invalid`);
  if (
    !Array.isArray(authorization.evidence_hashes)
    || !authorization.evidence_hashes.every(isHash)
    || new Set(authorization.evidence_hashes).size !== authorization.evidence_hashes.length
    || JSON.stringify([...authorization.evidence_hashes].sort()) !== JSON.stringify(authorization.evidence_hashes)
  ) errors.push('commit_authorization_evidence_hashes_invalid');

  if (authorization.policy_hash !== receipt.policy?.hash) errors.push('commit_authorization_policy_mismatch');
  if (authorization.run_id !== receipt.binding?.run_id) errors.push('commit_authorization_run_mismatch');
  const actualEvidence = Object.values(receipt.assessments?.evidence?.details?.artifact_hashes || {}).sort();
  if (JSON.stringify(actualEvidence) !== JSON.stringify(authorization.evidence_hashes || [])) {
    errors.push('commit_authorization_evidence_mismatch');
  }

  const verifiedPolicy = receipt.policy?.snapshot?.metadata?.verified_commit;
  const expectedPolicyFields = [
    'required', 'tool', 'target', 'settings_hash', 'run_id', 'capsule_hash',
    'evidence_hashes', 'max_ttl_seconds',
  ].sort();
  if (!verifiedPolicy || typeof verifiedPolicy !== 'object' || Array.isArray(verifiedPolicy)) {
    errors.push('verified_commit_policy_missing');
  } else {
    if (Object.keys(verifiedPolicy).sort().join('\u001f') !== expectedPolicyFields.join('\u001f')) {
      errors.push('verified_commit_policy_shape_invalid');
    }
    if (verifiedPolicy.required !== true) errors.push('verified_commit_policy_not_required');
    try {
      for (const name of ['tool', 'target', 'settings_hash', 'run_id', 'capsule_hash', 'evidence_hashes']) {
        if (canonical(authorization[name]) !== canonical(verifiedPolicy[name])) {
          errors.push(`commit_authorization_policy_${name}_mismatch`);
        }
      }
    } catch {
      errors.push('verified_commit_policy_canonicalization_unsupported');
    }
    if (!Number.isSafeInteger(verifiedPolicy.max_ttl_seconds) || verifiedPolicy.max_ttl_seconds <= 0) {
      errors.push('verified_commit_policy_ttl_invalid');
    }
  }

  try {
    const actionBinding = {
      tool: authorization.tool,
      target: authorization.target,
      settings_hash: authorization.settings_hash,
      run_id: authorization.run_id,
      capsule_hash: authorization.capsule_hash,
      evidence_hashes: authorization.evidence_hashes,
      policy_hash: authorization.policy_hash,
    };
    if (authorization.action_hash !== sha256Canonical(actionBinding)) {
      errors.push('commit_authorization_action_hash_mismatch');
    }
    const body = { ...authorization };
    delete body.authorization_hash;
    if (authorization.authorization_hash !== sha256Canonical(body)) {
      errors.push('commit_authorization_hash_mismatch');
    }
  } catch {
    errors.push('commit_authorization_canonicalization_unsupported');
  }

  const created = Date.parse(receipt.created_at);
  const expires = Date.parse(authorization.expires_at);
  if (Number.isNaN(expires)) errors.push('commit_authorization_expiry_invalid');
  else if (Number.isNaN(created) || expires <= created) errors.push('commit_authorization_expiry_not_after_issue');
  else if (
    verifiedPolicy
    && Number.isSafeInteger(verifiedPolicy.max_ttl_seconds)
    && expires - created > verifiedPolicy.max_ttl_seconds * 1000
  ) errors.push('commit_authorization_ttl_exceeds_policy');

  try {
    if (!details.authorization || canonical(details.authorization) !== canonical(authorization)) {
      errors.push('commit_authorization_assessment_mismatch');
    }
  } catch {
    errors.push('commit_authorization_assessment_canonicalization_unsupported');
  }
  if (details.raw_settings_stored !== false) errors.push('commit_authorization_settings_privacy_invalid');
  if (details.raw_one_use_code_stored !== false) errors.push('commit_authorization_code_privacy_invalid');
  return [...new Set(errors)].sort();
}

function recomputedReasons(assessments) {
  const reasons = [];
  Object.entries(assessments).forEach(([name, check]) => {
    (check.reason_codes || []).forEach((reason) => reasons.push(`${name}:${reason}`));
  });
  return [...new Set(reasons)].sort();
}

function validatePolicy(policy) {
  const fields = [
    'policy_id', 'version', 'require_trusted_source', 'require_independent_source',
    'require_declared_coverage', 'require_replay_guard', 'require_evidence',
    'require_source_bound_evidence', 'require_outcome_witness', 'required_evidence_ids',
    'required_claim_ids', 'evidence_assertions', 'max_source_age_seconds',
    'max_evidence_bytes', 'no_badge_action_types', 'deny_risk_levels', 'rollback_on_harm', 'metadata',
  ];
  if (!policy || Object.keys(policy).sort().join('\u001f') !== [...fields].sort().join('\u001f')) {
    throw new Error('policy_field_set_invalid');
  }
  if (typeof policy.policy_id !== 'string' || !policy.policy_id || typeof policy.version !== 'string' || !policy.version) {
    throw new Error('policy_identity_invalid');
  }
  for (const name of [
    'require_trusted_source', 'require_independent_source', 'require_declared_coverage',
    'require_replay_guard', 'require_evidence', 'require_source_bound_evidence',
    'require_outcome_witness', 'rollback_on_harm',
  ]) if (typeof policy[name] !== 'boolean') throw new Error(`policy_boolean_invalid:${name}`);
  for (const name of ['required_evidence_ids', 'required_claim_ids', 'no_badge_action_types', 'deny_risk_levels']) {
    if (!Array.isArray(policy[name]) || !policy[name].every((value) => typeof value === 'string')) {
      throw new Error(`policy_array_invalid:${name}`);
    }
  }
  if (!Array.isArray(policy.evidence_assertions) || !policy.evidence_assertions.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
    throw new Error('policy_assertions_invalid');
  }
  if (policy.max_source_age_seconds !== null && (!Number.isSafeInteger(policy.max_source_age_seconds) || policy.max_source_age_seconds < 0)) {
    throw new Error('policy_age_invalid');
  }
  if (!Number.isSafeInteger(policy.max_evidence_bytes) || policy.max_evidence_bytes < 1) throw new Error('policy_evidence_size_invalid');
  if (!policy.metadata || typeof policy.metadata !== 'object' || Array.isArray(policy.metadata)) throw new Error('policy_metadata_invalid');
}

function verifyReceipt(receipt, trustedGateKeys) {
  const errors = [];
  const body = { ...receipt };
  const signature = body.signature;
  const payloadHash = body.payload_hash;
  delete body.signature;
  delete body.payload_hash;
  try {
    const bytes = Buffer.from(canonical(body), 'ascii');
    const expectedHash = crypto.createHash('sha256').update(bytes).digest('hex');
    if (payloadHash !== expectedHash) errors.push('payload_hash_mismatch');
    if (!signature || signature.algorithm !== 'Ed25519') {
      errors.push('unsupported_signature_algorithm');
    } else {
      const raw = Buffer.from(signature.public_key, 'hex');
      const value = Buffer.from(signature.value, 'hex');
      if (raw.length !== 32 || value.length !== 64) {
        errors.push('invalid_signature_encoding');
      } else {
        const prefix = Buffer.from('302a300506032b6570032100', 'hex');
        const key = crypto.createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' });
        if (!crypto.verify(null, bytes, key, value)) errors.push('signature_invalid');
      }
    }
    if (!signature || !trustedGateKeys.has(signature.public_key)) errors.push('gate_key_not_trusted');
  } catch (error) {
    errors.push(`canonicalization_error:${error.message}`);
  }
  if (receipt.kind !== 'proof_to_policy_decision_receipt') errors.push('decision_profile_invalid');
  if (!['0.2', '0.3', '0.4'].includes(receipt.receipt_version)) errors.push('decision_version_unsupported');
  const expectedAlgorithm = {
    '0.2': 'openline-proof-to-policy-gate-0.2',
    '0.3': 'openline-proof-to-policy-gate-0.3',
    '0.4': 'openline-proof-to-policy-gate-0.4',
  }[receipt.receipt_version];
  if (receipt.algorithm_id !== expectedAlgorithm) errors.push('decision_algorithm_unsupported');
  if (receipt.canonicalization_id !== 'olp-canonical-json-int-v1') errors.push('decision_canonicalization_unsupported');
  if (typeof receipt.created_at !== 'string' || Number.isNaN(Date.parse(receipt.created_at))) {
    errors.push('decision_timestamp_invalid');
  }
  if (!receipt.issuer || typeof receipt.issuer.id !== 'string' || !receipt.issuer.id) errors.push('decision_issuer_invalid');
  if (typeof receipt.request_id !== 'string' || !receipt.request_id) errors.push('decision_request_id_invalid');
  if (!['VERIFIED', 'REJECTED', 'UNDECIDABLE'].includes(receipt.verdict)) errors.push('decision_verdict_invalid');
  if (!['COMMIT', 'QUARANTINE', 'DENY', 'NO_BADGE', 'ROLLBACK_REQUEST'].includes(receipt.decision)) {
    errors.push('decision_action_invalid');
  }
  if (!receipt.source || !receipt.binding) {
    errors.push('decision_binding_inputs_missing');
  } else {
    [['primary', receipt.source.primary_hash], ['expected', receipt.binding.expected_source_hash]].forEach(([name, value]) => {
      if (value !== null && value !== undefined && (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))) {
        errors.push(`decision_source_${name}_hash_invalid`);
      }
    });
  }
  if (
    !receipt.privacy
    || receipt.privacy.raw_evidence_stored !== false
    || receipt.privacy.raw_source_disclosure_stored !== false
  ) errors.push('decision_privacy_profile_invalid');
  try {
    if (!receipt.policy?.snapshot) throw new Error('policy_snapshot_missing');
    validatePolicy(receipt.policy.snapshot);
    const policyHash = crypto.createHash('sha256').update(Buffer.from(canonical(receipt.policy.snapshot), 'ascii')).digest('hex');
    if (policyHash !== receipt.policy.hash) errors.push('policy_hash_mismatch');
    if (receipt.policy.snapshot.policy_id !== receipt.policy.id || receipt.policy.snapshot.version !== receipt.policy.version) {
      errors.push('policy_identity_mismatch');
    }
    const validStatuses = new Set(['pass', 'fail', 'partial', 'unavailable']);
    const assessmentNames = ['integrity', 'profile', 'provenance', 'independence', 'coverage', 'freshness', 'evidence', 'outcome'];
    if (['0.3', '0.4'].includes(receipt.receipt_version)) assessmentNames.push('source_signal');
    if (receipt.receipt_version === '0.4') assessmentNames.push('verified_commit');
    for (const name of assessmentNames) {
      const check = receipt.assessments?.[name];
      if (
        !check
        || !validStatuses.has(check.status)
        || !Array.isArray(check.reason_codes)
        || !check.reason_codes.every((code) => typeof code === 'string')
        || !check.details
        || typeof check.details !== 'object'
        || Array.isArray(check.details)
      ) throw new Error(`assessment_shape_invalid:${name}`);
    }
    const expected = chooseDecision(receipt);
    if (receipt.verdict !== expected[0] || receipt.decision !== expected[1]) errors.push('decision_recompute_mismatch');
    if (JSON.stringify(receipt.reason_codes || []) !== JSON.stringify(recomputedReasons(receipt.assessments))) {
      errors.push('reason_codes_recompute_mismatch');
    }
    const replayStatus = receipt.assessments.freshness?.details?.replay_guard?.status;
    const expectedAccepted = receipt.policy.snapshot.require_replay_guard === true && replayStatus === 'pass';
    if (receipt.chain_accepted !== expectedAccepted) errors.push('chain_acceptance_recompute_mismatch');
  } catch (error) {
    errors.push(`decision_semantic_recompute_error:${error.message}`);
  }
  if (receipt.receipt_version === '0.4') {
    validateCommitAuthorization(receipt).forEach((error) => errors.push(error));
  } else if (receipt.commit_authorization !== null && receipt.commit_authorization !== undefined) {
    errors.push('legacy_commit_authorization_present');
  }
  return [...new Set(errors)].sort();
}

function verifyLog(path, trustedGateKeys) {
  const lines = fs.readFileSync(path, 'utf8').split(/\r?\n/).filter((line) => line.trim());
  const receipts = [];
  const errors = [];
  lines.forEach((line, index) => {
    try {
      rejectDuplicateKeys(line);
      const receipt = JSON.parse(line);
      verifyReceipt(receipt, trustedGateKeys).forEach((error) => errors.push(`receipt_${index + 1}:${error}`));
      receipts.push(receipt);
    } catch {
      errors.push(`json_parse_error:${index + 1}`);
    }
  });
  const sessions = new Map();
  receipts.forEach((receipt, index) => {
    const binding = receipt.binding || {};
    const key = `${binding.run_id}\u001f${binding.session_id}`;
    const state = sessions.get(key) || { sequence: 1, parent: null };
    if (receipt.chain_accepted === true) {
      if (binding.sequence !== state.sequence) errors.push(`receipt_${index + 1}:decision_sequence_mismatch`);
      if (binding.parent_decision_hash !== state.parent) errors.push(`receipt_${index + 1}:decision_parent_mismatch`);
      sessions.set(key, { sequence: state.sequence + 1, parent: receipt.payload_hash });
    }
  });
  return { valid: errors.length === 0, count: receipts.length, errors: [...new Set(errors)].sort() };
}

const args = process.argv.slice(2);
const gateKeys = new Set();
for (let index = 1; index < args.length; index += 1) {
  if (args[index] !== '--gate-key' || index + 1 >= args.length) {
    console.error('usage: node verify-decision-node.mjs <decision-receipts.jsonl> --gate-key <hex> [--gate-key <hex> ...]');
    process.exit(2);
  }
  const key = args[index + 1].replace(/^ed25519:/, '');
  if (!/^[0-9a-f]{64}$/.test(key)) {
    console.error('gate key must be 32-byte lowercase hex');
    process.exit(2);
  }
  gateKeys.add(key);
  index += 1;
}

if (args.length < 3 || gateKeys.size === 0) {
  console.error('usage: node verify-decision-node.mjs <decision-receipts.jsonl> --gate-key <hex> [--gate-key <hex> ...]');
  process.exit(2);
}

const result = verifyLog(args[0], gateKeys);
console.log(JSON.stringify(result, null, 2));
process.exit(result.valid ? 0 : 1);
