# Benchmark-only replacement of principal mandate fit evaluation.
# The Gateway validates and normalizes inputs before querying this policy.
# Gateway remains responsible for crypto, durable replay state, live agent
# revocation, standing, decision binding and signed receipts.
package gateway_mandate

import rego.v1

reason contains "mandate_expired" if { input.expires_at_seconds <= input.now_seconds }
reason contains sprintf("%s_mismatch", [field]) if {
    some field in {"mandate_id", "principal_id", "agent_id", "purpose"}
    input.effect[field] != input.mandate[field]
}
reason contains "action_not_allowed" if {
    not input.effect.action_type in input.mandate.allowed_action_types
}
reason contains "target_not_allowed" if {
    count(input.mandate.allowed_targets) > 0
    not input.effect.target in input.mandate.allowed_targets
}
reason contains "forbidden_disclosure" if {
    some disclosure in input.effect.disclosures
    disclosure in input.mandate.forbidden_disclosure_classes
}
reason contains "disclosure_outside_allowlist" if {
    some disclosure in input.effect.disclosures
    not disclosure in input.mandate.allowed_disclosure_classes
}
reason contains "settlement_limit_exceeded" if {
    input.effect.action_type == "accept_settlement"
    input.effect.value_cents > input.mandate.max_settlement_cents
}
reason contains "payment_limit_exceeded" if {
    input.effect.action_type == "authorize_payment"
    input.effect.value_cents > input.mandate.max_payment_cents
}
reason contains "delegation_not_allowed" if {
    input.effect.action_type == "delegate"
    not input.mandate.delegation_allowed
}
reason contains "delegatee_missing" if {
    input.effect.action_type == "delegate"
    input.effect.delegatee == null
}
reason contains "unexpected_delegatee" if {
    input.effect.action_type != "delegate"
    input.effect.delegatee != null
}

decision := {"allowed": count(reason) == 0, "reason_codes": sort(reason)}
