# Baseline B: Envoy + OPA with stateful controls where practical.
# Same bearer-token check, PLUS:
#   - token allowlist in OPA data (data.valid_tokens)
#   - revocation list in OPA data (data.revoked_tokens), writable via the
#     Data API at runtime (revocation = data write + re-evaluation)
#   - decision logs enabled (see opa-config-b.yaml)
# What OPA still does not do here (genuine, not a weakened baseline):
#   - no replay/nonce tracking (repeated requests look fresh)
#   - no cryptographic binding between decision and action
#   - decision logs are unsigned and prove evaluation, not enforcement
package envoy.authz

import rego.v1

default allow := false

_bearer := substring(input.attributes.request.http.headers.authorization, 7, -1) if {
	startswith(input.attributes.request.http.headers.authorization, "Bearer ")
}

allow if {
	startswith(input.attributes.request.http.path, "/api/")
	data.valid_tokens[_bearer]
	not data.revoked_tokens[_bearer]
}

headers["x-opa-decision"] := "allow" if {
	allow
}
