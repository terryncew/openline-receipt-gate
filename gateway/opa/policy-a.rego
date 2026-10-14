# Baseline A: ordinary Envoy + OPA.
# A competent, straightforward OPA deployment: bearer-token check in Rego,
# no external state, no revocation list. This is the honest "what most
# teams actually run" baseline — not weakened, not augmented.
package envoy.authz

import rego.v1

default allow := false

allow if {
	startswith(input.attributes.request.http.path, "/api/")
	input.attributes.request.http.headers.authorization == "Bearer opaline-token-001"
}

headers["x-opa-decision"] := "allow" if {
	allow
}
