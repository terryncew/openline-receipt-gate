# Adapt the historical policy result to the official native Envoy plugin's
# object contract. The authorization policy itself remains unchanged.
package latency_native

import rego.v1

decision := {"allowed": data.envoy.authz.allow, "headers": data.envoy.authz.headers}
