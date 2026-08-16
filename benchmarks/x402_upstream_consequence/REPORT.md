# Result: a real upstream consequence-order loss, blocked at release

**Disposition:** `PASS — REPRODUCED_ON_PINNED_UPSTREAM`

The runner executed the official asynchronous Python MCP wrapper from
`x402-foundation/x402` at commit
`167a828e8319aa7b403f4f4312489e9cffadff10`.

| Observation | Returned error | Settlement calls | Durable/protected effects |
|---|---:|---:|---:|
| Official wrapper, settlement fails | yes | 1 | **1** |
| Receipt Gate airlock, settlement fails | exception surfaced | 1 | **0** |
| Official wrapper, settlement succeeds | no | 1 | **1** |
| Receipt Gate airlock, settlement confirms | no | 1 | **1** |

The official wrapper's source also places the handler call at line 221 and the
settlement call at line 267. The behavior is therefore unsurprising but no
longer merely inferred from reading code: the failed run left an actual file
effect behind.

Receipt Gate did not make the settlement succeed. It changed which consequence
was allowed to occur before success was known. Under failure, payment
settlement was attempted and the protected resource was not released. Under
the legitimate control, it was released once.

The independent verifier passed with no errors. It rechecked the Git commit,
source SHA-256, AST call order, serialized observations, and exact effect-file
bytes without importing Receipt Gate code.

## Claim earned

For this pinned official Python MCP wrapper, an effectful tool can run before a
settlement failure is known. The disclosed Receipt Gate composition places the
protected resource effect after matching settlement confirmation and therefore
withholds it in that failure.

## Claim not earned

This is not evidence that every x402 implementation is vulnerable, that a
live-chain exploit occurred, that money was lost, or that Receipt Gate is a
complete payment-security product. The TypeScript implementation and later
Python commits may use different ordering. The result is a reproducible wedge,
not a declaration of universal superiority.

