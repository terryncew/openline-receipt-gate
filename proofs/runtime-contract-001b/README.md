# RUNTIME-CONTRACT-001B — Frozen transitivity result

Status: **FROZEN**

Main after merge:

`58c5f63532ae2bf0f859146d50c1b2804a2e390d`

Workflow run:

`33937615382`

## Verdict

```text
TRANSITIVE_CONSEQUENCE_NOT_DISCOVERED
```

Before X lost standing:

```text
A executed  true
B executed  true
C executed  true
```

The fixture encoded:

```text
X -> A -> B
```

Specifically, A's signed decision receipt recorded X as its basis, and B used
that exact A receipt as its direct support. There was no explicit `X -> B`
standing update after the revocation.

After X was revoked:

```text
A blocked    true
B blocked    false
B executed   true
C executed   true
```

A was directly quarantined with:

`evidence_revoked:decision_standing`

The unrelated C control remained executable.

B also remained executable.

That is the falsifier.

## Source guard

The tested `olp_gate` tree remained byte-identical to the preregistered product
tree:

`5b7f139ad83f2f15b283270b94b46009889cbb4e`

No Claim Graph or dependency remedy was imported into the runtime under test.

## Frozen hashes

Result JSON SHA-256:

`44db09e4c229e7f5654059a64b047fbe31f22f4e67afd0b18ad6f89d91634f7f`

Artifact ZIP SHA-256:

`4aa21bb254b874a144b0cab19935003a2f39f0b2fbd84993ba86f429a89b2b81`

Preregistered freeze SHA-256:

`7ff13f1568ccb3f655ddf737bb1af37c1e8da18960b3ba2701ff6b27d2aa7ab2`

Artifact ID:

`9960693195`

## Earned conclusion

Current Receipt Gate standing enforcement is direct, not transitive.

If a directly supported decision becomes the support for another consequential
decision, later loss of the upstream basis is not discovered automatically by
the current runtime.

That earns an ancestry/closure mechanism.

It does **not** yet earn full Claim Graph semantics, partial-sufficiency rules,
production graph storage, or propagation guarantees.

## Next

Freeze the minimum ancestry/closure contract before implementing the remedy.
