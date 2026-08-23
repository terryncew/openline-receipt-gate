# Normal workflow — Authority Compiler

Repository: `terryncew/openline-receipt-gate`

Base: `main@0cb6544889f19268528e26a84c4bfaa843352d30`

## Branch

```text
feat/authority-compiler
```

## Commit

```text
feat(gate): add receipt-native authority compiler
```

## PR title

```text
Authority Compiler: unify proposal, mandate, evidence, and Verified Commit
```

## Merge

```text
feat/authority-compiler → main
```

Overlay this ZIP at repository root. Do not place the enclosing folder inside
the repository.

Require the normal `release-check`, existing DPL workflows, and the new
`authority-compiler` workflow to be green before merge.

DPL-001 and DPL-002 remain frozen. Do not create DPL-003. DPL-002's surviving
disposition is `CAPABILITY_PARITY`.
