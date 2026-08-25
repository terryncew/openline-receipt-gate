# OpenLine authority stack: composition milestone

AUTHORITY-STACK-001 is the pencils-down integration proof for the current internal authority architecture. It deliberately adds no new enforcement primitive.

The stack under test is:

```text
policy / mandate authoring
        -> receiver-pinned mandate ownership
        -> exact-action approval evidence
        -> receiver-recognized standing
        -> Authority Compiler
        -> Receipt Gate / Verified Commit
        -> exact effect
```

The experiment asks whether those pieces can compose without hidden mutation, bypass logic, duplicated authority semantics, or cross-layer rescue.

## Important correction exposed by composition

A mandate successor cannot legitimately restore an action whose standing remains revoked. Mandate authority and action standing are separate authorities. Therefore the canonical sequence requires a separate receiver-admitted standing successor before execution can return.

That is a feature of the composition proof. If admitting a new mandate implicitly changed standing, OpenLine would have collapsed two distinct authority boundaries into one.

## What a passing run establishes

A passing run supports four bounded software claims:

1. **Authorship is not authority.** The developer's broader mandate proposal cannot govern until the receiver-pinned owner admits a mandate.
2. **A valid receipt is not current standing.** The exact approval receipt can remain correctly signed and unchanged while execution becomes blocked.
3. **Standing loss is selective.** A standing change for one exact support/action pair does not globally halt unrelated authorized work.
4. **Governance is current-head based.** A superseded mandate authorization remains authentic history, but only the current receiver-admitted mandate determines the effect ceiling for new actions.

The benchmark also checks that a mandate change does not silently repair revoked standing.

## No new primitive

This PR should add only benchmark, test, and documentation files. It should not modify `olp_gate/` production modules. The runtime path is the existing `LocalAuthorityRuntime`; the authorization path is the existing `authorize_owned(...)` composition with `standing_requirement_source(...)`.

If the test cannot pass under those constraints, record `AUTHORITY_STACK_COMPOSITION_GAP` rather than adding a rescue layer.

## After this milestone

A green result closes the current internal mechanism-building phase. Further architectural work should be pulled by external interoperability or deployment friction rather than by another internally invented authority primitive.
