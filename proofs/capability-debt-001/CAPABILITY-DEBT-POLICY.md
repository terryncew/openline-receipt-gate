# Capability Economics Policy

Frozen 2026-09-16. Status: POLICY — governs all future experiment and
implementation spend in this repo. This is a procedure, not an authorization
to build anything.

## The rule

Three kinds of spend. Each is justified by a different repayment.

**EXPLORATION** — allowed to lose both money and reuse, but only cheaply.
Spend is justified by information: does the missing thing exist, and does it
matter at all. This is where the tiny falsifier belongs. Exploration never
borrows against the future; it pays cash and expects nothing back.

**CAPABILITY DEBT** — R&D. Spend is justified by acquiring a named primitive
that expands what the system can do. Debt is admitted only when all four hold:

- the missing capability has already been demonstrated;
- the build is general infrastructure, not test scaffolding;
- a debt ceiling is frozen beforehand;
- a reassessment point is frozen beforehand.

**PAYBACK** — operating improvement. Spend is justified by measured economic
repayment. No measured repayment, no optimization spend.

The sequence: Explore cheaply → acquire capability deliberately → optimize
only when payback is measurable.

The distinction: Optimization must repay cash. Capability R&D must repay reuse.

## The independence safeguard

Reuse only counts if it is independent and unchanged enough to be credible.
Otherwise you can accidentally manufacture "reuse" by designing two follow-on
experiments around the thing you just built.

At reassessment the question is:

Did at least two genuinely independent uses consume the primitive largely
unchanged?

- Yes → infrastructure earned. The debt converts to an asset.
- No → treat the spend as research loss / specialized machinery, not an
  accumulating platform asset.

Independence is judged, not assumed. A use counts when it serves a different
downstream question than the one that motivated the build, was not designed
around the primitive, and consumes the original machinery largely unchanged.
Two experiments built to exercise the new primitive do not count.

## Frozen instantiation: coalition

The first debt this policy would admit, if authorized:

- Debt purchased: mandate-scoped authority derivation with shared
  cumulative-origin bounds.
- Debt ceiling: implementation + tests + maintenance surface, bounded to the
  planned production primitive (estimated ~1,000 lines + ~400 tests).
- Reassessment: after two independent downstream uses or first external
  receiver integration, whichever comes first.
- Success: substantial reuse of the original derivation/verification machinery
  without coalition-specific rewrites.
- Failure: subsequent uses require materially new bespoke authority machinery.

This instantiation is a frozen example. It is NOT an authorization to build.
Building the derivation primitive additionally requires Terrynce's explicit
implementation authorization, a frozen semantic contract, and a frozen
discriminating test. None exist yet; demand is unproven.

## Non-movable parts

- The debt ceiling and reassessment point are frozen before the build starts.
  Moving them after the fact is the same failure as moving an experiment
  threshold.
- The "two independent uses" criterion is fixed. Independence is judged at
  reassessment against the safeguard above.
- Exploration spend stays cheap. A falsifier that gets expensive has become
  capability debt and needs the debt procedure.
