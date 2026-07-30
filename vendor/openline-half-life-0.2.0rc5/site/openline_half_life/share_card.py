from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Mapping


def _rounded_percent(micros: int) -> int:
    magnitude = abs(micros)
    return (magnitude + 5_000) // 10_000


def describe_share_card(retirement_turn: int, comparison: Mapping[str, Any]) -> dict[str, str]:
    """Return the only public claim the comparison has earned."""

    delta = comparison["delta"]
    reduction_micros = int(delta["error_reduction_micros"])
    if comparison.get("passed") is True:
        return {
            "status": "COMPARISON PASSED",
            "headline": f"Agent retired after turn {retirement_turn}.",
            "subhead": (
                f"Verified handoff reduced errors by {_rounded_percent(reduction_micros)}% on the same exam."
            ),
        }

    if not comparison.get("legitimate_task_completion_preserved", False):
        reason = "Verified residue did not preserve legitimate task completion."
    elif reduction_micros > 0:
        reason = (
            f"Errors fell by {_rounded_percent(reduction_micros)}%, but the comparison gate failed."
        )
    elif reduction_micros < 0:
        reason = (
            f"Verified residue increased errors by {_rounded_percent(reduction_micros)}% on the same exam."
        )
    else:
        reason = "Verified residue did not reduce errors on the same exam."
    return {
        "status": "COMPARISON FAILED",
        "headline": "No verified handoff advantage established.",
        "subhead": reason,
    }


def render_share_card(
    path: Path,
    retirement_turn: int,
    comparison: Mapping[str, Any],
    compaction: Mapping[str, Any] | None = None,
) -> str:
    description = describe_share_card(retirement_turn, comparison)
    full = comparison["full_history"]["metrics"]
    residue = comparison["verified_residue"]["metrics"]
    compaction_line = ""
    if compaction is not None:
        if compaction.get("passed") is True:
            ratio = _rounded_percent(int(compaction["active_size_ratio_micros"]))
            compaction_line = (
                f'<div class="compaction">Causal capsule preserved exact receiver decisions at {ratio}% of active receipt size.</div>'
            )
        else:
            compaction_line = '<div class="compaction">Causal compaction not admitted: decision equivalence failed.</div>'
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenLine Half-Life Result</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #090c12; color: #f5f7fb; font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
.card {{ width: min(920px, 92vw); padding: clamp(32px, 7vw, 76px); border: 1px solid #2c3442; border-radius: 28px; background: linear-gradient(145deg, #121722, #0c1017); box-shadow: 0 30px 90px rgba(0,0,0,.42); }}
.eyebrow {{ font-size: 14px; letter-spacing: .16em; text-transform: uppercase; color: #9eacc1; }}
.status {{ display: inline-block; margin-top: 22px; padding: 8px 12px; border: 1px solid #3a4659; border-radius: 999px; font-size: 13px; font-weight: 700; letter-spacing: .08em; }}
h1 {{ margin: 24px 0 12px; font-size: clamp(42px, 7vw, 84px); line-height: .98; letter-spacing: -.045em; }}
.sub {{ margin: 0; max-width: 760px; color: #c8d1df; font-size: clamp(22px, 3vw, 34px); line-height: 1.2; }}
.metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-top: 42px; }}
.metric {{ padding: 18px; border-radius: 16px; background: #171d29; border: 1px solid #2a3342; }}
.label {{ color: #8f9db2; font-size: 13px; text-transform: uppercase; letter-spacing: .1em; }}
.value {{ margin-top: 8px; font-size: 28px; font-weight: 700; }}
.compaction {{ margin-top: 24px; padding: 16px 18px; border: 1px solid #2a3342; border-radius: 14px; color: #b8c4d6; background: #111722; font-size: 16px; }}
.footer {{ margin-top: 32px; color: #75849a; font-size: 14px; }}
@media (max-width: 640px) {{ .metrics {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<main class="card">
<div class="eyebrow">OpenLine Half-Life · Same Exam · Receiver Verified</div>
<div class="status">{escape(description['status'])}</div>
<h1>{escape(description['headline'])}</h1>
<p class="sub">{escape(description['subhead'])}</p>
<section class="metrics">
<div class="metric"><div class="label">Full-history errors</div><div class="value">{full['error_count']}</div></div>
<div class="metric"><div class="label">Verified-residue errors</div><div class="value">{residue['error_count']}</div></div>
<div class="metric"><div class="label">Unsupported claims</div><div class="value">{full['unsupported_claim_count']} → {residue['unsupported_claim_count']}</div></div>
</section>
{compaction_line}
<div class="footer">Synthetic deterministic demo. Not a universal model-support claim. Automatic retirement remains forbidden.</div>
</main>
</body>
</html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return html
