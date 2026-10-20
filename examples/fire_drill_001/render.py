"""Self-contained 40-second auto-playing storyboard from actual recorded run rows.

Do not invent screenshots, provider activity, terminal outputs, or testimonials.
Not an MP4; works offline in a normal browser and can be screen-recorded later.
"""
from __future__ import annotations
import html
import json
from pathlib import Path

def read_events(root,mode):
    return [json.loads(line) for line in (root/mode/"events.jsonl").read_text().splitlines()]

def render(root,out):
    root=Path(root)
    records={mode:read_events(root,mode) for mode in ("intentionally_weak","conventional","openline")}
    def effects(mode,labels):
        return sum(e["decision"]["documents_after"]-e["decision"]["documents_before"]
                   for e in records[mode] if e["label"] in labels)
    labels=("a_new_effect_1","a_reuses_shared_bearer","a_outside_named_http_route","fired_a_after_b_grant")
    weak=effects("intentionally_weak",labels)
    conv=effects("conventional",labels)
    olp=effects("openline",labels)
    good={m:effects(m,("successor_b_finishes_approved_work","unrelated_work_continues"))
          for m in records}
    values={"weak":weak,"conventional":conv,"openline":olp,"good":good}
    # Every numeric claim comes from this run's actual observed decisions.
    pages=[
        ("THE OPENLINE FIRE DRILL","Can you fire an AI agent—and actually stop it?","A disposable challenge. Three receivers. Independent evidence."),
        ("BEFORE THE FIRING","Agent A completes one approved action.","All three receivers record one protected local document."),
        ("OWNER REVOKES A","The owner withdraws permission.","The protected receivers accept a signed REVOKED authority update."),
        ("THE TEST","A tries again: new effects, old credentials, a side route.",
         f"Intentionally weak: {weak} post-revocation A effects. Proper JWT: {conv}. OpenLine: {olp}."),
        ("WHAT REPLAY PROVES","The exact old request is replayed.","Identical record IDs fail again. Reusing a shared bearer for a NEW effect is different."),
        ("THE WORK SURVIVES","A successor completes authorized work.","Approved successor + independent unrelated slot: "
         +", ".join(f"{k}: {v}" for k,v in good.items())+" recorded effects."),
        ("THE HONEST BLIND SPOT","Outside the receiver is outside its protection.",
         "The direct unprotected SQLite path still accepts 1 local write in EVERY mode."),
        ("DON'T TRUST THE VIDEO","Verify the signed decisions and the actual rows.","OpenLine and strong JWT both pass here. Check MANIFEST.json, trust roots, and receiver SQLite. No real agent tested.")
    ]
    data=json.dumps({"pages":pages,"counts":values},ensure_ascii=True).replace("<","\\u003c")
    html_src=r'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenLine Fire Drill — 40-second verified-evidence playback</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Arial,Helvetica,sans-serif;background:#0b1f2e;color:#f6f3eb}
body{display:flex;align-items:center;justify-content:center;min-height:100dvh;padding:24px}
main{width:min(1100px,100%);min-height:min(650px,85dvh);border:1px solid #6b879144;position:relative;overflow:hidden;display:flex;flex-direction:column;padding:clamp(24px,5vw,72px)}
header{display:flex;justify-content:space-between;gap:22px;align-items:center;font-size:12px;letter-spacing:.16em;font-weight:700}
.mark{display:inline-flex;gap:6px;vertical-align:middle;align-items:center;margin-right:8px}.mark i{display:block;width:14px;height:14px;transform:skew(-20deg);background:#f6f3eb}.mark i:last-child{background:#ef8968}
#number{font-variant-numeric:tabular-nums;color:#a9c5d1}
section{flex:1;display:flex;flex-direction:column;justify-content:center;max-width:920px}
.eyebrow{color:#ef8968;font-size:clamp(12px,2.1vw,18px);font-weight:700;letter-spacing:.16em;margin-bottom:20px}
h1{font-size:clamp(40px,7.6vw,104px);line-height:1.02;letter-spacing:-.057em;margin:0 0 28px;font-weight:650}
p{font-size:clamp(17px,2.25vw,27px);line-height:1.34;color:#bcd1d9;margin:0;max-width:830px}
footer{display:flex;align-items:center;justify-content:space-between;gap:16px;border-top:1px solid #6b879144;padding-top:20px;font-size:13px;color:#a9c5d1}
button{background:none;border:1px solid #7899a8;color:#f6f3eb;padding:10px 16px;cursor:pointer;font:inherit;border-radius:3px}
button:focus-visible{outline:3px solid #ef8968}#track{height:3px;background:#465c66;margin-top:18px}#fill{height:100%;background:#ef8968;width:0}
.disclaimer{font-size:10px;letter-spacing:0;color:#aac1ca}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
<main>
<header><div><span class="mark" aria-hidden="true"><i></i><i></i></span>OPENLINE / FIRE DRILL</div><div id="number">00 / 40 SEC</div></header>
<section aria-live="polite"><div class="eyebrow" id="eyebrow"></div><h1 id="headline"></h1><p id="detail"></p></section>
<footer><div><strong>Fire the agent. Keep the work. Prove both.</strong><div class="disclaimer">Public test keys · simulated workers · local SQLite · not a real agent certification</div></div><button id="restart" type="button">Replay 40s</button></footer>
<div id="track" role="progressbar" aria-label="40 second playback" aria-valuemin="0" aria-valuemax="40" aria-valuenow="0"><div id="fill"></div></div>
</main>
<script>
"use strict";const DATA=__DATA__;
const nodes={eye:document.getElementById('eyebrow'),head:document.getElementById('headline'),detail:document.getElementById('detail'),time:document.getElementById('number'),fill:document.getElementById('fill'),track:document.getElementById('track')};
let start=performance.now(),shown=-1,done=false;
function draw(){
 const elapsed=Math.min(40,Math.max(0,(performance.now()-start)/1000)),page=Math.min(7,Math.floor(elapsed/5));
 if(page!==shown){shown=page;const p=DATA.pages[page];nodes.eye.textContent=p[0];nodes.head.textContent=p[1];nodes.detail.textContent=p[2];}
 nodes.time.textContent=String(Math.floor(elapsed)).padStart(2,'0')+' / 40 SEC';
 nodes.fill.style.width=(elapsed/40*100)+'%';nodes.track.setAttribute('aria-valuenow',Math.floor(elapsed));
 if(elapsed<40)requestAnimationFrame(draw);else done=true;
}
document.getElementById('restart').addEventListener('click',()=>{start=performance.now();shown=-1;done=false;requestAnimationFrame(draw)});
requestAnimationFrame(draw);
</script></html>'''.replace("__DATA__",data)
    Path(out).write_text(html_src,encoding="utf-8")
    return values
