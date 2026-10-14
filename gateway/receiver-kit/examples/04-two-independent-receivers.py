#!/usr/bin/env python3
"""Two isolated local receiver processes using existing Wallet wire contracts.

NOT two actual organizations. Receiver keys generated within separate
processes. Owner signs one bundle admitted separately by both. A process
writes a local simulated-effect trace only after it returns ALLOWED.
This trace is not a remotely witnessed external effect.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import json
import multiprocessing as mp
import os
from pathlib import Path
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openline_wallet import Wallet
from openline_wallet.crypto import public_key_hex, verify_record
from wallet_bridge import WalletReceiver, worker_present

ACTION = "read_reports"
EXTRA = "audit_reports"
UNCONFIGURED = "export_reports"


def receiver_process(pipe, name, principal_id, root_pub, required, effect_file):
    """All receiver trust and signing state stays in this separate process."""
    rx = WalletReceiver(name, max_bundle_age_seconds=30, challenge_ttl_seconds=20)
    rx.pin_owner(principal_id, root_pub)  # synthetic out-of-band onboarding
    rx.protect_action(ACTION, required)
    pipe.send({"public_key": rx.public_key, "gate_id": name})
    while True:
        try:
            command = pipe.recv()
        except EOFError:
            return
        if command["op"] == "close":
            pipe.send({"closed": True})
            return
        try:
            if command["op"] == "admit":
                out = {"admission": rx.admit_bundle(command["bundle"])}
            elif command["op"] == "challenge":
                out = {"challenge": rx.issue_challenge(
                    command["principal"], command["subject"], command["action"])}
            elif command["op"] == "decide":
                receipt = rx.authorize(command["presentation"], command["action"])
                # Local simulated effect. The receipt proves ONLY authorization.
                if receipt["decision"] == "ALLOWED":
                    with open(effect_file, "a", encoding="utf-8") as handle:
                        handle.write(json.dumps({"action": command["action"],
                            "receiver": name, "subject": command["presentation"]["subject_id"],
                            "simulation": True}, sort_keys=True) + "\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                out = {"receipt": receipt}
            else:
                out = {"error": "UNSUPPORTED_RPC"}
        except Exception as exc:
            out = {"error": getattr(exc, "code", type(exc).__name__)}
        pipe.send(out)


def rpc(pipe, **command):
    pipe.send(command)
    response = pipe.recv()
    if "error" in response and command["op"] != "admit":
        raise RuntimeError(f"unexpected receiver error {response['error']} for {command['op']}")
    return response


def main(out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    checks = []
    receipts = []
    started = time.perf_counter()

    def check(label, condition):
        checks.append({"name": label, "pass": bool(condition)})
        if not condition:
            raise AssertionError(label)

    with tempfile.TemporaryDirectory(prefix="receiver-001-owner-") as owner_dir:
        owner = Wallet.create(owner_dir)
        old_key = Ed25519PrivateKey.generate()
        new_key = Ed25519PrivateKey.generate()
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        old_m = owner.grant(subject_id="worker-original",
            subject_public_key=public_key_hex(old_key),
            scopes=[ACTION, UNCONFIGURED], expires_at=expiry)
        new_m = owner.grant(subject_id="worker-successor",
            subject_public_key=public_key_hex(new_key),
            scopes=[ACTION, EXTRA], expires_at=expiry)
        b1 = owner.export_bundle(ttl_seconds=30)
        parents = {}
        children = []
        try:
            # Separate processes; different local rules and signing keys.
            for name, required in (("receiver-alpha", [ACTION]),
                                   ("receiver-beta", [ACTION, EXTRA])):
                parent, child = mp.Pipe()
                proc = mp.Process(target=receiver_process,
                    args=(child, name, owner.principal_id, owner.root_public_key,
                          required, str(out_dir / (name + "-effects.jsonl"))))
                proc.start()
                child.close()
                hello = parent.recv()
                parents[name] = {"pipe": parent, "proc": proc,
                                 "key": hello["public_key"]}
                children.append(proc)

            alpha = parents["receiver-alpha"]
            beta = parents["receiver-beta"]
            check("different receiver signing roots", alpha["key"] != beta["key"])
            for cfg in (alpha, beta):
                adm = rpc(cfg["pipe"], op="admit", bundle=b1)
                check("separate receiver admits owner's bundle",
                      adm["admission"]["decision"] == "BUNDLE_ADMITTED")

            def decide(cfg, subject, key, mandate, bundle, action=ACTION):
                ch = rpc(cfg["pipe"], op="challenge", principal=owner.principal_id,
                         subject=subject, action=action)["challenge"]
                presentation = worker_present(bundle=bundle,
                    mandate_id=mandate["data"]["mandate_id"], subject_id=subject,
                    subject_key=key, action=action, challenge=ch)
                response = rpc(cfg["pipe"], op="decide",
                               presentation=presentation, action=action)
                receipt = response["receipt"]
                valid, reason = verify_record(receipt, expected_public_key=cfg["key"])
                check("decision receipt verifies against pinned receiver key", valid)
                receipts.append({"receiver": "alpha" if cfg is alpha else "beta",
                                 "receipt": receipt})
                return receipt, presentation

            a1, original_presentation = decide(alpha, "worker-original", old_key, old_m, b1)
            b1deny, _ = decide(beta, "worker-original", old_key, old_m, b1)
            check("alpha accepts narrower owner grant", a1["decision"] == "ALLOWED")
            check("beta requires extra owner-granted scope",
                  b1deny["decision"] == "STOPPED"
                  and "RECEIVER_SCOPE_POLICY_UNMET" in b1deny["reason_codes"])

            a2, _ = decide(alpha, "worker-successor", new_key, new_m, b1)
            b2, _ = decide(beta, "worker-successor", new_key, new_m, b1)
            check("replacement worker accepted by both without first provider",
                  a2["decision"] == b2["decision"] == "ALLOWED")

            unknown, _ = decide(alpha, "worker-original", old_key, old_m,
                                b1, action=UNCONFIGURED)
            check("unconfigured action refuses even if owner granted scope",
                  unknown["decision"] == "STOPPED"
                  and "RECEIVER_ACTION_UNCONFIGURED" in unknown["reason_codes"])
            replay = rpc(alpha["pipe"], op="decide",
                         presentation=original_presentation, action=ACTION)["receipt"]
            check("one-use presentation replay rejected",
                  replay["decision"] == "STOPPED"
                  and "PRESENTATION_REPLAYED" in replay["reason_codes"])
            check("replay denial signed",
                  verify_record(replay, expected_public_key=alpha["key"])[0])
            receipts.append({"receiver": "alpha", "receipt": replay})
            check("cross-receiver signer spoofing rejected",
                  not verify_record(a1, expected_public_key=beta["key"])[0])

            # An owner signature may be valid but too old: admit new head.
            owner.revoke(new_m["data"]["mandate_id"], reason="OWNER_REVOKED")
            b2_new = owner.export_bundle(ttl_seconds=30)
            for cfg in (alpha, beta):
                rpc(cfg["pipe"], op="admit", bundle=b2_new)
                old, _ = decide(cfg, "worker-successor", new_key, new_m, b1)
                current, _ = decide(cfg, "worker-successor", new_key, new_m, b2_new)
                check("old signed head rejected after new admission",
                      old["decision"] == "STOPPED"
                      and "PRESENTATION_HEAD_STALE" in old["reason_codes"])
                check("new bundle carries revocation",
                      current["decision"] == "STOPPED"
                      and "MANDATE_REVOKED" in current["reason_codes"])

            with tempfile.TemporaryDirectory(prefix="receiver-001-foreign-") as foreign_dir:
                foreign = Wallet.create(foreign_dir)
                # Each receiver must choose its own trust anchors; this one is unpinned.
                forged = foreign.export_bundle(ttl_seconds=30)
                for cfg in (alpha, beta):
                    response = cfg["pipe"]
                    response.send({"op": "admit", "bundle": forged})
                    rejected = response.recv()
                    check("unknown owner root cannot be admitted",
                          rejected.get("error") == "ROOT_NOT_PINNED")

            for cfg in (alpha, beta):
                rpc(cfg["pipe"], op="close")
                cfg["proc"].join(timeout=5)
                check("receiver exited cleanly", cfg["proc"].exitcode == 0)

            count_a = len((out_dir / "receiver-alpha-effects.jsonl").read_text().splitlines())
            count_b = len((out_dir / "receiver-beta-effects.jsonl").read_text().splitlines())
            check("only authorized simulated effects recorded", count_a == 2 and count_b == 1)
            summary = {"synthetic": True, "elapsed_harness_seconds": round(time.perf_counter()-started,3),
                       "checked": len(checks), "passed": sum(x["pass"] for x in checks),
                       "checks": checks, "simulated_effect_counts": {"alpha": count_a,"beta": count_b},
                       "not_proven": ["external organizational independence",
                                     "real external effect or third-party observation",
                                     "automatic revocation delivery", "production durability",
                                     "clean-room setup time", "commercial demand"]}
            (out_dir / "trusted_receiver_keys.json").write_text(json.dumps({
                "alpha": alpha["key"], "beta": beta["key"],
                "note": "Synthetic pins generated by two receiver processes; an outside verifier must obtain real pins out-of-band"},indent=2)+"\n")
            (out_dir / "decision_receipts.json").write_text(json.dumps(receipts,indent=2)+"\n")
            (out_dir / "summary.json").write_text(json.dumps(summary,indent=2)+"\n")
            print(f"{summary['passed']}/{summary['checked']} synthetic checks PASS; evidence: {out_dir}")
            return summary
        finally:
            for cfg in parents.values():
                if cfg["proc"].is_alive():
                    cfg["proc"].terminate()
                    cfg["proc"].join(timeout=3)
                cfg["pipe"].close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    main(args.out)
