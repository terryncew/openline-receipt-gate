"""HOME-GUARD-003: deliberately narrow signed-owner-policy -> kernel firewall gate.

Run ONLY inside disposable hg3-fw network namespace. Inputs are static
fixture-signed policies; no user-controlled shell code, real credentials, or
household network. This is an experiment, not a network configuration service.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

EXP = Path(__file__).resolve().parents[1] / "home-guard-001"
ROOT = EXP.parents[1]
for folder in (str(EXP), str(ROOT)):
    if folder not in sys.path:
        sys.path.insert(0, folder)

from home_guard import keys  # test-only fixed signing keys; NEVER production
from olp_gate.crypto import (
    olp_canonical_json, sign_olp_body, strict_json_load, verify_olp_signature,
)

SCHEMA = "openline.home_guard.firewall_policy.v1"
RECEIPT_SCHEMA = "openline.home_guard.kernel_apply_receipt.v1"
POLICY_ID = "hg3-isolated-veth-network"
# This independent trust anchor is NOT read from the submitted policy.
OWNER_PUB = "bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5"
RECEIVER_PUB = keys.public_key_hex_of("receiver")


def epoch_us() -> int:
    return time.time_ns() // 1000


def firewall_snapshot() -> tuple[str, str]:
    rules = subprocess.run(["iptables", "-S", "FORWARD"], capture_output=True,
                           text=True, check=True).stdout
    return rules, hashlib.sha256(rules.encode()).hexdigest()


def validate_signed(raw: bytes) -> dict:
    policy = strict_json_load(raw.decode("utf-8"))
    if not isinstance(policy, dict) or set(policy) != {
        "schema", "policy_id", "version", "valid_until", "rules",
        "payload_hash", "signature",
    }:
        raise ValueError("unknown_policy_fields")
    valid, reason = verify_olp_signature(policy)
    if not valid:
        raise ValueError("invalid_owner_signature:" + str(reason))
    if policy["signature"]["public_key"] != OWNER_PUB:
        raise ValueError("untrusted_owner_key")
    if policy["schema"] != SCHEMA or policy["policy_id"] != POLICY_ID:
        raise ValueError("wrong_policy_identity")
    if type(policy["version"]) is not int or not (1 <= policy["version"] <= 1000000):
        raise ValueError("invalid_version")
    if type(policy["valid_until"]) is not str:
        raise ValueError("invalid_policy_time")
    expires = datetime.fromisoformat(policy["valid_until"].replace("Z", "+00:00"))
    if expires.tzinfo is None or expires.utcoffset() is None:
        raise ValueError("timezone_required")
    if datetime.now(timezone.utc) >= expires.astimezone(timezone.utc):
        raise ValueError("expired_signed_policy")
    rules = policy["rules"]
    if not isinstance(rules, dict) or set(rules) != {
        "tv_to_nvr_tcp_8080", "thermostat_to_hvac_tcp_9000",
    }:
        raise ValueError("unrecognized_firewall_scope")
    if type(rules["tv_to_nvr_tcp_8080"]) is not bool:
        raise ValueError("invalid_tv_permission")
    if rules["thermostat_to_hvac_tcp_9000"] is not True:
        raise ValueError("control_connection_must_remain_authorized")
    return policy


def render_firewall(allow_tv: bool) -> str:
    tv_target = "ACCEPT" if allow_tv else "DROP"
    # These are independent ingress-interface rules, not trusting packet's
    # spoofable source alone. Both directions of revoked TCP traffic drop
    # BEFORE any established-connection exceptions.
    return "\n".join([
        "*filter", ":INPUT ACCEPT [0:0]", ":FORWARD DROP [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        "-A FORWARD -i fwtv -o fwnvr -s 10.73.1.2/32 -d 10.73.2.2/32 "
        "-p tcp --dport 8080 -j " + tv_target,
        "-A FORWARD -i fwnvr -o fwtv -s 10.73.2.2/32 -d 10.73.1.2/32 "
        "-p tcp --sport 8080 -m conntrack --ctstate ESTABLISHED -j " + tv_target,
        "-A FORWARD -i fwtv -j DROP",
        "-A FORWARD -i fwnvr -j DROP",
        "-A FORWARD -i fwthermo -o fwhvac -s 10.73.3.2/32 -d 10.73.4.2/32 "
        "-p tcp --dport 9000 -j ACCEPT",
        "-A FORWARD -i fwhvac -o fwthermo -s 10.73.4.2/32 -d 10.73.3.2/32 "
        "-p tcp --sport 9000 -m conntrack --ctstate ESTABLISHED -j ACCEPT",
        "-A FORWARD -j DROP", "COMMIT", "",
    ])


def apply_kernel(allow_tv: bool) -> str:
    config = render_firewall(allow_tv)
    subprocess.run(["iptables-restore", "-w"], input=config.encode(), check=True)
    # Verify installed rules from the KERNEL, not from our planned config.
    observed, digest = firewall_snapshot()
    if allow_tv:
        expected = "-A FORWARD -i fwtv -o fwnvr"
        if expected not in observed or "--dport 8080 -j ACCEPT" not in observed:
            raise RuntimeError("allowed_rule_not_installed")
    else:
        if "-A FORWARD -i fwtv -j DROP" not in observed:
            raise RuntimeError("tv_ingress_drop_not_installed")
        if "--dport 8080 -j ACCEPT" in observed:
            raise RuntimeError("revoked_tv_permission_still_installed")
        # conntrack eviction closes a previously admitted flow. The kernel's
        # explicit ingress/egress DROP rules independently block all packets.
        deleted = subprocess.run(
            ["conntrack", "-D", "-p", "tcp", "-s", "10.73.1.2",
             "-d", "10.73.2.2", "--dport", "8080"],
            capture_output=True, text=True)
        # "0 flow entries" may return nonzero. Do not infer containment from it.
        print("CONNTRACK_EVICT_EXIT=" + str(deleted.returncode), flush=True)
        print("CONNTRACK_EVICT=" + deleted.stdout.strip(), flush=True)
    return digest


def record(receipts: Path, *, request: bytes, version: int | None,
           decision: str, reason: str, before: str, after: str) -> dict:
    body = {
        "schema": RECEIPT_SCHEMA,
        "policy_id": POLICY_ID,
        "policy_file_sha256": hashlib.sha256(request).hexdigest(),
        "requested_version": version,
        "decision": decision,
        "reason": reason,
        "kernel_rules_before_sha256": before,
        "kernel_rules_after_sha256": after,
        "applied_at_epoch_us": epoch_us(),
    }
    receipt = sign_olp_body(body, keys.private_key("receiver"))
    receipts.parent.mkdir(parents=True, exist_ok=True)
    with receipts.open("a", encoding="utf-8") as output:
        output.write(json.dumps(receipt, sort_keys=True) + "\n")
        output.flush()
    print("HOME_GUARD_003_GATE=" + json.dumps({
        "version": version, "decision": decision, "reason": reason,
        "before": before, "after": after,
        "receipt_public_key": receipt["signature"]["public_key"],
    }, sort_keys=True), flush=True)
    return receipt


def run(policy_file: Path, ledger: Path, receipts: Path, snapshot: Path) -> int:
    # If the verifier cannot inspect installed rules, fail before any update.
    before_rules, before_hash = firewall_snapshot()
    raw = policy_file.read_bytes()
    policy = None
    conn = None
    try:
        policy = validate_signed(raw)
        ledger.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(ledger), timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("CREATE TABLE IF NOT EXISTS applied "
                     "(slot INTEGER PRIMARY KEY CHECK(slot=1), version INTEGER NOT NULL,"
                     " policy_hash TEXT NOT NULL, kernel_hash TEXT NOT NULL)")
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT version FROM applied WHERE slot=1").fetchone()
        if row is not None and policy["version"] <= row[0]:
            raise ValueError("stale_or_rolled_back_version")
        after_hash = apply_kernel(policy["rules"]["tv_to_nvr_tcp_8080"])
        conn.execute("INSERT OR REPLACE INTO applied(slot,version,policy_hash,kernel_hash)"
                     " VALUES (1,?,?,?)",
                     (policy["version"], policy["payload_hash"], after_hash))
        conn.execute("COMMIT")
        snapshot.write_text(firewall_snapshot()[0])
        record(receipts, request=raw, version=policy["version"], decision="APPLIED",
               reason="owner_signature_verified_and_kernel_rules_installed",
               before=before_hash, after=after_hash)
        return 0
    except (ValueError, TypeError, UnicodeError, KeyError) as exc:
        if conn is not None and conn.in_transaction:
            conn.execute("ROLLBACK")
        # No kernel invocation occurs on malformed/forged/stale policy.
        after_hash = firewall_snapshot()[1]
        if after_hash != before_hash:
            raise RuntimeError("rejected_policy_changed_kernel_rules") from exc
        version = policy.get("version") if isinstance(policy, dict) else None
        record(receipts, request=raw, version=version, decision="REJECTED",
               reason=str(exc), before=before_hash, after=after_hash)
        return 10
    finally:
        if conn is not None:
            conn.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--receipts", required=True, type=Path)
    parser.add_argument("--snapshot", required=True, type=Path)
    a = parser.parse_args()
    return run(a.policy, a.ledger, a.receipts, a.snapshot)


if __name__ == "__main__":
    raise SystemExit(main())
