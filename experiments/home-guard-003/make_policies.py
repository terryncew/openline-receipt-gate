"""Generate signed fixture policies from explicitly TEST-ONLY identity keys."""
from pathlib import Path
import json
import sys

EXP = Path(__file__).resolve().parents[1] / "home-guard-001"
ROOT = EXP.parents[1]
for folder in (str(EXP), str(ROOT)):
    if folder not in sys.path:
        sys.path.insert(0, folder)
from home_guard import keys
from olp_gate.crypto import sign_olp_body

SCHEMA = "openline.home_guard.firewall_policy.v1"
PID = "hg3-isolated-veth-network"

def policy(seq: int, allow_tv: bool, who: str = "owner",
           valid_until: str = "2031-01-01T00:00:00Z") -> dict:
    return sign_olp_body({
        "schema": SCHEMA,
        "policy_id": PID,
        "version": seq,
        "valid_until": valid_until,
        "rules": {
            "tv_to_nvr_tcp_8080": allow_tv,
            "thermostat_to_hvac_tcp_9000": True,
        },
    }, keys.private_key(who))

def main():
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    candidates = {
        "v1-owner-allow.json": policy(1, True),
        "v2-owner-revoke.json": policy(2, False),
        "v999-attacker-forged-allow.json": policy(999, True, "attacker"),
        "v1-owner-rollback.json": policy(1, True),
        "v3-owner-expired.json": policy(3, True, valid_until="2000-01-01T00:00:00Z"),
    }
    forged = policy(3, True)
    forged["rules"]["tv_to_nvr_tcp_8080"] = False
    candidates["v3-tampered-unsigned.json"] = forged
    for name, body in candidates.items():
        (output / name).write_text(json.dumps(body, sort_keys=True, indent=2) + "\n")
    print("WROTE_OWNER_SIGNED_TEST_POLICIES owner_root=" + keys.public_key_hex_of("owner"))

if __name__ == "__main__":
    main()
