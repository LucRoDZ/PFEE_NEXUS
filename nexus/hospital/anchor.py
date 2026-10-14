"""Hospital-side anchors for the HDG audit chain.

Every few seconds (every 10 minutes in production), the hospital copies the
current head of HDG's audit chain into a file HDG cannot touch. Later, any
rewrite of the chain, even a fully recomputed one, shows up as a mismatch
between an anchored hash and the hash HDG now reports for that position.

    python -m nexus.hospital.anchor run --interval 2
    python -m nexus.hospital.anchor check
"""
import argparse
import json
import sys
import time

import httpx

from ..common.canon import now_iso
from ..common.config import AUDIT_URL, SELF_TOKEN, bearer, service_dir

SERVICE = "hospital-anchor"
ANCHORS = service_dir("hospital") / "anchors.jsonl"


def headers():
    return bearer(SELF_TOKEN[SERVICE])


def take_anchor() -> dict | None:
    head = httpx.get(f"{AUDIT_URL}/head", headers=headers(), timeout=5).json()
    if head["seq"] == 0:
        return None
    last = None
    if ANCHORS.exists():
        lines = ANCHORS.read_text().strip().splitlines()
        last = json.loads(lines[-1]) if lines else None
    if last and last["seq"] == head["seq"]:
        return None
    record = {"seq": head["seq"], "hash": head["hash"], "anchored_at": now_iso()}
    with ANCHORS.open("a") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def check() -> dict:
    """Return the first discrepancy between HDG's chain and the hospital's anchors."""
    integrity = httpx.get(f"{AUDIT_URL}/verify", headers=headers(), timeout=30).json()
    anchors = [json.loads(line) for line in ANCHORS.read_text().splitlines()] if ANCHORS.exists() else []
    for anchor in anchors:
        response = httpx.get(f"{AUDIT_URL}/hash-at/{anchor['seq']}", headers=headers(), timeout=5)
        current = response.json().get("hash") if response.status_code == 200 else None
        if current != anchor["hash"]:
            return {"chain_self_consistent": integrity["ok"], "anchors_ok": False,
                    "first_mismatch_seq": anchor["seq"], "anchored_hash": anchor["hash"],
                    "hash_now_reported": current, "anchors_checked": len(anchors),
                    "chain_check": integrity}
    return {"chain_self_consistent": integrity["ok"], "anchors_ok": True,
            "anchors_checked": len(anchors), "chain_check": integrity}


def main(argv=None):
    parser = argparse.ArgumentParser(description="NEXUS audit anchors (hospital side)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--interval", type=float, default=600.0)
    sub.add_parser("once")
    sub.add_parser("check")
    args = parser.parse_args(argv)

    if args.cmd == "run":
        while True:
            try:
                take_anchor()
            except httpx.HTTPError:
                pass
            time.sleep(args.interval)
    elif args.cmd == "once":
        print(json.dumps(take_anchor()))
    else:
        result = check()
        print(json.dumps(result, indent=2))
        return 0 if result["anchors_ok"] and result["chain_self_consistent"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
