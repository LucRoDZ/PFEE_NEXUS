"""Researcher client: fetch ciphertext from HDG, ask the hospital broker for the key.

    python -m nexus.researcher.client fetch OBJECT_ID GRANT_ID --out image.dcm
    python -m nexus.researcher.client watch OBJECT_ID GRANT_ID --interval 0.1
"""
import argparse
import json
import sys
import time

import httpx

from ..common import crypto
from ..common.canon import b64d, now_iso
from ..common.config import BROKER_URL, DATA_URL, bearer

DEFAULT_TOKEN = "tok-researcher"


class Denied(Exception):
    def __init__(self, reason: str, decision_ms: float | None = None):
        super().__init__(reason)
        self.reason = reason
        self.decision_ms = decision_ms


def fetch_ciphertext(object_id: str, token: str = DEFAULT_TOKEN):
    response = httpx.get(f"{DATA_URL}/objects/{object_id}", headers=bearer(token), timeout=30)
    response.raise_for_status()
    return response.content, response.headers["X-Patient-Ref"], response.headers["X-Wrapped-Dek"]


def request_key(patient_ref: str, object_id: str, wrapped_dek: str, grant_id: str, token: str = DEFAULT_TOKEN):
    response = httpx.post(f"{BROKER_URL}/unwrap", headers=bearer(token), timeout=10,
                          json={"patient_ref": patient_ref, "object_id": object_id,
                                "wrapped_dek": wrapped_dek, "grant_id": grant_id})
    body = response.json()
    if response.status_code != 200:
        detail = body.get("detail", {})
        if isinstance(detail, dict):
            raise Denied(detail.get("reason", "denied"), detail.get("decision_ms"))
        raise Denied(str(detail))
    return b64d(body["dek"]), body["decision_ms"]


def fetch(object_id: str, grant_id: str, token: str = DEFAULT_TOKEN, ciphertext_override: bytes | None = None):
    ciphertext, patient_ref, wrapped = fetch_ciphertext(object_id, token)
    if ciphertext_override is not None:
        ciphertext = ciphertext_override
    dek, decision_ms = request_key(patient_ref, object_id, wrapped, grant_id, token)
    return crypto.unseal(dek, ciphertext, object_id.encode()), decision_ms


def main(argv=None):
    parser = argparse.ArgumentParser(description="NEXUS researcher client")
    sub = parser.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("object_id")
    f.add_argument("grant_id")
    f.add_argument("--out", required=True)
    f.add_argument("--token", default=DEFAULT_TOKEN)
    w = sub.add_parser("watch")
    w.add_argument("object_id")
    w.add_argument("grant_id")
    w.add_argument("--interval", type=float, default=0.1)
    w.add_argument("--token", default=DEFAULT_TOKEN)
    args = parser.parse_args(argv)

    if args.cmd == "fetch":
        try:
            plaintext, ms = fetch(args.object_id, args.grant_id, args.token)
        except Denied as exc:
            print(json.dumps({"decision": "denied", "reason": exc.reason}))
            return 1
        with open(args.out, "wb") as fh:
            fh.write(plaintext)
        print(json.dumps({"decision": "allowed", "bytes": len(plaintext), "decision_ms": ms, "out": args.out}))
        return 0

    ciphertext, patient_ref, wrapped = fetch_ciphertext(args.object_id, args.token)
    while True:
        try:
            request_key(patient_ref, args.object_id, wrapped, args.grant_id, args.token)
            print(f"{now_iso()}  ALLOWED")
        except Denied as exc:
            print(f"{now_iso()}  DENIED   {exc.reason}")
        sys.stdout.flush()
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
