"""Patient agent and portal. Runs on the patient's own device.

It holds the patient's Ed25519 signing key, which never leaves the device.
Every grant, revocation and erasure request is signed here. Revocations are
sent to both HDG's consent service and the hospital key broker, so HDG cannot
silently drop one.

    python -m nexus.patient.agent init --profile var/patient --ref P-xxxx
    python -m nexus.patient.agent serve --profile var/patient --port 8301
"""
import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ..common import crypto
from ..common.canon import now_iso
from ..common.config import BROKER_URL, CONSENT_URL, bearer

STATIC = Path(__file__).parent / "static"


class Profile:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.key_path = self.dir / "signing_key.pem"
        self.meta_path = self.dir / "profile.json"

    def init(self, patient_ref: str) -> dict:
        self.dir.mkdir(parents=True, exist_ok=True)
        key = crypto.new_signing_key()
        self.key_path.write_bytes(crypto.private_to_pem(key))
        self.key_path.chmod(0o600)
        meta = {"patient_ref": patient_ref, "pubkey": crypto.public_b64(key), "patient_token": None}
        self.meta_path.write_text(json.dumps(meta, indent=2))
        return meta

    @property
    def meta(self) -> dict:
        return json.loads(self.meta_path.read_text())

    def set_token(self, token: str):
        meta = self.meta
        meta["patient_token"] = token
        self.meta_path.write_text(json.dumps(meta, indent=2))

    def key(self):
        return crypto.private_from_pem(self.key_path.read_bytes())

    def headers(self):
        return bearer(self.meta["patient_token"])


# --- operations, usable from the portal or from scripts -------------------------

def grant(profile: Profile, grantee: str, purpose: str, days: int = 30) -> dict:
    now = datetime.now(timezone.utc)
    payload = {
        "type": "grant",
        "grant_id": str(uuid.uuid4()),
        "patient_ref": profile.meta["patient_ref"],
        "grantee": grantee,
        "purpose": purpose,
        "issued_at": now.isoformat(timespec="milliseconds"),
        "expires_at": (now + timedelta(days=days)).isoformat(timespec="milliseconds"),
    }
    signed = crypto.sign(profile.key(), payload)
    response = httpx.post(f"{CONSENT_URL}/grants", json=signed, headers=profile.headers(), timeout=10)
    response.raise_for_status()
    return response.json()


def revoke(profile: Profile, grant_id: str) -> dict:
    payload = {"type": "revocation", "grant_id": grant_id, "patient_ref": profile.meta["patient_ref"],
               "revoked_at": now_iso()}
    signed = crypto.sign(profile.key(), payload)
    t0 = time.perf_counter()
    to_hospital = httpx.post(f"{BROKER_URL}/revocations", json=signed, timeout=10)
    to_hdg = httpx.post(f"{CONSENT_URL}/revocations", json=signed, headers=profile.headers(), timeout=10)
    elapsed = (time.perf_counter() - t0) * 1000
    return {"grant_id": grant_id, "hospital": to_hospital.status_code, "hdg": to_hdg.status_code,
            "revoked_at": payload["revoked_at"], "round_trip_ms": round(elapsed, 2)}


def erase(profile: Profile) -> dict:
    payload = {"type": "erase", "patient_ref": profile.meta["patient_ref"], "requested_at": now_iso()}
    response = httpx.post(f"{BROKER_URL}/erase", json=crypto.sign(profile.key(), payload), timeout=10)
    response.raise_for_status()
    return response.json()


def my_grants(profile: Profile) -> list:
    return httpx.get(f"{CONSENT_URL}/me/grants", headers=profile.headers(), timeout=10).json()


def my_access_log(profile: Profile) -> list:
    return httpx.get(f"{CONSENT_URL}/me/access-log", headers=profile.headers(), timeout=10).json()


# --- local portal ----------------------------------------------------------------

def build_app(profile: Profile) -> FastAPI:
    app = FastAPI(title="NEXUS patient portal (runs on the patient's device)")

    class GrantRequest(BaseModel):
        grantee: str
        purpose: str
        days: int = 30

    @app.get("/")
    def index():
        return FileResponse(STATIC / "portal.html")

    @app.get("/api/me")
    def me():
        meta = profile.meta
        return {"patient_ref": meta["patient_ref"], "enrolled": bool(meta["patient_token"])}

    @app.get("/api/grants")
    def grants():
        return my_grants(profile)

    @app.post("/api/grants")
    def new_grant(body: GrantRequest):
        try:
            return grant(profile, body.grantee, body.purpose, body.days)
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)

    @app.post("/api/grants/{grant_id}/revoke")
    def revoke_grant(grant_id: str):
        return revoke(profile, grant_id)

    @app.get("/api/access-log")
    def access_log():
        return my_access_log(profile)

    @app.post("/api/erase")
    def erase_all():
        return erase(profile)

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description="NEXUS patient agent")
    sub = parser.add_subparsers(dest="cmd", required=True)
    init = sub.add_parser("init")
    init.add_argument("--profile", required=True)
    init.add_argument("--ref", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--profile", required=True)
    serve.add_argument("--port", type=int, default=8301)
    args = parser.parse_args(argv)

    profile = Profile(Path(args.profile))
    if args.cmd == "init":
        print(json.dumps(profile.init(args.ref), indent=2))
    else:
        import uvicorn
        uvicorn.run(build_app(profile), host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
