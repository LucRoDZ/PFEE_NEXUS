"""HDG consent service: stores consent grants and revocations signed by patients.

HDG cannot forge a grant: every grant is signed on the patient's own device with
an Ed25519 key that never leaves it. The hospital key broker re-checks each
signature with its own copy of the patient's public key before releasing a key.
"""
import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from ..common import crypto
from ..common.audit_client import AuditUnavailable, log_event
from ..common.auth import require_actor, require_one_of, token_from_header
from ..common.canon import parse_iso
from ..common.config import AUDIT_URL, PURPOSES, SELF_TOKEN, bearer, service_dir
from ..common.db import ThreadLocalDB
from ..common.http import client

SERVICE = "hdg-consent"
DB_PATH = service_dir("hdg") / "consent.sqlite"

app = FastAPI(title="NEXUS consent service (HDG)")

SCHEMA = """
CREATE TABLE IF NOT EXISTS patients (
    patient_ref TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    token_sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY,
    patient_ref TEXT NOT NULL,
    grantee TEXT NOT NULL,
    purpose TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    signed_grant TEXT NOT NULL,
    revoked_at TEXT,
    signed_revocation TEXT
);
"""


DB = ThreadLocalDB(DB_PATH, SCHEMA)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def require_patient(authorization: Optional[str] = Header(default=None)) -> sqlite3.Row:
    token = token_from_header(authorization)
    row = DB.execute("SELECT * FROM patients WHERE token_sha256 = ?", (_sha(token),)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="unknown patient token")
    return row


def status_of(row: sqlite3.Row) -> str:
    if row["revoked_at"]:
        return "revoked"
    if parse_iso(row["expires_at"]) < datetime.now(timezone.utc):
        return "expired"
    return "active"


def audit(actor: str, action: str, decision: str, patient_ref: str, detail: str = None):
    try:
        log_event(SERVICE, actor, action, decision, patient_ref=patient_ref, detail=detail)
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail="audit unavailable: change refused (no log, no change)")


class Enrollment(BaseModel):
    patient_ref: str
    pubkey: str


class Signed(BaseModel):
    payload: dict
    sig: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/patients")
def enroll(body: Enrollment, _: str = Depends(require_one_of("hospital-admin"))):
    token = "pt-" + secrets.token_urlsafe(24)
    DB.execute(
        "INSERT OR REPLACE INTO patients (patient_ref, pubkey, token_sha256) VALUES (?,?,?)",
        (body.patient_ref, body.pubkey, _sha(token)),
    )
    DB.commit()
    return {"patient_ref": body.patient_ref, "patient_token": token}


@app.post("/grants")
def create_grant(signed: Signed, patient: sqlite3.Row = Depends(require_patient)):
    p = signed.payload
    if p.get("type") != "grant" or p.get("patient_ref") != patient["patient_ref"]:
        raise HTTPException(status_code=400, detail="not a grant for this patient")
    if p.get("purpose") not in PURPOSES:
        raise HTTPException(status_code=400, detail=f"unknown purpose, expected one of {sorted(PURPOSES)}")
    if not crypto.verify(patient["pubkey"], signed.model_dump()):
        raise HTTPException(status_code=400, detail="invalid patient signature")
    audit(f"patient:{patient['patient_ref']}", "consent.grant", "recorded", patient["patient_ref"],
          detail=f"grantee={p['grantee']} purpose={p['purpose']} grant={p['grant_id']}")
    DB.execute(
        "INSERT INTO grants (grant_id, patient_ref, grantee, purpose, issued_at, expires_at, signed_grant)"
        " VALUES (?,?,?,?,?,?,?)",
        (p["grant_id"], p["patient_ref"], p["grantee"], p["purpose"], p["issued_at"], p["expires_at"],
         json.dumps(signed.model_dump())),
    )
    DB.commit()
    return {"grant_id": p["grant_id"], "status": "active"}


@app.post("/revocations")
def revoke(signed: Signed, patient: sqlite3.Row = Depends(require_patient)):
    p = signed.payload
    if p.get("type") != "revocation" or p.get("patient_ref") != patient["patient_ref"]:
        raise HTTPException(status_code=400, detail="not a revocation for this patient")
    if not crypto.verify(patient["pubkey"], signed.model_dump()):
        raise HTTPException(status_code=400, detail="invalid patient signature")
    row = DB.execute("SELECT * FROM grants WHERE grant_id = ? AND patient_ref = ?",
                     (p["grant_id"], patient["patient_ref"])).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="no such grant")
    audit(f"patient:{patient['patient_ref']}", "consent.revoke", "recorded", patient["patient_ref"],
          detail=f"grant={p['grant_id']}")
    DB.execute("UPDATE grants SET revoked_at = ?, signed_revocation = ? WHERE grant_id = ?",
               (p["revoked_at"], json.dumps(signed.model_dump()), p["grant_id"]))
    DB.commit()
    return {"grant_id": p["grant_id"], "status": "revoked"}


def _grant_view(row: sqlite3.Row) -> dict:
    return {
        "grant_id": row["grant_id"],
        "patient_ref": row["patient_ref"],
        "grantee": row["grantee"],
        "purpose": row["purpose"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
        "status": status_of(row),
        "revoked_at": row["revoked_at"],
    }


@app.get("/grants")
def grants_for_grantee(grantee: str, actor: str = Depends(require_actor)):
    if actor != grantee:
        raise HTTPException(status_code=403, detail="you can only list grants made to you")
    rows = DB.execute("SELECT * FROM grants WHERE grantee = ?", (grantee,)).fetchall()
    return [_grant_view(r) for r in rows]


@app.get("/grants/{grant_id}")
def get_grant(grant_id: str, actor: str = Depends(require_actor)):
    row = DB.execute("SELECT * FROM grants WHERE grant_id = ?", (grant_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="no such grant")
    if actor not in ("hospital-keybroker", row["grantee"]):
        raise HTTPException(status_code=403, detail="not your grant")
    return {**_grant_view(row), "signed_grant": json.loads(row["signed_grant"])}


@app.get("/grants/{grant_id}/status")
def grant_status(grant_id: str, _: str = Depends(require_one_of("hospital-keybroker"))):
    row = DB.execute("SELECT * FROM grants WHERE grant_id = ?", (grant_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="no such grant")
    return {"grant_id": grant_id, "status": status_of(row)}


@app.get("/me/grants")
def my_grants(patient: sqlite3.Row = Depends(require_patient)):
    rows = DB.execute("SELECT * FROM grants WHERE patient_ref = ? ORDER BY issued_at DESC",
                      (patient["patient_ref"],)).fetchall()
    return [_grant_view(r) for r in rows]


@app.get("/me/access-log")
def my_access_log(patient: sqlite3.Row = Depends(require_patient)):
    """EHDS article 9: the patient sees who accessed their data, when, and the decision."""
    response = client().get(f"{AUDIT_URL}/events", params={"patient_ref": patient["patient_ref"]},
                         headers=bearer(SELF_TOKEN[SERVICE]), timeout=5)
    response.raise_for_status()
    return response.json()
