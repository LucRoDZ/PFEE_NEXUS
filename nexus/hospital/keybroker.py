"""Hospital key broker: holds one key-encryption key (KEK) per patient.

It runs on the hospital's side, never on HDG's. HDG stores ciphertext and
wrapped data keys, but only this broker can unwrap them, and it does so only when:

1. the patient's key has not been destroyed (crypto-shredding on erasure),
2. the requester presents a grant signed by the patient (checked with the
   broker's own copy of the patient's public key, so HDG cannot forge one),
3. the grant names this requester, is not expired and has not been revoked,
   either through HDG's consent service or through a revocation the patient
   sent directly to the hospital (so HDG cannot hide a revocation),
4. the decision has been written to the audit chain (no log, no key).

KEKs are sealed with a master key. In the PoC the master key is a local file;
in the target architecture it lives in an HSM at the hospital.
"""
import json
import sqlite3
import time
from datetime import datetime, timezone

import httpx
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from ..common import crypto
from ..common.audit_client import AuditUnavailable, log_event
from ..common.auth import require_actor, require_one_of
from ..common.canon import b64d, b64e, parse_iso
from ..common.config import CONSENT_URL, SELF_TOKEN, bearer, service_dir
from ..common.db import ThreadLocalDB
from ..common.http import client

SERVICE = "hospital-keybroker"
HOME = service_dir("hospital")
DB_PATH = HOME / "keybroker.sqlite"
MASTER_PATH = HOME / "master.key"

app = FastAPI(title="NEXUS key broker (hospital)")

SCHEMA = """
CREATE TABLE IF NOT EXISTS patients (
    patient_ref TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    kek_sealed BLOB,
    erased_at TEXT
);
CREATE TABLE IF NOT EXISTS direct_revocations (
    grant_id TEXT PRIMARY KEY,
    patient_ref TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    signed_revocation TEXT NOT NULL
);
"""


def master_key() -> bytes:
    if not MASTER_PATH.exists():
        MASTER_PATH.write_bytes(crypto.new_key())
        MASTER_PATH.chmod(0o600)
    return MASTER_PATH.read_bytes()


MASTER = master_key()


DB = ThreadLocalDB(DB_PATH, SCHEMA)


def kek_for(patient_ref: str) -> bytes:
    row = DB.execute("SELECT * FROM patients WHERE patient_ref = ?", (patient_ref,)).fetchone()
    if row is None:
        raise LookupError("unknown patient")
    if row["kek_sealed"] is None:
        raise PermissionError("patient key destroyed (crypto-shredded)")
    return crypto.unseal(MASTER, row["kek_sealed"], patient_ref.encode())


def aad(patient_ref: str, object_id: str) -> bytes:
    return f"{patient_ref}|{object_id}".encode()


class Enrollment(BaseModel):
    patient_ref: str
    pubkey: str


class WrapRequest(BaseModel):
    patient_ref: str
    object_id: str
    dek: str


class UnwrapRequest(BaseModel):
    patient_ref: str
    object_id: str
    wrapped_dek: str
    grant_id: str


class Signed(BaseModel):
    payload: dict
    sig: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/patients")
def enroll(body: Enrollment, _: str = Depends(require_one_of("hospital-admin"))):
    existing = DB.execute("SELECT 1 FROM patients WHERE patient_ref = ?", (body.patient_ref,)).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="patient already enrolled")
    kek = crypto.new_key()
    DB.execute("INSERT INTO patients (patient_ref, pubkey, kek_sealed) VALUES (?,?,?)",
               (body.patient_ref, body.pubkey, crypto.seal(MASTER, kek, body.patient_ref.encode())))
    DB.commit()
    return {"patient_ref": body.patient_ref, "kek": "created and sealed at the hospital"}


@app.post("/wrap")
def wrap(body: WrapRequest, actor: str = Depends(require_one_of("hospital-gateway"))):
    try:
        kek = kek_for(body.patient_ref)
    except (LookupError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    wrapped = crypto.seal(kek, b64d(body.dek), aad(body.patient_ref, body.object_id))
    return {"wrapped_dek": b64e(wrapped)}


def deny(actor: str, body: UnwrapRequest, reason: str, started: float):
    try:
        log_event(SERVICE, actor, "key.unwrap", "denied", patient_ref=body.patient_ref,
                  object_id=body.object_id, detail=reason)
    except AuditUnavailable:
        pass  # a denial is safe even if it could not be logged
    raise HTTPException(status_code=403, detail={"decision": "denied", "reason": reason,
                                                 "decision_ms": round((time.perf_counter() - started) * 1000, 2)})


@app.post("/unwrap")
def unwrap(body: UnwrapRequest, actor: str = Depends(require_actor)):
    started = time.perf_counter()
    patient = DB.execute("SELECT * FROM patients WHERE patient_ref = ?", (body.patient_ref,)).fetchone()
    if patient is None:
        deny(actor, body, "unknown patient", started)
    if patient["kek_sealed"] is None:
        deny(actor, body, "patient key destroyed (crypto-shredded)", started)

    direct = DB.execute("SELECT 1 FROM direct_revocations WHERE grant_id = ?", (body.grant_id,)).fetchone()
    if direct:
        deny(actor, body, "grant revoked (notice received directly from the patient)", started)

    try:
        response = client().get(f"{CONSENT_URL}/grants/{body.grant_id}", headers=bearer(SELF_TOKEN[SERVICE]), timeout=5)
    except httpx.HTTPError:
        deny(actor, body, "consent service unreachable", started)
    if response.status_code != 200:
        deny(actor, body, f"grant not found ({response.status_code})", started)
    grant = response.json()
    signed = grant["signed_grant"]
    payload = signed["payload"]

    if not crypto.verify(patient["pubkey"], signed):
        deny(actor, body, "grant signature invalid (not signed by the patient)", started)
    if payload.get("type") != "grant" or payload.get("grant_id") != body.grant_id:
        deny(actor, body, "malformed grant", started)
    if payload.get("patient_ref") != body.patient_ref:
        deny(actor, body, "grant is for another patient", started)
    if payload.get("grantee") != actor:
        deny(actor, body, "grant was not given to this requester", started)
    if parse_iso(payload["expires_at"]) < datetime.now(timezone.utc):
        deny(actor, body, "grant expired", started)
    if grant["status"] != "active":
        deny(actor, body, f"grant {grant['status']}", started)

    try:
        dek = crypto.unseal(kek_for(body.patient_ref), b64d(body.wrapped_dek), aad(body.patient_ref, body.object_id))
    except crypto.InvalidTag:
        deny(actor, body, "wrapped key does not match this patient and object", started)

    try:
        log_event(SERVICE, actor, "key.unwrap", "allowed", patient_ref=body.patient_ref,
                  object_id=body.object_id, detail=f"grant={body.grant_id} purpose={payload['purpose']}")
    except AuditUnavailable:
        deny(actor, body, "audit unavailable (no log, no key)", started)

    return {"decision": "allowed", "dek": b64e(dek),
            "decision_ms": round((time.perf_counter() - started) * 1000, 2)}


@app.post("/revocations")
def direct_revocation(signed: Signed):
    """Revocation sent by the patient's device straight to the hospital."""
    p = signed.payload
    patient = DB.execute("SELECT * FROM patients WHERE patient_ref = ?", (p.get("patient_ref"),)).fetchone()
    if patient is None or p.get("type") != "revocation":
        raise HTTPException(status_code=400, detail="not a revocation for a known patient")
    if not crypto.verify(patient["pubkey"], signed.model_dump()):
        raise HTTPException(status_code=400, detail="invalid patient signature")
    DB.execute("INSERT OR IGNORE INTO direct_revocations (grant_id, patient_ref, revoked_at, signed_revocation)"
               " VALUES (?,?,?,?)", (p["grant_id"], p["patient_ref"], p["revoked_at"], json.dumps(signed.model_dump())))
    DB.commit()
    return {"grant_id": p["grant_id"], "status": "revoked at the hospital"}


@app.post("/erase")
def erase(signed: Signed):
    """Right to erasure: destroy the patient's KEK. Every copy of every object, backups
    included, becomes permanently unreadable."""
    p = signed.payload
    patient = DB.execute("SELECT * FROM patients WHERE patient_ref = ?", (p.get("patient_ref"),)).fetchone()
    if patient is None or p.get("type") != "erase":
        raise HTTPException(status_code=400, detail="not an erasure request for a known patient")
    if not crypto.verify(patient["pubkey"], signed.model_dump()):
        raise HTTPException(status_code=400, detail="invalid patient signature")
    try:
        log_event(SERVICE, f"patient:{p['patient_ref']}", "key.erase", "destroyed", patient_ref=p["patient_ref"],
                  detail="patient KEK destroyed (crypto-shredding)")
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail="audit unavailable: erasure must be logged first")
    DB.execute("UPDATE patients SET kek_sealed = NULL, erased_at = ? WHERE patient_ref = ?",
               (p["requested_at"], p["patient_ref"]))
    DB.commit()
    return {"patient_ref": p["patient_ref"], "status": "key destroyed"}
