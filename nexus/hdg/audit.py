"""HDG audit service: an append-only, hash-chained log of every access decision.

Each entry stores hash = SHA-256(previous_hash || canonical(entry)). Changing any
past entry breaks the chain from that point. An administrator who recomputes the
whole chain to hide an edit is caught by the hospital-side anchors (see
nexus/hospital/anchor.py), which keep copies of past head hashes outside HDG.
"""
import threading
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from ..common.auth import require_actor, require_one_of
from ..common.canon import now_iso
from ..common.config import service_dir
from ..common.db import ThreadLocalDB
from .chain import FIELDS, GENESIS, entry_hash

DB_PATH = service_dir("hdg") / "audit.sqlite"
WRITERS = ("hospital-gateway", "hospital-keybroker", "hdg-consent", "hdg-data-api")
READERS = ("hdg-consent", "hospital-anchor", "hospital-admin", "hdg-detector")

app = FastAPI(title="NEXUS audit service (HDG)")
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    patient_ref TEXT,
    object_id TEXT,
    detail TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""

DB = ThreadLocalDB(DB_PATH, SCHEMA)


class Event(BaseModel):
    actor: str
    action: str
    decision: str
    patient_ref: Optional[str] = None
    object_id: Optional[str] = None
    detail: Optional[str] = None
    source: Optional[str] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/events")
def append(event: Event, writer: str = Depends(require_one_of(*WRITERS))):
    with _lock:
        last = DB.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (last["seq"] + 1) if last else 1
        prev = last["hash"] if last else GENESIS
        fields = {
            "seq": seq,
            "ts": now_iso(),
            "source": writer,
            "actor": event.actor,
            "action": event.action,
            "decision": event.decision,
            "patient_ref": event.patient_ref,
            "object_id": event.object_id,
            "detail": event.detail,
        }
        digest = entry_hash(prev, fields)
        DB.execute(
            "INSERT INTO events (seq, ts, source, actor, action, decision, patient_ref, object_id, detail, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (*[fields[k] for k in FIELDS], prev, digest),
        )
        DB.commit()
    return {"seq": seq, "hash": digest}


@app.get("/head")
def head(_: str = Depends(require_actor)):
    last = DB.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    return {"seq": last["seq"], "hash": last["hash"]} if last else {"seq": 0, "hash": GENESIS}


@app.get("/hash-at/{seq}")
def hash_at(seq: int, _: str = Depends(require_actor)):
    row = DB.execute("SELECT hash FROM events WHERE seq = ?", (seq,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="no such entry")
    return {"seq": seq, "hash": row["hash"]}


@app.get("/verify")
def verify(_: str = Depends(require_actor)):
    """Recompute the whole chain from the stored rows."""
    prev = GENESIS
    checked = 0
    for row in DB.execute("SELECT * FROM events ORDER BY seq"):
        fields = {k: row[k] for k in FIELDS}
        if row["prev_hash"] != prev:
            return {"ok": False, "checked": checked, "first_bad_seq": row["seq"], "reason": "broken link to previous entry"}
        if entry_hash(prev, fields) != row["hash"]:
            return {"ok": False, "checked": checked, "first_bad_seq": row["seq"], "reason": "entry content does not match its hash"}
        prev = row["hash"]
        checked += 1
    return {"ok": True, "checked": checked, "head": prev}


@app.get("/events")
def events(patient_ref: Optional[str] = None, limit: int = 200, _: str = Depends(require_one_of(*READERS))):
    if patient_ref:
        rows = DB.execute(
            "SELECT * FROM events WHERE patient_ref = ? ORDER BY seq DESC LIMIT ?", (patient_ref, limit)
        ).fetchall()
    else:
        rows = DB.execute("SELECT * FROM events ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
