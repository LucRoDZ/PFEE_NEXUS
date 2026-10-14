"""NEXUS demonstration: the mechanisms the report claims (G1, G2, G3, G5).

    python demo/scenes.py setup     # synthetic DICOM, patient enrollment, first consent
    python demo/scenes.py scene1    # HDG only ever sees ciphertext
    python demo/scenes.py scene2    # a revoked consent cuts access at once; erasure = crypto-shredding
    python demo/scenes.py scene3    # any edit to the audit log is detected
    python demo/scenes.py scene5    # the AI job never sees or outputs an identity; revoked patients excluded
    python demo/scenes.py all       # everything, in order
    python demo/scenes.py watch     # video: live ALLOWED/DENIED while you click Revoke in the portal
    python demo/scenes.py erase     # video: crypto-shredding on its own

Results are written to var/results.json for the report.
"""
import io
import json
import math
import sqlite3
import sys
import threading
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import boto3  # noqa: E402
import httpx  # noqa: E402
import pydicom  # noqa: E402
from botocore.client import Config  # noqa: E402

from demo.make_sample_dicom import FAKE_PATIENT, make  # noqa: E402
from nexus.common import config  # noqa: E402
from nexus.hospital import anchor  # noqa: E402
from nexus.hospital.deid import pseudonym  # noqa: E402
from nexus.hospital.gateway import upload_bytes  # noqa: E402
from nexus.patient import agent  # noqa: E402
from nexus.researcher import client  # noqa: E402

VAR = config.DATA_DIR
STATE = VAR / "demo_state.json"
RESULTS = VAR / "results.json"
PROFILE = agent.Profile(VAR / "patient")
RESEARCHER = "dr-alice-research"

GREEN, RED, BOLD, DIM, END = "\033[32m", "\033[31m", "\033[1m", "\033[2m", "\033[0m"


def title(text):
    print(f"\n{BOLD}{'=' * 72}\n{text}\n{'=' * 72}{END}")


def step(text):
    print(f"\n{BOLD}> {text}{END}")


def ok(text):
    print(f"  {GREEN}PASS{END}  {text}")


def fail(text):
    print(f"  {RED}FAIL{END}  {text}")


def check(condition, text, results, key):
    (ok if condition else fail)(text)
    results.setdefault("checks", {})[key] = bool(condition)
    return condition


def load(path, default):
    return json.loads(path.read_text()) if path.exists() else default


def save(path, data):
    path.write_text(json.dumps(data, indent=2))


# --------------------------------------------------------------------------------

def setup():
    title("SETUP  synthetic data, patient enrollment, first consent")
    samples = VAR / "samples"
    files = [make(samples / f"chest_{i + 1}.dcm", FAKE_PATIENT, seed=i) for i in range(3)]
    burned = make(samples / "chest_burned_in.dcm", FAKE_PATIENT, seed=99, burned_in=True)
    print(f"  {len(files)} synthetic chest X-rays for fake patient {FAKE_PATIENT['PatientName']} "
          f"({FAKE_PATIENT['PatientID']}), plus 1 with burned-in text")

    step("Enrollment at the hospital: the patient's device creates its own signing key")
    ref = pseudonym(FAKE_PATIENT["PatientID"])
    meta = PROFILE.init(ref)
    print(f"  pseudonym {ref}  (the link to {FAKE_PATIENT['PatientID']} stays in the hospital's mapping table)")
    r = httpx.post(f"{config.BROKER_URL}/patients", headers=config.bearer("tok-hospital-admin"),
                   json={"patient_ref": ref, "pubkey": meta["pubkey"]})
    r.raise_for_status()
    print(f"  key broker (hospital): {r.json()['kek']}")
    r = httpx.post(f"{config.CONSENT_URL}/patients", headers=config.bearer("tok-hospital-admin"),
                   json={"patient_ref": ref, "pubkey": meta["pubkey"]})
    r.raise_for_status()
    PROFILE.set_token(r.json()["patient_token"])
    print("  consent service (HDG): patient registered")

    step("Patient grants research access to Dr Alice, signed on the patient's device")
    g = agent.grant(PROFILE, RESEARCHER, "research", days=30)
    print(f"  grant {g['grant_id']}  status {g['status']}")
    save(STATE, {"patient_ref": ref, "grant_id": g["grant_id"], "files": [str(f) for f in files],
                 "burned": str(burned)})


# --------------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def scene1():
    state = load(STATE, None)
    results = load(RESULTS, {})
    r1 = results.setdefault("scene1", {})
    title("SCENE 1  HDG only ever sees ciphertext")

    step("The hospital gateway de-identifies, encrypts and uploads 3 chest X-rays")
    objects = []
    for path in state["files"]:
        out = upload_bytes(Path(path).read_bytes())
        objects.append(out["object_id"])
        print(f"  {Path(path).name}  ->  object {out['object_id'][:8]}…  {out['bytes']} bytes  {out['timings_ms']}")
    r1["upload_timings_ms"] = out["timings_ms"]
    state["objects"] = objects

    step("A file with burned-in text in the pixels is quarantined, not uploaded")
    from nexus.hospital.deid import Quarantined
    try:
        upload_bytes(Path(state["burned"]).read_bytes())
        quarantined = False
    except Quarantined as exc:
        quarantined = True
        print(f"  {exc}")
    check(quarantined, "burned-in annotation refused at the source", r1, "burned_in_quarantined")

    step("Malicious HDG administrator reads the storage directly, bypassing every API")
    s3 = boto3.client("s3", endpoint_url=config.S3_ENDPOINT, aws_access_key_id=config.S3_ACCESS_KEY,
                      aws_secret_access_key=config.S3_SECRET_KEY, region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}))
    raw = []
    for item in s3.list_objects_v2(Bucket=config.S3_BUCKET).get("Contents", []):
        obj = s3.get_object(Bucket=config.S3_BUCKET, Key=item["Key"])
        raw.append((item["Key"], obj["Body"].read(), obj["Metadata"]))
    print(f"  {len(raw)} objects downloaded by the admin")
    r1["objects_read_by_admin"] = len(raw)
    secrets_found = []
    for key, data, meta in raw:
        h = entropy(data)
        found = [label for label, marker in [("DICOM header", b"DICM"), ("patient name", b"DOE^JANE"),
                                             ("patient ID", FAKE_PATIENT["PatientID"].encode()),
                                             ("hospital", b"Saint-Exemple"), ("PNG", b"\x89PNG")]
                 if marker in data]
        secrets_found += found
        print(f"  {key[:8]}…  entropy {h:.3f} bits/byte (8.000 = random)   readable markers: {found or 'none'}")
        r1["entropy_bits_per_byte"] = round(h, 4)
    r1["markers_found"] = secrets_found
    check(not secrets_found, "no DICOM header, name, patient ID or hospital name in what HDG stores", r1,
          "storage_ciphertext_only")

    step("The admin asks the hospital key broker for a data key, without a patient grant")
    key, data, meta = raw[0]
    denied_reason = None
    try:
        client.request_key(meta["patient-ref"], key, meta["wrapped-dek"], "forged-grant", token="tok-data")
    except client.Denied as exc:
        denied_reason = exc.reason
    print(f"  broker answer: {denied_reason}")
    r1["hdg_key_request_answer"] = denied_reason
    check(denied_reason is not None, "HDG cannot obtain a key; the attempt is logged in the patient's history",
          r1, "hdg_key_request_denied")

    step("Key material on HDG's side")
    hdg_files = sorted(p.name for p in (VAR / "hdg").iterdir())
    hospital_files = sorted(p.name for p in (VAR / "hospital").iterdir())
    print(f"  HDG holds:       {hdg_files}   (audit log, consent records: no keys)")
    print(f"  hospital holds:  {hospital_files}")
    check(not any("key" in f for f in hdg_files), "no key file on HDG's side", r1, "no_keys_at_hdg")
    save(STATE, state)
    save(RESULTS, results)


# --------------------------------------------------------------------------------

def scene2():
    state = load(STATE, None)
    results = load(RESULTS, {})
    r2 = results.setdefault("scene2", {})
    title("SCENE 2  a revoked consent cuts access at once")
    object_id, grant_id = state["objects"][0], state["grant_id"]

    step("Dr Alice, with the patient's grant, opens the image")
    plaintext, ms = client.fetch(object_id, grant_id)
    ds = pydicom.dcmread(io.BytesIO(plaintext))
    print(f"  key released in {ms} ms; image {ds.Rows}x{ds.Columns}")
    print(f"  PatientID = {ds.PatientID!r}  PatientName = {str(ds.PatientName)!r}  "
          f"PatientIdentityRemoved = {ds.PatientIdentityRemoved}")
    r2["authorized_key_release_ms"] = ms
    check(ds.PatientID == state["patient_ref"] and str(ds.PatientName) == "",
          "researcher sees a pseudonymized image, never the identity", r2, "pseudonymized_for_researcher")

    step("Dr Alice's tool keeps requesting the key every 100 ms; the patient revokes from their device")
    ciphertext, patient_ref, wrapped = client.fetch_ciphertext(object_id)
    attempts = []
    stop = threading.Event()

    def hammer():
        while not stop.is_set():
            t = time.perf_counter()
            try:
                client.request_key(patient_ref, object_id, wrapped, grant_id)
                attempts.append((t, time.perf_counter(), "allowed"))
            except client.Denied:
                attempts.append((t, time.perf_counter(), "denied"))
            time.sleep(0.1)

    worker = threading.Thread(target=hammer)
    worker.start()
    time.sleep(1.0)
    t_click = time.perf_counter()
    rev = agent.revoke(PROFILE, grant_id)
    t_done = time.perf_counter()
    time.sleep(1.5)
    stop.set()
    worker.join()

    before = [a for a in attempts if a[1] < t_click]
    after = [a for a in attempts if a[0] > t_done]
    first_denied = next((a for a in attempts if a[2] == "denied"), None)
    delay_ms = (first_denied[1] - t_click) * 1000 if first_denied else None
    print(f"  before revocation: {Counter(a[2] for a in before)}")
    print(f"  revocation recorded at the hospital and at HDG in {rev['round_trip_ms']} ms")
    print(f"  after revocation:  {Counter(a[2] for a in after)}")
    if delay_ms is not None:
        print(f"  first refusal {delay_ms:.0f} ms after the click (requests are 100 ms apart)")
    r2.update({"revocation_round_trip_ms": rev["round_trip_ms"],
               "click_to_first_denial_ms": round(delay_ms, 1) if delay_ms else None,
               "allowed_before_revocation": sum(1 for a in before if a[2] == "allowed"),
               "requests_after_revocation": len(after),
               "allowed_after_revocation": sum(1 for a in after if a[2] == "allowed")})
    check(all(a[2] == "allowed" for a in before), "access worked before revocation", r2, "allowed_before")
    check(after and all(a[2] == "denied" for a in after), "zero successful request after revocation", r2,
          "denied_after")
    check(delay_ms is not None and delay_ms < 5000, "revocation effective in under 5 seconds", r2, "under_5s")

    erasure(state, r2, ciphertext)
    save(RESULTS, results)


def erasure(state, r2, backup_copy):
    object_id = state["objects"][0]
    step("Right to erasure: the patient asks the hospital to destroy their key (crypto-shredding)")
    erased = agent.erase(PROFILE)
    print(f"  {erased}")
    try:
        # even a brand-new grant cannot bring the data back
        g2 = agent.grant(PROFILE, RESEARCHER, "research", days=1)
        client.fetch(object_id, g2["grant_id"], ciphertext_override=backup_copy)
        restored = True
    except client.Denied as exc:
        restored = False
        r2["erasure_answer"] = exc.reason
        print(f"  restore from backup + new grant: {exc.reason}")
    check(not restored, "backup copies are permanently unreadable once the key is destroyed", r2,
          "crypto_shredding")


def watch():
    """For the video: run in a terminal, then click Revoke in the portal."""
    state = load(STATE, None)
    title("WATCH  Dr Alice's tool requests the key every 100 ms (Ctrl-C to stop)")
    client.main(["watch", state["objects"][0], state["grant_id"], "--interval", "0.1"])


def erase_only():
    state = load(STATE, None)
    results = load(RESULTS, {})
    title("ERASURE  crypto-shredding")
    ciphertext, _, _ = client.fetch_ciphertext(state["objects"][0])
    erasure(state, results.setdefault("scene2", {}), ciphertext)
    save(RESULTS, results)


# --------------------------------------------------------------------------------

def scene3():
    results = load(RESULTS, {})
    r3 = results.setdefault("scene3", {})
    title("SCENE 3  any edit to the audit log is detected")
    state = load(STATE, None)

    step("What the patient sees in their portal (EHDS article 9)")
    log = agent.my_access_log(PROFILE)
    for e in sorted(log, key=lambda e: e["seq"])[-8:]:
        print(f"  #{e['seq']:<3} {e['ts'][11:19]}  {e['actor'][:26]:<26} {e['action']:<15} {e['decision']:<17} "
              f"{DIM}{(e['detail'] or '')[:55]}{END}")
    r3["patient_visible_events"] = len(log)

    anchor.take_anchor()
    step("Integrity check before any tampering")
    before = anchor.check()
    print(f"  chain self-consistent: {before['chain_self_consistent']}   hospital anchors match: {before['anchors_ok']}"
          f"   ({before['anchors_checked']} anchors)")
    check(before["chain_self_consistent"] and before["anchors_ok"], "log intact", r3, "intact_before")

    db_path = VAR / "hdg" / "audit.sqlite"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    target = conn.execute("SELECT * FROM events WHERE actor = 'hdg-data-api' AND action = 'key.unwrap' "
                          "ORDER BY seq LIMIT 1").fetchone()

    step(f"Attack 1: the admin edits entry #{target['seq']} to hide his failed key request")
    conn.executescript("DROP TRIGGER events_no_update; DROP TRIGGER events_no_delete;")
    conn.execute("UPDATE events SET actor = 'dr-alice-research', decision = 'allowed' WHERE seq = ?", (target["seq"],))
    conn.commit()
    t = time.perf_counter()
    v1 = httpx.get(f"{config.AUDIT_URL}/verify", headers=config.bearer("tok-anchor")).json()
    r3["detect_edit_ms"] = round((time.perf_counter() - t) * 1000, 1)
    print(f"  verification: ok={v1['ok']}  first bad entry #{v1.get('first_bad_seq')}  ({v1.get('reason')})")
    r3["edited_entry"] = target["seq"]
    r3["edit_detected_at"] = v1.get("first_bad_seq")
    check(not v1["ok"] and v1["first_bad_seq"] == target["seq"], "edit detected at the exact entry", r3,
          "edit_detected")

    step("Attack 2: the admin deletes the entry and recomputes every hash after it")
    from nexus.hdg.chain import FIELDS, GENESIS, entry_hash
    rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY seq")]
    rows = [r for r in rows if r["seq"] != target["seq"]]
    conn.execute("DELETE FROM events")
    prev = GENESIS
    for new_seq, r in enumerate(rows, start=1):
        r["seq"] = new_seq
        fields = {k: r[k] for k in FIELDS}
        h = entry_hash(prev, fields)
        conn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (*[fields[k] for k in FIELDS], prev, h))
        prev = h
    conn.commit()
    conn.close()
    v2 = httpx.get(f"{config.AUDIT_URL}/verify", headers=config.bearer("tok-anchor")).json()
    print(f"  HDG's own verification now says ok={v2['ok']}  (the forgery is self-consistent)")
    after = anchor.check()
    print(f"  hospital anchors: match={after['anchors_ok']}  first mismatch at #{after.get('first_mismatch_seq')}")
    print(f"    anchored  {str(after.get('anchored_hash'))[:16]}…   now reported {str(after.get('hash_now_reported'))[:16]}…")
    r3["rewrite_passes_hdg_check"] = v2["ok"]
    r3["rewrite_first_anchor_mismatch"] = after.get("first_mismatch_seq")
    check(v2["ok"] and not after["anchors_ok"], "full rewrite detected by the hospital's anchors", r3,
          "rewrite_detected")
    save(RESULTS, results)


# --------------------------------------------------------------------------------

G5_PATIENT = dict(FAKE_PATIENT, PatientName="ROE^RICHARD", PatientID="IPP-5150-0042",
                  PatientBirthDate="19710905", AccessionNumber="ACC-2026-004411")


def identity_markers(patient: dict) -> dict:
    return {label: patient[key].encode() for label, key in [
        ("name", "PatientName"), ("patient ID", "PatientID"), ("birth date", "PatientBirthDate"),
        ("hospital", "InstitutionName"), ("referring physician", "ReferringPhysicianName"),
        ("accession number", "AccessionNumber")]}


def scene5():
    from nexus.researcher import ai_job
    results = load(RESULTS, {})
    r5 = results.setdefault("scene5", {})
    title("SCENE 5  the AI job never sees or outputs an identity")

    step("A second patient is enrolled, 3 X-rays carrying a fake identity are uploaded, research is granted")
    ref = pseudonym(G5_PATIENT["PatientID"])
    profile = agent.Profile(VAR / "patient-g5")
    meta = profile.init(ref)
    adm = config.bearer("tok-hospital-admin")
    httpx.post(f"{config.BROKER_URL}/patients", headers=adm, json={"patient_ref": ref, "pubkey": meta["pubkey"]}).raise_for_status()
    r = httpx.post(f"{config.CONSENT_URL}/patients", headers=adm, json={"patient_ref": ref, "pubkey": meta["pubkey"]})
    r.raise_for_status()
    profile.set_token(r.json()["patient_token"])
    for i in range(3):
        upload_bytes(make(VAR / "samples" / f"g5_{i + 1}.dcm", G5_PATIENT, seed=40 + i).read_bytes())
    g = agent.grant(profile, RESEARCHER, "research", days=30)
    print(f"  patient {ref}, grant {g['grant_id'][:8]}…")

    step("The AI job runs in the AI zone; everything it decrypts and everything it outputs is searched")
    markers = identity_markers(G5_PATIENT)
    seen_inputs, found_in = [], []

    def inspect(plaintext: bytes):
        seen_inputs.append(plaintext)
        found_in.extend(label for label, m in markers.items() if m in plaintext)

    out = ai_job.run(only_patient=ref, inspect=inspect)
    output_text = json.dumps(out).encode()
    found_out = [label for label, m in markers.items() if m in output_text]
    print(f"  images processed: {out['images_used']}   identity fields found in inputs: {sorted(set(found_in)) or 'none'}")
    print(f"  output: {out}")
    print(f"  identity fields found in the output: {found_out or 'none'}")
    r5.update({"images_processed": out["images_used"], "identity_in_inputs": sorted(set(found_in)),
               "identity_in_output": found_out, "fields_searched": list(markers)})
    check(out["images_used"] == 3 and not found_in, "no identity in anything the AI zone receives", r5,
          "no_identity_in_ai_inputs")
    check(not found_out, "no identity in what the AI zone outputs", r5, "no_identity_in_ai_output")

    step("The patient withdraws consent; the next AI run must exclude every one of their images")
    agent.revoke(profile, g["grant_id"])
    out2 = ai_job.run(only_patient=ref)
    print(f"  next run: used {out2['images_used']}, excluded {out2['images_excluded_no_valid_consent']}")
    r5.update({"next_run_used": out2["images_used"], "next_run_excluded": out2["images_excluded_no_valid_consent"]})
    check(out2["images_used"] == 0 and out2["images_excluded_no_valid_consent"] == 3,
          "revoked patient excluded from the next AI run", r5, "revoked_excluded_from_ai")
    save(RESULTS, results)


def main():
    scenes = {"setup": [setup], "scene1": [scene1], "scene2": [scene2], "scene3": [scene3],
              "scene5": [scene5], "watch": [watch], "erase": [erase_only],
              "all": [setup, scene1, scene2, scene5, scene3]}
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    for fn in scenes[cmd]:
        fn()
    results = load(RESULTS, {})
    checks = {k: v for s in ("scene1", "scene2", "scene3", "scene5")
              for k, v in results.get(s, {}).get("checks", {}).items()}
    if cmd == "all":
        passed = sum(checks.values())
        print(f"\n{BOLD}{passed}/{len(checks)} checks passed. Results in {RESULTS}{END}")
        return 0 if passed == len(checks) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
