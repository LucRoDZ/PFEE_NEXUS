"""Red-team scenario (report §7): a phished clinician account attacks NEXUS.

    python demo/redteam.py      # needs `make up`; creates its own victim patient

1. Compromise: the attacker logs in with a clinician's stolen password.
2. Abuse: he requests the file of a patient who withdrew consent, then
   enumerates patient identifiers to find other files.
3. Escalation: from a shell in an HDG pod he reads the raw storage and asks the
   key broker for keys with the pod's own service token.

The detector watches the audit chain, raises an alert and disables the account.
The script measures detection and containment time, then analyses the incident
from the audit chain alone, and counts how many keys the attacker obtained.
Results go to var/redteam.json.
"""
import json
import math
import sys
import threading
import time
import uuid
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import boto3  # noqa: E402
import httpx  # noqa: E402
from botocore.client import Config  # noqa: E402

from demo.loadtest import fresh_patient  # noqa: E402
from nexus.common import config  # noqa: E402
from nexus.hdg import detector  # noqa: E402
from nexus.patient import agent  # noqa: E402

VAR = config.DATA_DIR
ATTACKER_TOKEN = "tok-clinician"
ATTACKER = config.TOKENS[ATTACKER_TOKEN]
POD_TOKEN = "tok-data"
BOLD, GREEN, RED, END = "\033[1m", "\033[32m", "\033[31m", "\033[0m"


def step(text):
    print(f"\n{BOLD}> {text}{END}")


def entropy(data: bytes) -> float:
    counts = Counter(data)
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts.values())


def key_request(token, patient_ref, object_id, wrapped, grant_id):
    r = httpx.post(f"{config.BROKER_URL}/unwrap", headers=config.bearer(token), timeout=10,
                   json={"patient_ref": patient_ref, "object_id": object_id,
                         "wrapped_dek": wrapped, "grant_id": grant_id})
    if r.status_code == 200:
        return "KEY RELEASED"
    detail = r.json().get("detail")
    return detail.get("reason", "denied") if isinstance(detail, dict) else str(detail)


def analyse(actor: str) -> dict:
    events = httpx.get(f"{config.AUDIT_URL}/events", params={"limit": 5000},
                       headers=config.bearer("tok-detector"), timeout=10).json()
    mine = [e for e in events if e["actor"] == actor]
    return {
        "events": len(mine),
        "by_action_and_decision": dict(Counter(f"{e['action']} {e['decision']}" for e in mine)),
        "patients_targeted": len({e["patient_ref"] for e in mine if e["patient_ref"]}),
        "keys_released": sum(1 for e in mine if e["action"] == "key.unwrap" and e["decision"] == "allowed"),
        "first_event": min((e["ts"] for e in mine), default=None),
        "last_event": max((e["ts"] for e in mine), default=None),
    }


def main():
    result = {}
    print(f"{BOLD}RED TEAM  phished clinician account '{ATTACKER}' attacks NEXUS{END}")

    step("Setup: a victim patient with 1 image, who granted research access and then withdrew it")
    profile, object_id, grant_id, _ = fresh_patient("victim")
    agent.revoke(profile, grant_id)
    victim = profile.meta["patient_ref"]
    print(f"  victim {victim}, object {object_id[:8]}…, grant {grant_id[:8]}… (revoked)")

    alerts = []
    stop = threading.Event()
    watcher = threading.Thread(target=detector.run, kwargs={"stop": stop, "threshold": 10, "window_s": 60,
                                                             "interval": 0.5, "on_alert": alerts.append})
    watcher.start()
    time.sleep(1.0)

    step("1-2. The attacker requests the victim's file, then enumerates patient identifiers")
    answers = Counter()
    t_attack = time.time()
    r = httpx.get(f"{config.DATA_URL}/objects/{object_id}", headers=config.bearer(ATTACKER_TOKEN), timeout=10)
    wrapped = r.headers.get("X-Wrapped-Dek", "")
    print(f"  victim's file: HTTP {r.status_code}, {len(r.content)} bytes of ciphertext "
          f"(entropy {entropy(r.content):.3f} bits/byte)")
    answers[key_request(ATTACKER_TOKEN, victim, object_id, wrapped, grant_id)] += 1
    t_blocked_seen = None
    attempts = 0
    while time.time() - t_attack < 20:
        attempts += 1
        guess_ref = "P-" + uuid.uuid4().hex[:16]
        answer = key_request(ATTACKER_TOKEN, guess_ref, str(uuid.uuid4()), wrapped, str(uuid.uuid4()))
        answers[answer] += 1
        if answer == "account disabled":
            t_blocked_seen = time.time()
            break
        time.sleep(0.1)
    print(f"  {attempts} enumeration attempts; answers: {dict(answers)}")

    step("3. Escalation: from a shell in an HDG pod, read the raw storage and ask for keys with the pod's token")
    s3 = boto3.client("s3", endpoint_url=config.S3_ENDPOINT, aws_access_key_id=config.S3_ACCESS_KEY,
                      aws_secret_access_key=config.S3_SECRET_KEY, region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}))
    raw = s3.get_object(Bucket=config.S3_BUCKET, Key=object_id)
    data, meta = raw["Body"].read(), raw["Metadata"]
    pod_answers = Counter(key_request(POD_TOKEN, meta["patient-ref"], object_id, meta["wrapped-dek"], grant_id)
                          for _ in range(3))
    print(f"  raw object: entropy {entropy(data):.3f} bits/byte; key requests with the pod token: {dict(pod_answers)}")

    time.sleep(1.0)
    stop.set()
    watcher.join()

    step("Detection and containment")
    mine = next((a for a in alerts if a["actor"] == ATTACKER), None)
    if mine:
        result["detect_s"] = round(mine["detected_at"] - t_attack, 2)
        result["contain_s"] = round(mine.get("contained_at", mine["detected_at"]) - t_attack, 2)
        print(f"  {GREEN}alert{END} after {mine['refusals_in_window']} refusals: detected T+{result['detect_s']} s, "
              f"account disabled T+{result['contain_s']} s")
    else:
        print(f"  {RED}no alert raised{END}")
    if t_blocked_seen:
        result["attacker_blocked_s"] = round(t_blocked_seen - t_attack, 2)
        print(f"  the attacker's next request was refused as 'account disabled' at T+{result['attacker_blocked_s']} s")

    step("Analysis from the audit chain alone")
    t = time.perf_counter()
    report = analyse(ATTACKER)
    result["analysis_ms"] = round((time.perf_counter() - t) * 1000, 1)
    print(f"  built in {result['analysis_ms']} ms: {report['events']} events, "
          f"{report['patients_targeted']} patient references targeted, keys released: {report['keys_released']}")
    for k, v in report["by_action_and_decision"].items():
        print(f"    {v:>4}  {k}")

    keys_to_attacker = answers.get("KEY RELEASED", 0) + pod_answers.get("KEY RELEASED", 0)
    result.update({"attacker": ATTACKER, "attempts": attempts + 1, "answers": dict(answers),
                   "pod_token_answers": dict(pod_answers), "raw_storage_entropy": round(entropy(data), 4),
                   "keys_obtained_by_attacker": keys_to_attacker, "analysis": report,
                   "alerts": alerts})
    ok = bool(mine) and keys_to_attacker == 0 and t_blocked_seen is not None
    print(f"\n{BOLD}{'PASS' if ok else 'FAIL'}{END}  keys obtained by the attacker: {keys_to_attacker}; "
          f"plaintext exposed: {'none' if keys_to_attacker == 0 else 'YES'}")
    (VAR / "redteam.json").write_text(json.dumps(result, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
