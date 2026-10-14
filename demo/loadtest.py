"""Load test: what each protection costs, and whether revocation holds under load.

    python demo/loadtest.py --mode read  --seconds 30 --concurrency 20   # ciphertext only
    python demo/loadtest.py --mode full  --seconds 30 --concurrency 20   # ciphertext + key + decrypt
    python demo/loadtest.py --mode upload --count 50 --concurrency 5     # de-identify + encrypt + wrap + store
    python demo/loadtest.py --mode revoke --seconds 20 --concurrency 20  # revoke halfway through a full load

Run `python demo/scenes.py setup` first (the test creates its own patient and grant).
Results go to var/loadtest-<mode>.json.
"""
import argparse
import asyncio
import json
import statistics
from collections import Counter
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

from demo.make_sample_dicom import make  # noqa: E402
from nexus.common import config, crypto  # noqa: E402
from nexus.common.canon import b64d  # noqa: E402
from nexus.hospital.deid import pseudonym  # noqa: E402
from nexus.hospital.gateway import upload_bytes  # noqa: E402
from nexus.patient import agent  # noqa: E402

VAR = config.DATA_DIR
TOKEN = config.bearer("tok-researcher")
DECISIONS = []  # key-broker decision time (ms), as reported by the broker


def percentile(values, p):
    if not values:
        return None
    values = sorted(values)
    k = max(0, min(len(values) - 1, int(round(p / 100 * len(values) + 0.5)) - 1))
    return round(values[k], 2)


def summary(latencies, errors, elapsed):
    if isinstance(errors, Counter):
        by_cause = dict(errors)
        errors = sum(errors.values())
    else:
        by_cause = None
    return {"requests": len(latencies) + errors, "errors": errors, "errors_by_cause": by_cause, "seconds": round(elapsed, 2),
            "throughput_rps": round(len(latencies) / elapsed, 1) if elapsed else None,
            "p50_ms": percentile(latencies, 50), "p95_ms": percentile(latencies, 95),
            "p99_ms": percentile(latencies, 99), "mean_ms": round(statistics.mean(latencies), 2) if latencies else None}


def fresh_patient(tag: str):
    """Enroll a dedicated load-test patient, upload one image, grant Dr Alice."""
    patient_id = f"LOAD-{tag}-{int(time.time())}"
    ref = pseudonym(patient_id)
    profile = agent.Profile(VAR / f"patient-{tag}")
    meta = profile.init(ref)
    adm = config.bearer("tok-hospital-admin")
    httpx.post(f"{config.BROKER_URL}/patients", headers=adm, json={"patient_ref": ref, "pubkey": meta["pubkey"]}).raise_for_status()
    r = httpx.post(f"{config.CONSENT_URL}/patients", headers=adm, json={"patient_ref": ref, "pubkey": meta["pubkey"]})
    profile.set_token(r.json()["patient_token"])
    sample = make(VAR / "samples" / f"load-{tag}.dcm", {"PatientName": "LOAD^TEST", "PatientID": patient_id}, seed=7)
    obj = upload_bytes(sample.read_bytes())
    g = agent.grant(profile, "dr-alice-research", "research", days=1)
    return profile, obj["object_id"], g["grant_id"], patient_id


class RequestFailed(Exception):
    """A non-decision failure (HTTP error, unreadable answer): counted as an error, by cause."""


async def one_full(http, object_id, grant_id):
    r = await http.get(f"{config.DATA_URL}/objects/{object_id}", headers=TOKEN)
    if r.status_code != 200:
        raise RequestFailed(f"data API HTTP {r.status_code}")
    body = {"patient_ref": r.headers["X-Patient-Ref"], "object_id": object_id,
            "wrapped_dek": r.headers["X-Wrapped-Dek"], "grant_id": grant_id}
    k = await http.post(f"{config.BROKER_URL}/unwrap", headers=TOKEN, json=body)
    try:
        answer = k.json()
    except ValueError:
        raise RequestFailed(f"key broker HTTP {k.status_code}, not JSON")
    if k.status_code == 200:
        DECISIONS.append(answer["decision_ms"])
        crypto.unseal(b64d(answer["dek"]), r.content, object_id.encode())
        return "allowed"
    detail = answer.get("detail")
    if k.status_code == 403 and isinstance(detail, dict):
        DECISIONS.append(detail.get("decision_ms", 0))
        return "denied: " + detail.get("reason", "?")
    raise RequestFailed(f"key broker HTTP {k.status_code}: {str(detail)[:60]}")


async def run_for(seconds, concurrency, fn):
    latencies, outcomes, errors = [], [], Counter()
    deadline = time.perf_counter() + seconds

    async def worker(http):
        while time.perf_counter() < deadline:
            t = time.perf_counter()
            try:
                result = await fn(http)
                end = time.perf_counter()
                latencies.append((end - t) * 1000)
                outcomes.append((t, end, result))
            except RequestFailed as exc:
                errors[str(exc)] += 1
            except Exception as exc:
                errors[type(exc).__name__] += 1

    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=30, limits=httpx.Limits(max_connections=concurrency * 2)) as http:
        await asyncio.gather(*(worker(http) for _ in range(concurrency)))
    return latencies, outcomes, errors, time.perf_counter() - start


async def main_async(args):
    if args.mode == "upload":
        profile, _, _, patient_id = fresh_patient("up")  # enrolls the patient so the broker can wrap keys
        sample = make(VAR / "samples" / "load-upload.dcm", {"PatientName": "LOAD^UP", "PatientID": patient_id}, seed=3)
        data = sample.read_bytes()
        latencies, errors = [], 0
        sem = asyncio.Semaphore(args.concurrency)

        async def up():
            nonlocal errors
            async with sem:
                t = time.perf_counter()
                try:
                    await asyncio.to_thread(upload_bytes, data)
                    latencies.append((time.perf_counter() - t) * 1000)
                except Exception:
                    errors += 1

        start = time.perf_counter()
        await asyncio.gather(*(up() for _ in range(args.count)))
        result = summary(latencies, errors, time.perf_counter() - start)
        result["image_bytes"] = len(data)
        return result

    profile, object_id, grant_id, _ = fresh_patient(args.mode)

    if args.mode == "read":
        async def fn(http):
            r = await http.get(f"{config.DATA_URL}/objects/{object_id}", headers=TOKEN)
            if r.status_code != 200:
                raise RequestFailed(f"data API HTTP {r.status_code}")
            return "ok"
        lat, _, err, el = await run_for(args.seconds, args.concurrency, fn)
        return summary(lat, err, el)

    if args.mode == "full":
        lat, out, err, el = await run_for(args.seconds, args.concurrency, lambda h: one_full(h, object_id, grant_id))
        return {**summary(lat, err, el), "outcomes": dict(Counter(o for _, _, o in out)),
                "key_decision_p50_ms": percentile(DECISIONS, 50),
                "key_decision_p95_ms": percentile(DECISIONS, 95)}

    # revoke under load
    revoke_at = {}

    async def revoker():
        await asyncio.sleep(args.seconds / 2)
        revoke_at["t0"] = time.perf_counter()
        await asyncio.to_thread(agent.revoke, profile, grant_id)
        revoke_at["t1"] = time.perf_counter()

    task = asyncio.create_task(revoker())
    lat, out, err, el = await run_for(args.seconds, args.concurrency, lambda h: one_full(h, object_id, grant_id))
    await task
    t0, t1 = revoke_at["t0"], revoke_at["t1"]
    before = [o for _, end, o in out if end < t0]
    after = [o for start, _, o in out if start > t1]
    # first refusal *caused by the revocation*, measured from the click
    first_revoked = min((end for _, end, o in out if end >= t0 and "revoked" in o), default=None)
    result = summary(lat, err, el)
    result.update({
        "revocation_round_trip_ms": round((t1 - t0) * 1000, 1),
        "first_revocation_denial_after_click_ms": round((first_revoked - t0) * 1000, 1) if first_revoked else None,
        "requests_started_after_revocation": len(after),
        "allowed_after_revocation": sum(1 for o in after if o == "allowed"),
        "outcomes_before_revocation": dict(Counter(before)),
        "outcomes_after_revocation": dict(Counter(after)),
    })
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["read", "full", "upload", "revoke"], required=True)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--count", type=int, default=50)
    args = parser.parse_args()
    result = {"mode": args.mode, "concurrency": args.concurrency, **asyncio.run(main_async(args))}
    out = VAR / f"loadtest-{args.mode}.json"
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
