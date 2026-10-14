"""Incident detection and automatic containment (PoC stand-in for Falco + SIEM).

Watches the audit chain. When one account collects too many refusals in a short
window (stolen credentials probing data, enumeration of patient identifiers), it
raises an alert and disables that account at the identity provider, so every
service refuses its next request. Service accounts are never disabled
automatically: the alert asks a human to isolate the pod and rotate its secret,
because disabling a service account would take the platform down.

    python -m nexus.hdg.detector --threshold 10 --window 60
"""
import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone

import httpx

from ..common.auth import disable_actor, disabled_actors
from ..common.config import AUDIT_URL, bearer, service_dir

ALERTS = service_dir("hdg") / "alerts.jsonl"
SERVICE_ACCOUNTS = {"hospital-gateway", "hospital-keybroker", "hospital-admin", "hospital-anchor",
                    "hdg-consent", "hdg-data-api", "hdg-detector"}
TOKEN = "tok-detector"


def _ts(text: str) -> float:
    return datetime.fromisoformat(text).timestamp()


def scan_once(threshold: int, window_s: float, alerted: set) -> list[dict]:
    events = httpx.get(f"{AUDIT_URL}/events", params={"limit": 1000}, headers=bearer(TOKEN), timeout=5).json()
    now = time.time()
    refusals: dict[str, list[float]] = {}
    for e in events:
        if e["decision"] == "denied":
            t = _ts(e["ts"])
            if now - t <= window_s:
                refusals.setdefault(e["actor"], []).append(t)
    new_alerts = []
    for actor, times in refusals.items():
        if len(times) < threshold or actor in alerted:
            continue
        alerted.add(actor)
        detected_at = time.time()
        alert = {"actor": actor, "refusals_in_window": len(times), "window_s": window_s,
                 "first_refusal_at": min(times), "detected_at": detected_at}
        if actor in SERVICE_ACCOUNTS:
            alert["action"] = "service account: isolate the pod and rotate its secret (manual)"
        elif actor not in disabled_actors():
            disable_actor(actor)
            alert["action"] = "account disabled at the identity provider"
            alert["contained_at"] = time.time()
        with ALERTS.open("a") as fh:
            fh.write(json.dumps(alert) + "\n")
        new_alerts.append(alert)
    return new_alerts


def run(stop: threading.Event, threshold: int = 10, window_s: float = 60, interval: float = 0.5, on_alert=None):
    alerted: set = set()
    while not stop.is_set():
        try:
            for alert in scan_once(threshold, window_s, alerted):
                if on_alert:
                    on_alert(alert)
        except httpx.HTTPError:
            pass
        stop.wait(interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description="NEXUS incident detector")
    parser.add_argument("--threshold", type=int, default=10)
    parser.add_argument("--window", type=float, default=60)
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args(argv)
    run(threading.Event(), args.threshold, args.window, args.interval,
        on_alert=lambda a: print(json.dumps(a), flush=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
