"""Minimal "the model comes to the data" job.

Runs in the isolated AI zone. It only processes objects covered by an active
grant made to this researcher, decrypts them in memory, and outputs aggregate
statistics only. A real training loop (e.g. PyTorch on PneumoniaMNIST) would
replace `summarise`. In the target architecture this job runs in a confidential
VM and the key broker requires a TEE attestation before releasing keys.

    python -m nexus.researcher.ai_job
"""
import io
import json
import sys

import httpx
import numpy as np
import pydicom

from ..common.config import CONSENT_URL, DATA_URL, TOKENS, bearer
from .client import DEFAULT_TOKEN, Denied, fetch


def run(token: str = DEFAULT_TOKEN, only_patient: str | None = None, inspect=None) -> dict:
    me = TOKENS[token]
    grants = httpx.get(f"{CONSENT_URL}/grants", params={"grantee": me}, headers=bearer(token), timeout=10).json()
    used, excluded, means = 0, 0, []
    for g in grants:
        if g["purpose"] not in ("research", "ai-training"):
            continue
        if only_patient and g["patient_ref"] != only_patient:
            continue
        objects = httpx.get(f"{DATA_URL}/objects", params={"patient_ref": g["patient_ref"]},
                            headers=bearer(token), timeout=30).json()
        for object_id in objects:
            try:
                plaintext, _ = fetch(object_id, g["grant_id"], token)
            except Denied:
                excluded += 1
                continue
            if inspect:
                inspect(plaintext)  # used by the G5 test to search the decrypted input
            ds = pydicom.dcmread(io.BytesIO(plaintext))
            means.append(float(np.asarray(ds.pixel_array, dtype=np.float64).mean()))
            used += 1
    return {"images_used": used, "images_excluded_no_valid_consent": excluded,
            "mean_pixel_intensity": round(float(np.mean(means)), 3) if means else None,
            "note": "aggregate output only; no image or identifier leaves the AI zone"}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
    sys.exit(0)
