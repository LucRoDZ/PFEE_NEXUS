"""Hospital gateway: de-identify, encrypt, then upload. Runs inside the hospital.

    python -m nexus.hospital.gateway upload path/to/file.dcm

For each file: de-identify (pseudonym, mapping kept locally), draw a fresh
256-bit data key, encrypt with AES-256-GCM, have the hospital key broker wrap the
data key with the patient's KEK, and send only ciphertext + wrapped key to HDG.
"""
import argparse
import io
import json
import sys
import time
import uuid

import httpx
import pydicom

from ..common import crypto
from ..common.canon import b64e
from ..common.config import BROKER_URL, DATA_URL, SELF_TOKEN, bearer
from .deid import Quarantined, deidentify

SERVICE = "hospital-gateway"


def upload_bytes(dicom_bytes: bytes) -> dict:
    timings = {}
    t = time.perf_counter()
    ds = pydicom.dcmread(io.BytesIO(dicom_bytes))
    ds, pseudo = deidentify(ds)
    out = io.BytesIO()
    ds.save_as(out, enforce_file_format=True)
    clean = out.getvalue()
    timings["deidentify_ms"] = (time.perf_counter() - t) * 1000

    object_id = str(uuid.uuid4())
    t = time.perf_counter()
    dek = crypto.new_key()
    ciphertext = crypto.seal(dek, clean, object_id.encode())
    timings["encrypt_ms"] = (time.perf_counter() - t) * 1000

    t = time.perf_counter()
    wrapped = httpx.post(f"{BROKER_URL}/wrap", headers=bearer(SELF_TOKEN[SERVICE]), timeout=10,
                         json={"patient_ref": pseudo, "object_id": object_id, "dek": b64e(dek)})
    wrapped.raise_for_status()
    timings["wrap_ms"] = (time.perf_counter() - t) * 1000
    del dek  # the plaintext data key never leaves the hospital

    t = time.perf_counter()
    stored = httpx.put(
        f"{DATA_URL}/objects/{object_id}",
        content=ciphertext,
        headers={**bearer(SELF_TOKEN[SERVICE]), "X-Patient-Ref": pseudo,
                 "X-Wrapped-Dek": wrapped.json()["wrapped_dek"]},
        timeout=30,
    )
    stored.raise_for_status()
    timings["upload_ms"] = (time.perf_counter() - t) * 1000
    return {"object_id": object_id, "patient_ref": pseudo, "bytes": len(ciphertext),
            "timings_ms": {k: round(v, 2) for k, v in timings.items()}}


def main(argv=None):
    parser = argparse.ArgumentParser(description="NEXUS hospital gateway")
    sub = parser.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("upload", help="de-identify, encrypt and upload a DICOM file")
    up.add_argument("files", nargs="+")
    args = parser.parse_args(argv)

    for path in args.files:
        try:
            with open(path, "rb") as fh:
                print(json.dumps({"file": path, **upload_bytes(fh.read())}))
        except Quarantined as exc:
            print(json.dumps({"file": path, "quarantined": str(exc)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
