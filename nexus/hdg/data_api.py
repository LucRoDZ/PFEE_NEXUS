"""HDG data API: stores and serves ciphertext only.

Objects arrive already encrypted by the hospital gateway, together with a data
key that is itself wrapped by the hospital key broker. HDG holds no key that can
open either of them. Storage is any S3-compatible backend (Garage in the target
deployment, an S3 emulator in local tests).
"""
from typing import Optional

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response

from ..common.audit_client import AuditUnavailable, log_event
from ..common.auth import require_actor, require_one_of
from ..common.config import S3_ACCESS_KEY, S3_BUCKET, S3_ENDPOINT, S3_REGION, S3_SECRET_KEY

SERVICE = "hdg-data-api"
app = FastAPI(title="NEXUS data API (HDG)")


def s3_client():
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        region_name=S3_REGION,
        config=Config(s3={"addressing_style": "path"}, signature_version="s3v4"),
    )


S3 = s3_client()


def audit(actor, action, decision, patient_ref=None, object_id=None, detail=None):
    try:
        log_event(SERVICE, actor, action, decision, patient_ref=patient_ref, object_id=object_id, detail=detail)
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail="audit unavailable: request refused (no log, no access)")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.put("/objects/{object_id}")
async def put_object(
    object_id: str,
    request: Request,
    x_patient_ref: str = Header(...),
    x_wrapped_dek: str = Header(...),
    actor: str = Depends(require_one_of("hospital-gateway")),
):
    body = await request.body()
    audit(actor, "object.store", "stored", patient_ref=x_patient_ref, object_id=object_id,
          detail=f"{len(body)} bytes of ciphertext")
    S3.put_object(
        Bucket=S3_BUCKET,
        Key=object_id,
        Body=body,
        Metadata={"patient-ref": x_patient_ref, "wrapped-dek": x_wrapped_dek},
    )
    return {"object_id": object_id, "bytes": len(body)}


@app.get("/objects")
def list_objects(patient_ref: Optional[str] = None, actor: str = Depends(require_actor)):
    keys = []
    paginator = S3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=S3_BUCKET):
        for item in page.get("Contents", []):
            keys.append(item["Key"])
    if patient_ref is None:
        return keys
    result = []
    for key in keys:
        meta = S3.head_object(Bucket=S3_BUCKET, Key=key)["Metadata"]
        if meta.get("patient-ref") == patient_ref:
            result.append(key)
    return result


@app.get("/objects/{object_id}")
def get_object(object_id: str, actor: str = Depends(require_actor)):
    try:
        obj = S3.get_object(Bucket=S3_BUCKET, Key=object_id)
    except ClientError:
        raise HTTPException(status_code=404, detail="no such object")
    meta = obj["Metadata"]
    audit(actor, "object.read", "served-ciphertext", patient_ref=meta.get("patient-ref"), object_id=object_id)
    return Response(
        content=obj["Body"].read(),
        media_type="application/octet-stream",
        headers={"X-Patient-Ref": meta.get("patient-ref", ""), "X-Wrapped-Dek": meta.get("wrapped-dek", "")},
    )
