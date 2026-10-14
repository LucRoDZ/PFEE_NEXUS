"""Canonical encoding helpers shared by every NEXUS component.

Signatures and hash chains are computed over a canonical JSON form so that
two parties always hash and sign exactly the same bytes.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(text)
