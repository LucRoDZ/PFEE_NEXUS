"""Hash-chain rules shared by the audit service and its verifiers (no side effects)."""
from ..common.canon import canon, sha256_hex

GENESIS = "0" * 64
FIELDS = ("seq", "ts", "source", "actor", "action", "decision", "patient_ref", "object_id", "detail")


def entry_hash(prev_hash: str, fields: dict) -> str:
    """hash_n = SHA-256(hash_(n-1) || canonical JSON of entry n)."""
    return sha256_hex(prev_hash.encode() + canon(fields))
