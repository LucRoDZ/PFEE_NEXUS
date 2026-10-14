"""Cryptographic primitives.

- AES-256-GCM for data and key wrapping (envelope encryption).
- Ed25519 for patient signatures on consent grants, revocations and erasure requests.

The associated data (AAD) binds every ciphertext to its context, so a
ciphertext or wrapped key cannot be replayed under another object or patient.
"""
import os

from cryptography.exceptions import InvalidSignature, InvalidTag  # noqa: F401  (re-exported)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canon import b64d, b64e, canon

NONCE_BYTES = 12


def new_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)


# --- Ed25519 -----------------------------------------------------------------

def new_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_to_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def private_from_pem(data: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(data, password=None)


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64e(raw)


def public_from_b64(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64d(text))


def sign(key: Ed25519PrivateKey, payload: dict) -> dict:
    return {"payload": payload, "sig": b64e(key.sign(canon(payload)))}


def verify(public_b64_text: str, signed: dict) -> bool:
    try:
        public_from_b64(public_b64_text).verify(b64d(signed["sig"]), canon(signed["payload"]))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False
