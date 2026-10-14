"""Configuration read from environment variables, with defaults for a local run."""
import json
import os
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


AUDIT_URL = _env("NEXUS_AUDIT_URL", "http://127.0.0.1:8101")
CONSENT_URL = _env("NEXUS_CONSENT_URL", "http://127.0.0.1:8102")
DATA_URL = _env("NEXUS_DATA_URL", "http://127.0.0.1:8103")
BROKER_URL = _env("NEXUS_BROKER_URL", "http://127.0.0.1:8201")

S3_ENDPOINT = _env("NEXUS_S3_ENDPOINT", f"http://127.0.0.1:{_env('NEXUS_S3_PORT', '9000')}")
S3_BUCKET = _env("NEXUS_S3_BUCKET", "nexus-objects")
S3_ACCESS_KEY = _env("NEXUS_S3_ACCESS_KEY", "nexus-admin")
S3_SECRET_KEY = _env("NEXUS_S3_SECRET_KEY", "nexus-admin-secret")
S3_REGION = _env("NEXUS_S3_REGION", "garage")

DATA_DIR = Path(_env("NEXUS_DATA_DIR", "./var")).resolve()

# Static service and user tokens for the PoC. In the target architecture these
# are OIDC tokens issued by Keycloak (Pro Sante Connect for health professionals).
DEFAULT_TOKENS = {
    "tok-gateway": "hospital-gateway",
    "tok-broker": "hospital-keybroker",
    "tok-hospital-admin": "hospital-admin",
    "tok-anchor": "hospital-anchor",
    "tok-consent": "hdg-consent",
    "tok-data": "hdg-data-api",
    "tok-researcher": "dr-alice-research",
    "tok-researcher-2": "dr-bob-research",
    "tok-clinician": "dr-carol-clinician",
    "tok-detector": "hdg-detector",
}
TOKENS = json.loads(_env("NEXUS_TOKENS", json.dumps(DEFAULT_TOKENS)))

# Token each service uses when it calls another one.
SELF_TOKEN = {
    "hospital-gateway": "tok-gateway",
    "hospital-keybroker": "tok-broker",
    "hospital-admin": "tok-hospital-admin",
    "hospital-anchor": "tok-anchor",
    "hdg-consent": "tok-consent",
    "hdg-data-api": "tok-data",
}

PURPOSES = {"research", "ai-training", "second-opinion"}


def service_dir(name: str) -> Path:
    path = DATA_DIR / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
