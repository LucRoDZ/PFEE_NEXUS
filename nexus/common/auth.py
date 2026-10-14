"""Minimal bearer-token authentication for the PoC (Keycloak/OIDC in the target)."""
import json
from typing import Optional

from fastapi import Header, HTTPException

from .config import DATA_DIR, TOKENS

# Accounts disabled by incident response. In the target architecture this is the
# account switch in Keycloak, the central identity provider; here a shared file plays it.
DISABLED = DATA_DIR / "idp" / "disabled_accounts.json"
_cache = {"mtime": None, "actors": frozenset()}


def disabled_actors() -> frozenset:
    try:
        mtime = DISABLED.stat().st_mtime_ns
    except FileNotFoundError:
        return frozenset()
    if mtime != _cache["mtime"]:
        try:
            _cache["actors"] = frozenset(json.loads(DISABLED.read_text()))
            _cache["mtime"] = mtime
        except (OSError, ValueError):
            pass
    return _cache["actors"]


def disable_actor(actor: str) -> None:
    DISABLED.parent.mkdir(parents=True, exist_ok=True)
    actors = set(disabled_actors()) | {actor}
    tmp = DISABLED.with_suffix(".tmp")
    tmp.write_text(json.dumps(sorted(actors)))
    tmp.replace(DISABLED)


def token_from_header(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return authorization.removeprefix("Bearer ").strip()


def require_actor(authorization: Optional[str] = Header(default=None)) -> str:
    actor = TOKENS.get(token_from_header(authorization))
    if actor is None:
        raise HTTPException(status_code=401, detail="unknown token")
    if actor in disabled_actors():
        raise HTTPException(status_code=401, detail="account disabled")
    return actor


def require_one_of(*allowed: str):
    def dependency(authorization: Optional[str] = Header(default=None)) -> str:
        actor = require_actor(authorization)
        if actor not in allowed:
            raise HTTPException(status_code=403, detail=f"{actor} is not allowed here")
        return actor

    return dependency
