"""Client used by every service to write to the HDG audit chain.

Rule enforced by callers: no log, no access. If the audit service cannot record
a decision, the decision is a denial.
"""
from typing import Optional

import httpx

from .config import AUDIT_URL, SELF_TOKEN, bearer
from .http import client


class AuditUnavailable(RuntimeError):
    pass


def log_event(
    service: str,
    actor: str,
    action: str,
    decision: str,
    patient_ref: Optional[str] = None,
    object_id: Optional[str] = None,
    detail: Optional[str] = None,
) -> dict:
    event = {
        "actor": actor,
        "action": action,
        "decision": decision,
        "patient_ref": patient_ref,
        "object_id": object_id,
        "detail": detail,
        "source": service,
    }
    for attempt in (1, 2):  # one retry on a dropped connection; still fail closed after that
        try:
            response = client().post(f"{AUDIT_URL}/events", json=event, headers=bearer(SELF_TOKEN[service]))
            response.raise_for_status()
            return response.json()
        except httpx.TransportError as exc:
            if attempt == 2:
                raise AuditUnavailable(str(exc)) from exc
        except httpx.HTTPError as exc:
            raise AuditUnavailable(str(exc)) from exc
