"""G4 probe: can this container or pod send anything to the internet?

    python demo/egress_probe.py

Run inside an HDG container or pod. Pass = HTTPS and a direct TCP connection to
a public IP are both blocked. DNS is reported separately: on some setups the
resolver still answers names even when no packet can leave.
"""
import json
import socket
import sys

import httpx

result = {}
try:
    socket.getaddrinfo("example.com", 443)
    result["dns"] = "resolved"
except OSError as exc:
    result["dns"] = f"blocked ({type(exc).__name__})"
try:
    r = httpx.get("https://example.com", timeout=5)
    result["https"] = f"reached (HTTP {r.status_code})"
except httpx.HTTPError as exc:
    result["https"] = f"blocked ({type(exc).__name__})"
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5).close()
    result["tcp_1.1.1.1_443"] = "reached"
except OSError as exc:
    result["tcp_1.1.1.1_443"] = f"blocked ({type(exc).__name__})"
result["egress_blocked"] = result["https"].startswith("blocked") and result["tcp_1.1.1.1_443"].startswith("blocked")
print(json.dumps(result))
sys.exit(0 if result["egress_blocked"] else 1)
