"""Keep-alive HTTP clients for service-to-service calls (one per thread).

Opening a new TCP connection for every internal call adds latency and, under
load, exhausts sockets. Each worker thread reuses its own pooled client.
"""
import threading

import httpx

_local = threading.local()


def client() -> httpx.Client:
    c = getattr(_local, "client", None)
    if c is None:
        c = httpx.Client(timeout=10, limits=httpx.Limits(max_keepalive_connections=20, max_connections=50))
        _local.client = c
    return c
