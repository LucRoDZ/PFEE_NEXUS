"""SQLite access that is safe under concurrent requests.

FastAPI runs synchronous endpoints in a thread pool. Sharing one sqlite3
connection between those threads can fail under load ("Recursive use of
cursors", "bad parameter or other API misuse"). Each thread therefore gets its
own connection, in WAL mode so readers never block the single writer.
"""
import sqlite3
import threading
from pathlib import Path


class ThreadLocalDB:
    def __init__(self, path: Path, schema: str):
        self.path = str(path)
        self._local = threading.local()
        init = sqlite3.connect(self.path, timeout=10)
        init.execute("PRAGMA journal_mode=WAL")
        init.executescript(schema)  # schema (and triggers) created once, at startup only
        init.commit()
        init.close()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=10000")
            self._local.conn = conn
        return conn

    def execute(self, sql: str, params=()):
        return self._conn().execute(sql, params)

    def commit(self):
        self._conn().commit()
