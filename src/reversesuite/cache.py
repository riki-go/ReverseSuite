"""Content-addressed artifact cache (AC-13).

Key = sha256(input file) + schema_version + engine_build_id + params_hash.
Artifacts live under <cache>/artifacts/<sha256>, indexed in SQLite (WAL).
Writes are atomic (temp file + rename); reads verify the sha256 before use.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .version import ENGINE_BUILD_ID, SCHEMA_VERSION


def params_hash(**params) -> str:
    payload = json.dumps(params, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def make_key(file_sha256: str, **params) -> str:
    raw = "|".join([SCHEMA_VERSION, ENGINE_BUILD_ID, file_sha256, params_hash(**params)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Cache:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "index.sqlite"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _conn(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS artifacts ("
                " key TEXT PRIMARY KEY, sha256 TEXT NOT NULL, rel_path TEXT NOT NULL,"
                " bytes INTEGER NOT NULL, meta TEXT NOT NULL, created_at TEXT NOT NULL)"
            )

    def get(self, key: str) -> Optional[Path]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT sha256, rel_path, bytes FROM artifacts WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        expected, rel_path, size = row
        path = self.root / rel_path
        if not path.exists() or path.stat().st_size != size:
            return None
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            return None
        return path

    def put(self, key: str, source: Path, meta: Optional[dict] = None) -> str:
        data = Path(source).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        rel = Path("artifacts") / digest
        final = self.root / rel
        if not final.exists():
            fd, tmp_name = tempfile.mkstemp(dir=str(self.artifacts), suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, final)
            finally:
                if os.path.exists(tmp_name):
                    os.remove(tmp_name)
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO artifacts (key, sha256, rel_path, bytes, meta, created_at)"
                " VALUES (?, ?, ?, ?, ?, datetime('now'))",
                (key, digest, str(rel), len(data), json.dumps(meta or {}, sort_keys=True)),
            )
        return digest

    def stats(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute("SELECT COUNT(*), COALESCE(SUM(bytes),0) FROM artifacts").fetchone()
        return {"entries": rows[0], "bytes": rows[1], "root": str(self.root)}
