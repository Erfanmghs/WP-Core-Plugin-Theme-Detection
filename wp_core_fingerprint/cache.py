"""SQLite cache for GitHub tags and reference asset hashes (speed + offline reuse)."""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path(os.environ.get("WP_FINGERPRINT_CACHE", Path.home() / ".cache" / "wp-core-fingerprint"))
TAGS_TTL_S = 86400  # 24h
ASSET_TTL_S = 604800  # 7d


class AssetCache:
    """Thread-safe SQLite cache for GitHub tag lists and raw asset bytes."""

    def __init__(self, cache_dir: Path | None = None, enabled: bool = True) -> None:
        self.enabled = enabled
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self.stats: dict[str, int] = {"hits": 0, "misses": 0, "writes": 0}
        if enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.cache_dir / "reference.db"), check_same_thread=False)
            self._init_schema()

    def _init_schema(self) -> None:
        assert self._conn is not None
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS tags (
                name TEXT PRIMARY KEY,
                fetched_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tag_list (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                tags_json TEXT NOT NULL,
                fetched_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assets (
                tag TEXT NOT NULL,
                path TEXT NOT NULL,
                md5 TEXT NOT NULL,
                size INTEGER NOT NULL,
                data BLOB NOT NULL,
                fetched_at REAL NOT NULL,
                PRIMARY KEY (tag, path)
            );
            CREATE INDEX IF NOT EXISTS idx_assets_tag ON assets(tag);
            """
        )
        self._conn.commit()

    def get_tag_list(self) -> list[str] | None:
        if not self.enabled or not self._conn:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT tags_json, fetched_at FROM tag_list WHERE id = 1"
            ).fetchone()
            if not row:
                self.stats["misses"] += 1
                return None
            tags_json, fetched_at = row
            if time.time() - fetched_at > TAGS_TTL_S:
                self.stats["misses"] += 1
                return None
            import json

            self.stats["hits"] += 1
            return json.loads(tags_json)

    def put_tag_list(self, tags: list[str]) -> None:
        if not self.enabled or not self._conn:
            return
        import json

        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO tag_list (id, tags_json, fetched_at) VALUES (1, ?, ?)",
                (json.dumps(tags), time.time()),
            )
            self._conn.commit()
            self.stats["writes"] += 1

    def get_asset(self, tag: str, path: str) -> bytes | None:
        if not self.enabled or not self._conn:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT data, fetched_at FROM assets WHERE tag = ? AND path = ?",
                (tag, path),
            ).fetchone()
            if not row:
                self.stats["misses"] += 1
                return None
            data, fetched_at = row
            if time.time() - fetched_at > ASSET_TTL_S:
                self.stats["misses"] += 1
                return None
            self.stats["hits"] += 1
            return data

    def put_asset(self, tag: str, path: str, data: bytes) -> None:
        if not self.enabled or not self._conn or not data:
            return
        md5 = hashlib.md5(data).hexdigest()
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO assets (tag, path, md5, size, data, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (tag, path, md5, len(data), data, time.time()),
            )
            self._conn.commit()
            self.stats["writes"] += 1

    def prefetch_assets(self, tag: str, paths: list[str], http_get: Any) -> int:
        """Background-friendly batch fetch missing paths for one tag."""
        fetched = 0
        for path in paths:
            if self.get_asset(tag, path) is not None:
                continue
            url = f"https://raw.githubusercontent.com/WordPress/WordPress/{tag}/{path}"
            status, body, _, err = http_get(url)
            if status == 200 and body and not err:
                self.put_asset(tag, path, body)
                fetched += 1
        return fetched

    def to_dict(self) -> dict[str, Any]:
        return dict(self.stats)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
