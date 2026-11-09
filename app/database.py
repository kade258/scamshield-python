"""SQLite persistence for scan history."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

DEFAULT_DATABASE = Path(__file__).resolve().parent.parent / "scamshield.db"


def database_path() -> Path:
    return Path(os.getenv("SCAMSHIELD_DATABASE", DEFAULT_DATABASE))


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(database_path())
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with closing(connect()) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                kind TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                summary TEXT NOT NULL,
                findings TEXT NOT NULL,
                links TEXT NOT NULL,
                sender_checks TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(scans)").fetchall()
        }
        if "sender_checks" not in columns:
            connection.execute(
                "ALTER TABLE scans ADD COLUMN sender_checks TEXT NOT NULL DEFAULT '[]'"
            )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)"
        )
        connection.commit()


def save_scan(content: str, result: dict) -> dict:
    with closing(connect()) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (content, kind, score, level, summary, findings, links, sender_checks)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                content,
                result["kind"],
                result["score"],
                result["level"],
                result["summary"],
                json.dumps(result["findings"]),
                json.dumps(result["links"]),
                json.dumps(result.get("senderChecks", [])),
            ),
        )
        connection.commit()
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return _serialize(row)


def recent_scans(limit: int = 20) -> list[dict]:
    with closing(connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_serialize(row) for row in rows]


def _serialize(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "content": row["content"],
        "kind": row["kind"],
        "score": row["score"],
        "level": row["level"],
        "summary": row["summary"],
        "findings": json.loads(row["findings"]),
        "links": json.loads(row["links"]),
        "senderChecks": json.loads(row["sender_checks"]),
        "createdAt": row["created_at"],
    }
