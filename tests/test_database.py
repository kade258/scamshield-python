import json
import sqlite3

from app import database


def test_sender_checks_are_saved_and_legacy_database_is_migrated(tmp_path, monkeypatch):
    database_file = tmp_path / "scans.db"
    monkeypatch.setenv("SCAMSHIELD_DATABASE", str(database_file))
    with sqlite3.connect(database_file) as connection:
        connection.execute(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                kind TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                summary TEXT NOT NULL,
                findings TEXT NOT NULL,
                links TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            INSERT INTO scans (content, kind, score, level, summary, findings, links)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("Older scan content", "Message", 0, "Low risk", "No signals.", "[]", "[]"),
        )

    database.initialize_database()
    legacy_scan = database.recent_scans()[0]
    assert legacy_scan["senderChecks"] == []

    sender_checks = [
        {
            "email": "jordan@example.com",
            "domain": "example.com",
            "status": "caution",
            "note": "Verify this address independently.",
        }
    ]
    saved_scan = database.save_scan(
        "A new message containing a sender header.",
        {
            "kind": "Email",
            "score": 0,
            "level": "Low risk",
            "summary": "No signals.",
            "findings": [],
            "links": [],
            "senderChecks": sender_checks,
        },
    )
    assert saved_scan["senderChecks"] == sender_checks

    with sqlite3.connect(database_file) as connection:
        stored = connection.execute(
            "SELECT sender_checks FROM scans WHERE id = ?", (saved_scan["id"],)
        ).fetchone()
    assert json.loads(stored[0]) == sender_checks
