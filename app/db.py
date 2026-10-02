import sqlite3
from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            subject TEXT,
            sender TEXT,
            recipient TEXT,
            score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            summary TEXT NOT NULL,
            indicators TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT ''
        );
        """
    )
    db.commit()
