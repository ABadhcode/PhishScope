import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "phishscope.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_type TEXT NOT NULL,
            target TEXT NOT NULL,
            subject TEXT,
            risk_score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            findings TEXT NOT NULL,
            notes TEXT DEFAULT '',
            status TEXT DEFAULT 'Open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
