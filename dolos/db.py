"""SQLite state with parameterized queries and strict object ownership."""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from .security import hash_password
from .native import validate_event_tag

DB_PATH = Path(os.getenv('DOLOS_DB', 'instance/dolos.sqlite3'))


@contextmanager
def connect(path=None):
    path = str(path if path is not None else DB_PATH)
    if path != ':memory:':
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        with db:
            yield db
    finally:
        db.close()


def init(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','analyst'))
    );
    CREATE TABLE IF NOT EXISTS sessions(
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        csrf TEXT NOT NULL,
        expires INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS decoys(
        id INTEGER PRIMARY KEY,
        owner_id INTEGER NOT NULL REFERENCES users(id),
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))
    );
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY,
        owner_id INTEGER NOT NULL REFERENCES users(id),
        decoy_id INTEGER NOT NULL REFERENCES decoys(id),
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        peer TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_events_owner ON events(owner_id,created_at);
    ''')
    db.commit()


def create_user(db, username, password, role='analyst'):
    cur = db.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',
                     (username, hash_password(password), role))
    db.commit()
    return cur.lastrowid


def create_decoy(db, owner_id, name):
    cur = db.execute('INSERT INTO decoys(owner_id,name) VALUES(?,?)', (owner_id, name))
    db.commit()
    return cur.lastrowid


def create_event(db, owner_id, decoy_id, kind, value, peer='127.0.0.1'):
    validate_event_tag(kind)
    cur = db.execute('INSERT INTO events(owner_id,decoy_id,kind,value,peer) VALUES(?,?,?,?,?)',
                     (owner_id,decoy_id,kind,value,peer))
    db.commit()
    return cur.lastrowid
