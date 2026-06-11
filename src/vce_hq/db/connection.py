"""SQLite connection factory with sqlite-vec extension support.

Every tenant gets its own SQLite file. Connections are created on demand
and load the sqlite-vec extension for vector similarity search.

Security notes:
    - WAL mode is enabled for concurrent read/write safety.
    - Foreign keys are enforced.
    - The sqlite-vec extension is loaded at connection time.
"""

import sqlite3
from pathlib import Path

import sqlite_vec

from vce_hq.db.migrations import run_migrations


def create_connection(db_path: Path) -> sqlite3.Connection:
    """Create a configured SQLite connection with sqlite-vec loaded.

    Args:
        db_path: Absolute path to the tenant's SQLite database file.

    Returns:
        A fully initialized ``sqlite3.Connection`` with:
        - WAL journal mode (concurrent reads during writes)
        - Foreign key enforcement
        - sqlite-vec extension loaded
        - Schema migrations applied
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Harden the connection
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")

    # Load sqlite-vec extension
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.enable_load_extension(False)

    # Ensure schema is up to date
    run_migrations(conn)

    return conn
