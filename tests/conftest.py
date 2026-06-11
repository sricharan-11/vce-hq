"""Shared test fixtures."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

import sqlite_vec

from vce_hq.db.migrations import run_migrations


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Provide a temporary database file path."""
    return tmp_path / "test.db"


@pytest.fixture
def db_connection(tmp_db_path: Path) -> sqlite3.Connection:
    """Provide a fully initialized test database connection.

    Includes sqlite-vec extension and all migrations applied.
    """
    conn = sqlite3.connect(str(tmp_db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.enable_load_extension(False)

    run_migrations(conn)

    yield conn
    conn.close()
