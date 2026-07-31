"""Database schema migrations.

Migrations are idempotent (CREATE IF NOT EXISTS) and run on every
connection open. This ensures the schema is always up-to-date without
requiring a separate migration tool for v1.

Tables:
    - sessions: Short-term memory — active analysis sessions.
    - conversation_turns: Short-term memory — agent conversation history.
    - command_executions: Short-term memory — command execution audit log.
    - knowledge_chunks: Long-term memory metadata for vector-indexed docs.
    - knowledge_vectors: sqlite-vec virtual table for similarity search.
    - incident_resolutions: Long-term memory — completed incident analyses.
    - resolution_vectors: sqlite-vec virtual table for resolution search.
    - credentials: Encrypted credential storage (The Vault).
"""

import sqlite3

from vce_hq.config import settings

# Embedding dimensions from config — used to size vector columns.
_DIMS = settings.embedding_dimensions


def run_migrations(conn: sqlite3.Connection) -> None:
    """Apply all schema migrations idempotently.

    Args:
        conn: An open SQLite connection with sqlite-vec loaded.
    """
    _create_stm_tables(conn)
    _create_ltm_tables(conn)
    _create_vault_tables(conn)
    _create_auth_tables(conn)
    
    # Retroactive migrations for v1.x -> v1.y
    _retroactive_migrations(conn)
    
    conn.commit()


def _create_auth_tables(conn: sqlite3.Connection) -> None:
    """Create Authentication and User Management tables."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id               TEXT PRIMARY KEY,
            username         TEXT UNIQUE NOT NULL,
            password_hash    TEXT NOT NULL,
            role             TEXT NOT NULL DEFAULT 'user',
            created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
    """)

    # Check if we need to seed the default admin
    admin_exists = conn.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone()
    if not admin_exists:
        import uuid
        from vce_hq.auth.security import get_password_hash
        admin_id = str(uuid.uuid4())
        hashed_pw = get_password_hash(settings.admin_password)
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
            (admin_id, "admin", hashed_pw, "admin")
        )


def _retroactive_migrations(conn: sqlite3.Connection) -> None:
    """Safely apply ALTER TABLE patches to existing DBs."""
    def add_col(table: str, col: str, col_type: str) -> None:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e).lower():
                raise
                
    add_col("conversation_turns", "request_id", "TEXT")
    add_col("command_executions", "request_id", "TEXT")
    add_col("token_usage", "request_id", "TEXT")
    # Blocklist audit trail (PRD §8)
    add_col("command_executions", "risk_signal", "TEXT DEFAULT 'none'")
    add_col("command_executions", "gate_invoked", "INTEGER DEFAULT 0")
    add_col("command_executions", "gate_decision", "TEXT DEFAULT ''")
    # GCP OAuth users (PRD §7.5)
    add_col("users", "auth_method", "TEXT NOT NULL DEFAULT 'password'")
    add_col("users", "email", "TEXT")
    add_col("users", "google_sub", "TEXT")
    add_col("users", "last_role_sync_at", "TEXT")
    # Best-effort uniqueness on google_sub (ignore if index exists).
    try:
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub "
            "ON users(google_sub) WHERE google_sub IS NOT NULL"
        )
    except sqlite3.OperationalError:
        pass


def _create_stm_tables(conn: sqlite3.Connection) -> None:
    """Create short-term memory tables."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            event_json   TEXT,  -- Serialized NormalizedEvent JSON
            created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_tenant
            ON sessions(tenant_id);

        CREATE INDEX IF NOT EXISTS idx_sessions_status
            ON sessions(status);

        CREATE TABLE IF NOT EXISTS conversation_turns (
            turn_id      TEXT PRIMARY KEY,
            session_id   TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            request_id   TEXT,
            agent        TEXT NOT NULL,
            content      TEXT NOT NULL,
            created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_turns_session
            ON conversation_turns(session_id);

        CREATE TABLE IF NOT EXISTS command_executions (
            command_id       TEXT PRIMARY KEY,
            session_id       TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            request_id       TEXT,
            agent            TEXT NOT NULL,
            command          TEXT NOT NULL,
            reasoning        TEXT NOT NULL,
            exit_code        INTEGER,
            stdout           TEXT,
            stderr           TEXT,
            duration_ms      INTEGER,
            validated_by     TEXT NOT NULL,
            truncated        INTEGER DEFAULT 0,
            created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_cmd_exec_session
            ON command_executions(session_id);

        CREATE TABLE IF NOT EXISTS token_usage (
            usage_id         TEXT PRIMARY KEY,
            session_id       TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
            request_id       TEXT,
            tenant_id        TEXT NOT NULL,
            agent            TEXT NOT NULL,
            prompt_tokens    INTEGER NOT NULL,
            completion_tokens INTEGER NOT NULL,
            total_tokens     INTEGER NOT NULL,
            reasoning_tokens INTEGER NOT NULL DEFAULT 0,
            cache_read_tokens INTEGER NOT NULL DEFAULT 0,
            cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
            model_name       TEXT NOT NULL,
            created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_token_usage_session
            ON token_usage(session_id);
    """)

    # Conversation vectors — sqlite-vec virtual table for Semantic STM
    conn.execute(f"""
        CREATE VIRTUAL TABLE IF NOT EXISTS conversation_vectors
        USING vec0(
            turn_id TEXT PRIMARY KEY,
            embedding float[{_DIMS}]
        )
    """)


def _create_ltm_tables(conn: sqlite3.Connection) -> None:
    """Create long-term memory tables (metadata + vector indexes)."""
    # Knowledge chunks — metadata
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS knowledge_chunks (
            chunk_id         TEXT PRIMARY KEY,
            tenant_id        TEXT NOT NULL,
            category         TEXT NOT NULL,
            source_document  TEXT NOT NULL,
            content          TEXT NOT NULL,
            metadata_json    TEXT DEFAULT '{}',
            created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_chunks_tenant
            ON knowledge_chunks(tenant_id);

        CREATE INDEX IF NOT EXISTS idx_chunks_category
            ON knowledge_chunks(category);
    """)

    # Knowledge vectors — sqlite-vec virtual table
    conn.execute(f"""
        CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_vectors
        USING vec0(
            chunk_id TEXT PRIMARY KEY,
            embedding float[{_DIMS}]
        )
    """)

    # Incident resolutions — metadata
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS incident_resolutions (
            resolution_id  TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL,
            session_id     TEXT NOT NULL,
            title          TEXT NOT NULL,
            root_cause     TEXT NOT NULL,
            remediation    TEXT NOT NULL,
            agent_used     TEXT NOT NULL,
            severity       TEXT NOT NULL,
            tags_json      TEXT DEFAULT '[]',
            created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_resolutions_tenant
            ON incident_resolutions(tenant_id);
    """)

    # Resolution vectors — sqlite-vec virtual table
    conn.execute(f"""
        CREATE VIRTUAL TABLE IF NOT EXISTS resolution_vectors
        USING vec0(
            resolution_id TEXT PRIMARY KEY,
            embedding float[{_DIMS}]
        )
    """)


def _create_vault_tables(conn: sqlite3.Connection) -> None:
    """Create credential vault tables."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS credentials (
            credential_id      TEXT PRIMARY KEY,
            tenant_id          TEXT NOT NULL,
            name               TEXT NOT NULL,
            provider           TEXT NOT NULL,
            credential_hash    TEXT NOT NULL,
            credential_encrypted TEXT,  -- Fernet-encrypted plaintext for agent use
            created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            last_rotated       TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_credentials_tenant
            ON credentials(tenant_id);

        -- Prevent duplicate credential names per tenant
        CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_tenant_name
            ON credentials(tenant_id, name);
    """)

    # Idempotent: add credential_encrypted column if it doesn't exist yet
    # (for databases created before this migration was introduced)
    try:
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN credential_encrypted TEXT"
        )
        conn.commit()
    except Exception:
        pass  # Column already exists
