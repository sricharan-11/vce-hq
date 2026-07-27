"""Long-Term Memory (LTM) data access layer.

Manages vector-indexed knowledge chunks and incident resolutions.
All vector operations go through sqlite-vec virtual tables. The
embedding step is NOT done here — callers must provide pre-computed
embedding vectors.

Design rationale:
    Separating embedding from storage keeps this layer pure (no API calls),
    making it fast, testable, and free of side effects.
"""

import json
import sqlite3
import struct

from vce_hq.config import settings
from vce_hq.db.models import (
    IncidentResolution,
    KnowledgeChunk,
    VectorSearchResult,
)


def _serialize_vector(vector: list[float]) -> bytes:
    """Serialize a float list into the binary format sqlite-vec expects.

    sqlite-vec requires vectors as packed little-endian 32-bit floats.

    Args:
        vector: A list of floats (must match configured dimensions).

    Returns:
        Packed binary representation of the vector.

    Raises:
        ValueError: If vector length doesn't match configured dimensions.
    """
    if len(vector) != settings.embedding_dimensions:
        raise ValueError(
            f"Expected {settings.embedding_dimensions}-dim vector, "
            f"got {len(vector)}-dim"
        )
    return struct.pack(f"<{len(vector)}f", *vector)


class LongTermMemory:
    """Vector-indexed storage for knowledge and incident resolutions.

    Args:
        conn: An open SQLite connection for a specific tenant
              with sqlite-vec loaded.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # ── Knowledge Chunks ──────────────────────────────────────

    def store_knowledge_chunk(
        self, chunk: KnowledgeChunk, embedding: list[float]
    ) -> KnowledgeChunk:
        """Store a knowledge chunk with its embedding vector.

        This is an atomic operation — both the metadata row and the
        vector row are inserted in a single transaction.

        Args:
            chunk: The knowledge chunk metadata.
            embedding: Pre-computed embedding vector.

        Returns:
            The same chunk object (now persisted).
        """
        vector_bytes = _serialize_vector(embedding)

        self._conn.execute(
            """
            INSERT OR REPLACE INTO knowledge_chunks
                (chunk_id, tenant_id, category, source_document, content, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                chunk.chunk_id,
                chunk.tenant_id,
                chunk.category.value,
                chunk.source_document,
                chunk.content,
                json.dumps(chunk.metadata),
                chunk.created_at.isoformat(),
            ),
        )
        self._conn.execute(
            """
            INSERT OR REPLACE INTO knowledge_vectors (chunk_id, embedding)
            VALUES (?, ?)
            """,
            (chunk.chunk_id, vector_bytes),
        )
        self._conn.commit()
        return chunk

    def list_knowledge_documents(self) -> list[dict]:
        """List all unique documents currently stored in LTM."""
        rows = self._conn.execute(
            """
            SELECT 
                source_document as document_name, 
                category,
                COUNT(*) as chunks,
                MIN(created_at) as created_at
            FROM knowledge_chunks
            GROUP BY source_document, category
            ORDER BY created_at DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def search_knowledge(
        self,
        query_embedding: list[float],
        *,
        top_k: int = 5,
        category: str | None = None,
    ) -> list[VectorSearchResult]:
        """Semantic similarity search over knowledge chunks.

        Args:
            query_embedding: The query vector to match against.
            top_k: Number of results to return.
            category: If provided, filter to chunks of this category only.

        Returns:
            List of search results ordered by similarity (closest first).
        """
        query_bytes = _serialize_vector(query_embedding)

        # sqlite-vec returns (chunk_id, distance) from the virtual table.
        # We join with the metadata table to get the full content.
        if category:
            rows = self._conn.execute(
                """
                SELECT
                    kc.chunk_id,
                    kc.content,
                    kc.category,
                    kc.source_document,
                    kc.metadata_json,
                    kv.distance
                FROM knowledge_vectors kv
                JOIN knowledge_chunks kc ON kc.chunk_id = kv.chunk_id
                WHERE kv.embedding MATCH ? AND k = ?
                    AND kc.category = ?
                ORDER BY kv.distance ASC
                """,
                (query_bytes, top_k, category),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT
                    kc.chunk_id,
                    kc.content,
                    kc.category,
                    kc.source_document,
                    kc.metadata_json,
                    kv.distance
                FROM knowledge_vectors kv
                JOIN knowledge_chunks kc ON kc.chunk_id = kv.chunk_id
                WHERE kv.embedding MATCH ? AND k = ?
                ORDER BY kv.distance ASC
                """,
                (query_bytes, top_k),
            ).fetchall()

        return [
            VectorSearchResult(
                chunk_id=row["chunk_id"],
                content=row["content"],
                category=row["category"],
                source_document=row["source_document"],
                distance=row["distance"],
                metadata=json.loads(row["metadata_json"]) if row["metadata_json"] else {},
            )
            for row in rows
        ]

    def delete_knowledge_by_document(self, source_document: str) -> int:
        """Delete all chunks (and their vectors) for a given source document.

        Useful for re-ingestion: delete old chunks, then re-ingest.

        Args:
            source_document: The document identifier to purge.

        Returns:
            Number of chunks deleted.
        """
        # Get chunk IDs first, then delete from both tables.
        chunk_ids = self._conn.execute(
            "SELECT chunk_id FROM knowledge_chunks WHERE source_document = ?",
            (source_document,),
        ).fetchall()

        if not chunk_ids:
            return 0

        ids = [row["chunk_id"] for row in chunk_ids]
        placeholders = ", ".join("?" for _ in ids)

        self._conn.execute(
            f"DELETE FROM knowledge_vectors WHERE chunk_id IN ({placeholders})",
            ids,
        )
        self._conn.execute(
            f"DELETE FROM knowledge_chunks WHERE chunk_id IN ({placeholders})",
            ids,
        )
        self._conn.commit()
        return len(ids)

    # ── Incident Resolutions ──────────────────────────────────

    def store_resolution(
        self, resolution: IncidentResolution, embedding: list[float]
    ) -> IncidentResolution:
        """Store an incident resolution with its embedding vector.

        Args:
            resolution: The resolution metadata.
            embedding: Pre-computed embedding vector of the resolution text.

        Returns:
            The same resolution object (now persisted).
        """
        vector_bytes = _serialize_vector(embedding)

        self._conn.execute(
            """
            INSERT OR REPLACE INTO incident_resolutions
                (resolution_id, tenant_id, session_id, title, root_cause,
                 remediation, agent_used, severity, tags_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resolution.resolution_id,
                resolution.tenant_id,
                resolution.session_id,
                resolution.title,
                resolution.root_cause,
                resolution.remediation,
                resolution.agent_used.value,
                resolution.severity.value,
                json.dumps(resolution.tags),
                resolution.created_at.isoformat(),
            ),
        )
        self._conn.execute(
            """
            INSERT OR REPLACE INTO resolution_vectors (resolution_id, embedding)
            VALUES (?, ?)
            """,
            (resolution.resolution_id, vector_bytes),
        )
        self._conn.commit()
        return resolution

    def search_resolutions(
        self,
        query_embedding: list[float],
        *,
        top_k: int = 5,
    ) -> list[VectorSearchResult]:
        """Semantic similarity search over past incident resolutions.

        Args:
            query_embedding: The query vector to match against.
            top_k: Number of results to return.

        Returns:
            List of search results ordered by similarity (closest first).
        """
        query_bytes = _serialize_vector(query_embedding)

        rows = self._conn.execute(
            """
            SELECT
                ir.resolution_id AS chunk_id,
                (ir.title || '\n\nRoot Cause: ' || ir.root_cause
                 || '\n\nRemediation: ' || ir.remediation) AS content,
                'incident_resolution' AS category,
                ir.session_id AS source_document,
                ir.tags_json AS metadata_json,
                rv.distance
            FROM resolution_vectors rv
            JOIN incident_resolutions ir ON ir.resolution_id = rv.resolution_id
            WHERE rv.embedding MATCH ? AND k = ?
            ORDER BY rv.distance ASC
            """,
            (query_bytes, top_k),
        ).fetchall()

        return [
            VectorSearchResult(
                chunk_id=row["chunk_id"],
                content=row["content"],
                category=row["category"],
                source_document=row["source_document"],
                distance=row["distance"],
                metadata={"tags": json.loads(row["metadata_json"])} if row["metadata_json"] else {},
            )
            for row in rows
        ]
