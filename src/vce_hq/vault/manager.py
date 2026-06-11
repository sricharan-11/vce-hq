"""Credential manager — encrypted credential storage for The Vault.

Security model:
    - Credentials are stored in TWO forms:
        1. SHA-256 hash (for fast verification without decryption)
        2. Fernet (AES-128-CBC + HMAC-SHA256) symmetric encryption of
           the plaintext — so the Cloud Engineer agent can retrieve the
           actual credential at runtime to authenticate CLI calls.
    - The Fernet key is derived from the platform secret + tenant ID
      using PBKDF2-HMAC-SHA256, ensuring per-tenant key isolation.
    - Plaintext is decrypted in memory only, never written to disk
      (except for temporary files managed by ``credential_resolver``).
    - Constant-time comparison is used for hash verification to prevent
      timing attacks.

v3+ migration path:
    This module will be replaced by a HashiCorp Vault integration
    for centralized, auditable credential lifecycle management.
"""

import base64
import hashlib
import hmac
import logging
import sqlite3

from vce_hq.config import settings
from vce_hq.db.models import StoredCredential

logger = logging.getLogger(__name__)


class CredentialManager:
    """Manages encrypted credential storage and retrieval.

    Args:
        conn: Tenant-scoped SQLite connection.
        tenant_id: The tenant these credentials belong to.
    """

    def __init__(self, conn: sqlite3.Connection, tenant_id: str) -> None:
        self._conn = conn
        self._tenant_id = tenant_id
        self._fernet_key = self._derive_fernet_key()

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    def store_credential(
        self,
        *,
        name: str,
        provider: str,
        credential_value: str,
    ) -> StoredCredential:
        """Hash, encrypt, and store a credential.

        The credential value is:
        - Hashed (SHA-256 + salt) for fast verification.
        - Encrypted (Fernet) for agent retrieval at runtime.

        Args:
            name: Human-readable label (e.g., "GCP Prod Read-Only").
            provider: Cloud provider identifier (e.g., "gcp", "aws").
            credential_value: The actual credential (API key, JSON, etc.).

        Returns:
            The stored credential record (hash + encrypted blob, no plaintext).

        Raises:
            sqlite3.IntegrityError: If a credential with the same name
                already exists for this tenant.
        """
        credential_hash = self._hash_credential(credential_value)
        credential_encrypted = self._encrypt(credential_value)

        credential = StoredCredential(
            tenant_id=self._tenant_id,
            name=name,
            provider=provider,
            credential_hash=credential_hash,
        )

        self._conn.execute(
            """
            INSERT INTO credentials
                (credential_id, tenant_id, name, provider,
                 credential_hash, credential_encrypted, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                credential.credential_id,
                credential.tenant_id,
                credential.name,
                credential.provider,
                credential.credential_hash,
                credential_encrypted,
                credential.created_at.isoformat(),
            ),
        )
        self._conn.commit()

        logger.info(
            "Stored credential '%s' for tenant '%s' (provider: %s)",
            name, self._tenant_id, provider,
        )
        return credential

    def verify_credential(self, name: str, credential_value: str) -> bool:
        """Verify a credential value against the stored hash.

        Args:
            name: The credential name to look up.
            credential_value: The plaintext value to verify.

        Returns:
            ``True`` if the hash matches, ``False`` otherwise.
        """
        row = self._conn.execute(
            "SELECT credential_hash FROM credentials WHERE tenant_id = ? AND name = ?",
            (self._tenant_id, name),
        ).fetchone()

        if row is None:
            return False

        expected_hash = row["credential_hash"]
        actual_hash = self._hash_credential(credential_value)

        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected_hash, actual_hash)

    def get_plaintext(self, name: str) -> str | None:
        """Decrypt and return the plaintext credential value for agent use.

        This is called by the Cloud Engineer agent immediately before
        executing a CLI command. The returned value is used to construct
        environment variables (via ``credential_resolver``) and must not
        be logged or persisted.

        Args:
            name: The credential name to retrieve.

        Returns:
            Decrypted plaintext string, or ``None`` if not found or
            the credential was stored before encryption was introduced
            (hash-only legacy record).
        """
        row = self._conn.execute(
            "SELECT credential_encrypted FROM credentials "
            "WHERE tenant_id = ? AND name = ?",
            (self._tenant_id, name),
        ).fetchone()

        if row is None:
            logger.warning(
                "get_plaintext: credential '%s' not found for tenant '%s'",
                name, self._tenant_id,
            )
            return None

        encrypted = row["credential_encrypted"]
        if not encrypted:
            logger.warning(
                "get_plaintext: credential '%s' has no encrypted value "
                "(was stored before encryption support was added)",
                name,
            )
            return None

        return self._decrypt(encrypted)

    def list_credentials(self) -> list[StoredCredential]:
        """List all credentials for this tenant (metadata only, never plaintext).

        Returns:
            List of stored credential records.
        """
        rows = self._conn.execute(
            """
            SELECT credential_id, tenant_id, name, provider,
                   credential_hash, created_at, last_rotated
            FROM credentials
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            """,
            (self._tenant_id,),
        ).fetchall()

        return [
            StoredCredential(
                credential_id=row["credential_id"],
                tenant_id=row["tenant_id"],
                name=row["name"],
                provider=row["provider"],
                credential_hash=row["credential_hash"],
                created_at=row["created_at"],
                last_rotated=row["last_rotated"],
            )
            for row in rows
        ]

    def list_credentials_with_plaintext(self) -> list[dict]:
        """Retrieve all credentials WITH decrypted values for agent use.

        Returns a list of dicts suitable for ``credential_resolver``.
        Credentials missing an encrypted value are silently skipped.

        Returns:
            List of dicts: ``{name, provider, credential_value}``.
        """
        rows = self._conn.execute(
            """
            SELECT name, provider, credential_encrypted
            FROM credentials
            WHERE tenant_id = ? AND credential_encrypted IS NOT NULL
            ORDER BY created_at DESC
            """,
            (self._tenant_id,),
        ).fetchall()

        logger.info(
            "CredentialManager: list_with_plaintext found %d potential credentials for tenant %s",
            len(rows), self._tenant_id
        )
        result: list[dict] = []
        for row in rows:
            try:
                plaintext = self._decrypt(row["credential_encrypted"])
                result.append({
                    "name": row["name"],
                    "provider": row["provider"],
                    "credential_value": plaintext,
                })
            except Exception as exc:
                logger.error(
                    "Failed to decrypt credential '%s': %s", row["name"], exc
                )
        return result

    def delete_credential(self, name: str) -> bool:
        """Delete a credential by name.

        Args:
            name: The credential name to delete.

        Returns:
            ``True`` if a credential was deleted, ``False`` if not found.
        """
        cursor = self._conn.execute(
            "DELETE FROM credentials WHERE tenant_id = ? AND name = ?",
            (self._tenant_id, name),
        )
        self._conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info("Deleted credential '%s' for tenant '%s'", name, self._tenant_id)
        return deleted

    def rotate_credential(self, name: str, new_value: str) -> bool:
        """Rotate a credential's value (re-hash and re-encrypt).

        Args:
            name: The credential name to rotate.
            new_value: The new credential value.

        Returns:
            ``True`` if rotated successfully, ``False`` if not found.
        """
        new_hash = self._hash_credential(new_value)
        new_encrypted = self._encrypt(new_value)

        cursor = self._conn.execute(
            """
            UPDATE credentials
            SET credential_hash = ?,
                credential_encrypted = ?,
                last_rotated = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            WHERE tenant_id = ? AND name = ?
            """,
            (new_hash, new_encrypted, self._tenant_id, name),
        )
        self._conn.commit()
        rotated = cursor.rowcount > 0
        if rotated:
            logger.info("Rotated credential '%s' for tenant '%s'", name, self._tenant_id)
        return rotated

    # ──────────────────────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────────────────────

    def _derive_fernet_key(self) -> bytes:
        """Derive a per-tenant Fernet-compatible 32-byte key.

        Uses PBKDF2-HMAC-SHA256 with the platform secret as the password
        and the tenant ID as the salt, producing a URL-safe base64-encoded
        key suitable for ``cryptography.fernet.Fernet``.

        Returns:
            32-byte key encoded as URL-safe base64 (44 bytes total).
        """
        password = settings.credential_secret.encode("utf-8")
        salt = self._tenant_id.encode("utf-8")
        raw = hashlib.pbkdf2_hmac("sha256", password, salt, iterations=100_000, dklen=32)
        return base64.urlsafe_b64encode(raw)

    def _encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string using Fernet (AES-128-CBC + HMAC).

        Args:
            plaintext: The credential value to encrypt.

        Returns:
            URL-safe base64-encoded ciphertext string.
        """
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError(
                "The 'cryptography' package is required for credential encryption. "
                "Install it with: pip install cryptography"
            )
        f = Fernet(self._fernet_key)
        return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def _decrypt(self, ciphertext: str) -> str:
        """Decrypt a Fernet-encrypted ciphertext string.

        Args:
            ciphertext: URL-safe base64-encoded ciphertext.

        Returns:
            Decrypted plaintext string.

        Raises:
            cryptography.fernet.InvalidToken: If decryption fails (wrong key
                or tampered ciphertext).
        """
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError(
                "The 'cryptography' package is required for credential encryption."
            )
        f = Fernet(self._fernet_key)
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")

    def _hash_credential(self, credential_value: str) -> str:
        """Generate a salted SHA-256 hash of a credential value.

        Used for fast verification without decryption.

        Args:
            credential_value: The plaintext credential to hash.

        Returns:
            Hex-encoded SHA-256 hash.
        """
        salt = f"{settings.credential_secret}:{self._tenant_id}".encode("utf-8")
        return hashlib.sha256(salt + credential_value.encode("utf-8")).hexdigest()
