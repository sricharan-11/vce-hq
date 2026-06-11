"""Tests for the credential vault."""

import sqlite3

import pytest

from vce_hq.vault.manager import CredentialManager


class TestCredentialManager:
    """Tests for hashed credential storage and verification."""

    def test_store_and_verify(self, db_connection: sqlite3.Connection) -> None:
        vault = CredentialManager(db_connection, "tenant-1")
        vault.store_credential(
            name="aws-prod",
            provider="aws",
            credential_value="AKIAIOSFODNN7EXAMPLE",
        )
        assert vault.verify_credential("aws-prod", "AKIAIOSFODNN7EXAMPLE") is True
        assert vault.verify_credential("aws-prod", "wrong-key") is False

    def test_verify_nonexistent(self, db_connection: sqlite3.Connection) -> None:
        vault = CredentialManager(db_connection, "tenant-1")
        assert vault.verify_credential("nonexistent", "any-value") is False

    def test_list_credentials(self, db_connection: sqlite3.Connection) -> None:
        vault = CredentialManager(db_connection, "tenant-1")
        vault.store_credential(name="key-1", provider="aws", credential_value="val-1")
        vault.store_credential(name="key-2", provider="gcp", credential_value="val-2")

        creds = vault.list_credentials()
        assert len(creds) == 2
        names = {c.name for c in creds}
        assert names == {"key-1", "key-2"}

    def test_delete_credential(self, db_connection: sqlite3.Connection) -> None:
        vault = CredentialManager(db_connection, "tenant-1")
        vault.store_credential(name="to-delete", provider="aws", credential_value="val")

        assert vault.delete_credential("to-delete") is True
        assert vault.delete_credential("to-delete") is False  # Already deleted
        assert vault.list_credentials() == []

    def test_rotate_credential(self, db_connection: sqlite3.Connection) -> None:
        vault = CredentialManager(db_connection, "tenant-1")
        vault.store_credential(name="key", provider="aws", credential_value="old-value")

        assert vault.rotate_credential("key", "new-value") is True
        assert vault.verify_credential("key", "old-value") is False
        assert vault.verify_credential("key", "new-value") is True

    def test_tenant_isolation(self, db_connection: sqlite3.Connection) -> None:
        """Same credential value produces different hashes for different tenants."""
        vault_a = CredentialManager(db_connection, "tenant-a")
        vault_b = CredentialManager(db_connection, "tenant-b")

        vault_a.store_credential(name="shared-key", provider="aws", credential_value="same-value")
        vault_b.store_credential(name="shared-key", provider="aws", credential_value="same-value")

        creds_a = vault_a.list_credentials()
        creds_b = vault_b.list_credentials()

        # Same value, different hashes (different tenant salt)
        assert creds_a[0].credential_hash != creds_b[0].credential_hash

    def test_duplicate_name_raises(self, db_connection: sqlite3.Connection) -> None:
        vault = CredentialManager(db_connection, "tenant-1")
        vault.store_credential(name="dup", provider="aws", credential_value="val")

        with pytest.raises(Exception):
            vault.store_credential(name="dup", provider="aws", credential_value="val2")
