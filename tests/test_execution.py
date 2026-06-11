"""Tests for the command execution and validation layer."""

import pytest

from vce_hq.execution.validator import (
    CommandDomain,
    ValidationStatus,
    validate_command,
)


class TestCommandValidator:
    """Tests for the 3-stage command validation flow."""

    def test_os_allowlist_pass(self) -> None:
        """Valid OS commands should pass."""
        commands = [
            "df -hT",
            "journalctl -u nginx -n 50",
            "ps aux --sort=-%mem",
            "cat /proc/meminfo",
            "systemctl status kubelet",
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.OS)
            assert result.approved is True, f"Expected {cmd} to be approved"
            assert result.status == ValidationStatus.APPROVED

    def test_cloud_allowlist_pass(self) -> None:
        """Valid Cloud commands should pass."""
        commands = [
            "aws ec2 describe-instances --filters Name=instance-type,Values=m5.large",
            "gcloud compute instances list",
            "az vm show -g prod -n web",
            "kubectl get pods -n kube-system",
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.CLOUD)
            assert result.approved is True, f"Expected {cmd} to be approved"

    def test_os_blocklist_reject(self) -> None:
        """Blocked OS commands should be rejected."""
        commands = [
            "rm -rf /",                  # Destructive
            "systemctl restart nginx",   # Write operation
            "chmod 777 /etc/shadow",     # Permission change
            "useradd evil",              # User management
            "kill -9 1234",              # Process kill
            "fdisk /dev/sda",            # Disk partitioning
            "apt install nmap",          # Package installation
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.OS)
            assert result.approved is False, f"Expected {cmd} to be blocked"
            assert result.status == ValidationStatus.BLOCKED

    def test_cloud_blocklist_reject(self) -> None:
        """Blocked Cloud commands should be rejected."""
        commands = [
            "aws ec2 terminate-instances --instance-ids i-12345",
            "aws s3 rm s3://mybucket/file",
            "gcloud compute instances stop my-vm",
            "az vm deallocate -n my-vm",
            "kubectl delete pod my-pod",
            "kubectl apply -f deployment.yaml",
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.CLOUD)
            assert result.approved is False, f"Expected {cmd} to be blocked"
            assert result.status == ValidationStatus.BLOCKED

    def test_not_allowlisted(self) -> None:
        """Commands not explicitly allowlisted should be rejected."""
        result = validate_command("echo hello", CommandDomain.OS)
        assert result.approved is False
        assert result.status == ValidationStatus.NOT_ALLOWLISTED

    def test_shell_injection_pipes(self) -> None:
        """Safe pipes should pass, dangerous pipes should fail."""
        # Safe
        result = validate_command("df -hT | grep /dev/sda1", CommandDomain.OS)
        assert result.approved is True

        result = validate_command("kubectl get pods | awk '{print $1}'", CommandDomain.CLOUD)
        assert result.approved is True

        # Dangerous pipe (not in safe list)
        result = validate_command("df -hT | python -c 'import os'", CommandDomain.OS)
        assert result.approved is False
        assert result.status == ValidationStatus.SANITIZATION_FAILED

    def test_shell_injection_redirection(self) -> None:
        """File redirection should fail (except /dev/null)."""
        # Dangerous
        result = validate_command("df -hT > /tmp/out.txt", CommandDomain.OS)
        assert result.approved is False
        assert result.status == ValidationStatus.SANITIZATION_FAILED

        # Safe
        result = validate_command("apt list 2>/dev/null", CommandDomain.OS)
        assert result.approved is True

    def test_shell_injection_chaining(self) -> None:
        """Command chaining should fail."""
        commands = [
            "df -hT ; echo hello",
            "df -hT && echo fail",
            "df -hT || echo fail",
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.OS)
            assert result.approved is False
            assert result.status == ValidationStatus.SANITIZATION_FAILED

    def test_shell_injection_subshell(self) -> None:
        """Subshell execution should fail."""
        commands = [
            "df -hT $(echo /)",
            "df -hT `echo /`",
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.OS)
            assert result.approved is False
            assert result.status == ValidationStatus.SANITIZATION_FAILED
