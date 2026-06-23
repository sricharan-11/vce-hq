"""Tests for the command execution and validation layer."""

import pytest

from vce_hq.execution.validator import (
    CommandDomain,
    ValidationStatus,
    RiskSignal,
    validate_command,
)
from vce_hq.config import settings, ExecutionMode

class TestCommandValidator:
    """Tests for the blocklist-first validation flow."""

    def test_os_read_commands_pass(self) -> None:
        """Valid OS read commands should pass with NONE risk."""
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
            assert result.risk_signal == RiskSignal.NONE

    def test_cloud_read_commands_pass(self) -> None:
        """Valid Cloud read commands should pass with NONE risk."""
        commands = [
            "aws ec2 describe-instances --filters Name=instance-type,Values=m5.large",
            "gcloud compute instances list",
            "az vm show -g prod -n web",
            "kubectl get pods -n kube-system",
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.CLOUD)
            assert result.approved is True, f"Expected {cmd} to be approved"
            assert result.status == ValidationStatus.APPROVED
            assert result.risk_signal == RiskSignal.NONE

    def test_os_global_blocklist(self) -> None:
        """Globally blocked OS commands should be rejected."""
        commands = [
            "fdisk /dev/sda",            # Disk partitioning
            "mkfs.ext4 /dev/sda1",       # Formatting
            "useradd evil",              # User management
            "iptables -F",               # Firewall flush
            "vi /etc/passwd",            # Interactive editor
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.OS)
            assert result.approved is False, f"Expected {cmd} to be blocked"
            assert result.status == ValidationStatus.BLOCKED

    def test_cloud_global_blocklist(self) -> None:
        """Globally blocked Cloud commands should be rejected."""
        commands = [
            "gcloud projects delete my-project",
            "aws organizations close-account --account-id 123",
            "terraform destroy",
            "kubectl delete namespace prod",
            "aws s3 rm s3://bucket --force", # Dangerous flag combo
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.CLOUD)
            assert result.approved is False, f"Expected {cmd} to be blocked"
            assert result.status == ValidationStatus.BLOCKED

    def test_os_mode_blocklist(self) -> None:
        """Mutating and destructive commands should be blocked in Mode 1."""
        settings.execution_mode = ExecutionMode.MODE_1
        commands = [
            "rm -rf /",                  # Destructive
            "kill -9 1234",              # Destructive
            "systemctl restart nginx",   # Mutating
            "chmod 777 /etc/shadow",     # Mutating
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.OS)
            assert result.approved is False, f"Expected {cmd} to be blocked"
            assert result.status == ValidationStatus.MODE_BLOCKED

    def test_cloud_mode_blocklist(self) -> None:
        """Mutating and destructive commands should be blocked in Mode 1."""
        settings.execution_mode = ExecutionMode.MODE_1
        commands = [
            "aws ec2 terminate-instances --instance-ids i-12345", # Destructive
            "gcloud compute instances stop my-vm",                # Mutating
            "kubectl apply -f deployment.yaml",                   # Mutating
        ]
        for cmd in commands:
            result = validate_command(cmd, CommandDomain.CLOUD)
            assert result.approved is False, f"Expected {cmd} to be blocked"
            assert result.status == ValidationStatus.MODE_BLOCKED

    def test_mode_2_allows_mutating(self) -> None:
        """Mode 2 should allow mutating verbs but block destructive verbs."""
        settings.execution_mode = ExecutionMode.MODE_2
        
        # Should be blocked
        result = validate_command("rm -rf /", CommandDomain.OS)
        assert result.approved is False
        assert result.status == ValidationStatus.MODE_BLOCKED
        
        # Should be approved with ELEVATED risk
        result = validate_command("systemctl restart nginx", CommandDomain.OS)
        assert result.approved is True
        assert result.risk_signal == RiskSignal.ELEVATED

        # Reset mode for other tests
        settings.execution_mode = ExecutionMode.MODE_1

    def test_unknown_command_passes(self) -> None:
        """Commands that don't match any blocklist should pass."""
        result = validate_command("echo hello", CommandDomain.OS)
        assert result.approved is True
        assert result.risk_signal == RiskSignal(settings.unknown_binary_risk.lower())

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
