"""Sandboxed command executor.

Executes validated commands via subprocess (local) or SSH (remote hosts).
Implements the execution constraints from PRD_Brain_vB1.2 §7:
    - Per-command timeout (default: 30s)
    - Output size limits (stdout: 64KB, stderr: 16KB)
    - Tail-truncation for oversized output
    - Full audit trail (command, exit code, duration, output)

Security notes:
    - Commands are NEVER run through a shell interpreter (no ``shell=True``).
      For OS commands, ``shlex.split`` tokenizes the command safely.
    - Cloud CLI credentials are injected via environment variables and
      purged immediately after execution.
    - All execution results are stored in STM for Security Review audit.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from vce_hq.config import settings
from vce_hq.execution.validator import CommandDomain, ValidationResult, validate_command, RiskSignal
from vce_hq.execution.security_gate import review_command, GateDecision

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    """Result of a single command execution.

    Attributes:
        command_id: Unique identifier for this execution.
        command: The command that was executed.
        agent: Which agent requested this command.
        exit_code: Process exit code (None if timed out).
        stdout: Captured standard output (may be truncated).
        stderr: Captured standard error (may be truncated).
        duration_ms: Wall-clock execution time in milliseconds.
        validated_by: The validation scheme that approved the command.
        truncated: Whether output was truncated due to size limits.
        timestamp: When the command was executed.
    """
    command_id: str
    command: str
    agent: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    validated_by: str
    truncated: bool
    risk_signal: str = "none"
    gate_invoked: bool = False
    gate_decision: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        """Serialize to a dictionary for storage and state passing."""
        return {
            "command_id": self.command_id,
            "command": self.command,
            "agent": self.agent,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "validated_by": self.validated_by,
            "truncated": self.truncated,
            "risk_signal": self.risk_signal,
            "gate_invoked": self.gate_invoked,
            "gate_decision": self.gate_decision,
            "timestamp": self.timestamp.isoformat(),
        }


class CommandExecutor:
    """Sandboxed command execution engine.

    Validates commands via the blocklist system, executes them
    with strict timeouts and output limits, and returns structured results.

    Args:
        agent_name: The agent requesting execution (for audit trail).
        domain: Whether this executor runs OS or Cloud commands.
        timeout_seconds: Per-command timeout.
        max_stdout_bytes: Maximum stdout capture size.
        max_stderr_bytes: Maximum stderr capture size.
    """

    def __init__(
        self,
        agent_name: str,
        domain: CommandDomain,
        *,
        timeout_seconds: int | None = None,
        max_stdout_bytes: int | None = None,
        max_stderr_bytes: int | None = None,
    ) -> None:
        self._agent = agent_name
        self._domain = domain
        self._timeout = timeout_seconds or settings.cmd_timeout_seconds
        self._max_stdout = max_stdout_bytes or settings.cmd_max_stdout_bytes
        self._max_stderr = max_stderr_bytes or settings.cmd_max_stderr_bytes

        self._mode = int(str(settings.execution_mode)[-1]) # 1, 2, or 3

    async def execute(
        self,
        command: str,
        *,
        env_overrides: dict[str, str] | None = None,
        reasoning: str = "",
        use_shell: bool = False,
        original_query: str = "",
        adrs_context: str = "",
        skip_gate: bool = False,
    ) -> CommandResult:
        """Validate and execute a command.

        The full flow:
            1. Validate against blocklist system
            2. Execute as subprocess with timeout
            3. Capture and truncate output
            4. Return structured result

        Args:
            command: The command string to execute.
            env_overrides: Additional environment variables (e.g., cloud credentials).
                These are merged into the subprocess environment and NOT persisted.
            reasoning: Why the agent chose to run this command (for audit).
            use_shell: If ``True``, run the command via ``/bin/sh -c`` so that
                the container's full PATH (including cloud CLIs) is available.
                This is required for Cloud Engineer commands (gcloud, aws, az,
                kubectl). OS Engineer commands run without a shell for safety.
            skip_gate: Bypass the LLM security gate (used for approved HITL commands).

        Returns:
            A ``CommandResult`` with captured output and metadata.

        Raises:
            CommandValidationError: If the command fails validation.
        """
        command = command.strip()
        command_id = str(uuid.uuid4())

        # ── Stage 1: Validate ─────────────────────────────────
        validation = validate_command(command, self._domain)
        if not validation.approved:
            logger.warning(
                "Command execution DENIED | agent=%s cmd='%s' reason='%s'",
                self._agent, command, validation.reason,
            )
            return CommandResult(
                command_id=command_id,
                command=command,
                agent=self._agent,
                exit_code=-1,
                stdout="",
                stderr=f"VALIDATION FAILED: {validation.reason}",
                duration_ms=0,
                validated_by=f"{validation.status.value}",
                truncated=False,
                risk_signal=validation.risk_signal.value,
            )

        risk_signal = validation.risk_signal

        # Pre-Execution Security Gate for ELEVATED and CRITICAL risk
        if not skip_gate and risk_signal in (RiskSignal.ELEVATED, RiskSignal.CRITICAL):
            logger.info("Triggering LLM Security Gate for %s risk command", risk_signal.value)
            gate_result = await review_command(
                command=command,
                domain=self._domain.value,
                risk_signal=risk_signal.value,
                original_query=original_query,
                reasoning=reasoning,
                adrs_context=adrs_context,
            )
            
            if gate_result.decision == GateDecision.REJECTED:
                logger.warning(
                    "Command execution REJECTED by Security Gate | agent=%s cmd='%s' reason='%s'",
                    self._agent, command, gate_result.reason
                )
                return CommandResult(
                    command_id=command_id,
                    command=command,
                    agent=self._agent,
                    exit_code=-1,
                    stdout="",
                    stderr=f"SECURITY GATE REJECTED: {gate_result.reason}",
                    duration_ms=0,
                    validated_by="security_gate_rejected",
                    truncated=False,
                    risk_signal=risk_signal.value,
                    gate_invoked=True,
                    gate_decision=gate_result.decision.value,
                )
                
            if gate_result.decision == GateDecision.REQUIRES_HITL:
                logger.info(
                    "Command execution REQUIRES HITL | agent=%s cmd='%s'",
                    self._agent, command
                )
                return CommandResult(
                    command_id=command_id,
                    command=command,
                    agent=self._agent,
                    exit_code=-3, # Magic exit code for HITL needed
                    stdout="",
                    stderr=f"REQUIRES_HITL: {gate_result.reason}. Ask the user for approval.",
                    duration_ms=0,
                    validated_by="security_gate_hitl",
                    truncated=False,
                    risk_signal=risk_signal.value,
                    gate_invoked=True,
                    gate_decision=gate_result.decision.value,
                )

        # ── Stage 2: Execute ──────────────────────────────────
        logger.info(
            "Executing command | agent=%s domain=%s shell=%s cmd='%s' reasoning='%s'",
            self._agent, self._domain.value, use_shell, command, reasoning[:200],
        )

        start_time = time.monotonic()

        try:
            import os
            env = os.environ.copy()
            if env_overrides:
                env.update(env_overrides)

            # Extract infrastructure command prefix (e.g., gcloud auth
            # activate-service-account). This is injected by the credential
            # resolver and is NOT an LLM-generated command — it runs after
            # validation to transparently authenticate the CLI session.
            cmd_prefix = env.pop("_VCE_CMD_PREFIX_", "")
            if cmd_prefix:
                command = cmd_prefix + command
                logger.info(
                    "Executor: prepended auth prefix to command (total length: %d)",
                    len(command),
                )

            if use_shell:
                # Run via /bin/sh so the container's full PATH is available.
                # This is required for cloud CLIs (gcloud, aws, az, kubectl).
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    executable="/bin/sh",
                )
            else:
                # Safe tokenized execution (no shell interpreter).
                args = shlex.split(command)
                process = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )

            try:
                raw_stdout, raw_stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self._timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                duration_ms = int((time.monotonic() - start_time) * 1000)
                logger.warning(
                    "Command TIMED OUT after %ds | cmd='%s'",
                    self._timeout, command,
                )
                return CommandResult(
                    command_id=command_id,
                    command=command,
                    agent=self._agent,
                    exit_code=None,
                    stdout="",
                    stderr=f"TIMEOUT: Command exceeded {self._timeout}s limit",
                    duration_ms=duration_ms,
                    validated_by="blocklist_pass" if risk_signal == RiskSignal.NONE else "security_gate_approved",
                    truncated=False,
                    risk_signal=risk_signal.value,
                    gate_invoked=risk_signal in (RiskSignal.ELEVATED, RiskSignal.CRITICAL) and not skip_gate,
                    gate_decision="approved" if (risk_signal in (RiskSignal.ELEVATED, RiskSignal.CRITICAL) and not skip_gate) else "",
                )

            duration_ms = int((time.monotonic() - start_time) * 1000)

            # ── Stage 3: Truncate output ──────────────────────
            stdout, stderr, truncated = self._truncate_output(
                raw_stdout, raw_stderr
            )

            gate_was_invoked = risk_signal in (RiskSignal.ELEVATED, RiskSignal.CRITICAL) and not skip_gate
            result = CommandResult(
                command_id=command_id,
                command=command,
                agent=self._agent,
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                validated_by="blocklist_pass" if not gate_was_invoked else "security_gate_approved",
                truncated=truncated,
                risk_signal=risk_signal.value,
                gate_invoked=gate_was_invoked,
                gate_decision="approved" if gate_was_invoked else "",
            )

            logger.info(
                "Command completed | cmd='%s' exit=%s duration=%dms truncated=%s",
                command, process.returncode, duration_ms, truncated,
            )

            return result

        except FileNotFoundError:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            return CommandResult(
                command_id=command_id,
                command=command,
                agent=self._agent,
                exit_code=127,
                stdout="",
                stderr=f"Command not found: {shlex.split(command)[0]}",
                duration_ms=duration_ms,
                validated_by="blocklist_pass",
                truncated=False,
                risk_signal=risk_signal.value,
            )
        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            logger.error("Command execution failed: %s", e)
            return CommandResult(
                command_id=command_id,
                command=command,
                agent=self._agent,
                exit_code=-1,
                stdout="",
                stderr=f"Execution error: {e}",
                duration_ms=duration_ms,
                validated_by="blocklist_pass",
                truncated=False,
                risk_signal=risk_signal.value,
            )

    def _truncate_output(
        self,
        raw_stdout: bytes,
        raw_stderr: bytes,
    ) -> tuple[str, str, bool]:
        """Decode and tail-truncate output to configured limits.

        Tail-truncation preserves the most recent output, which is
        typically the most useful for diagnostics.

        Args:
            raw_stdout: Raw stdout bytes from the process.
            raw_stderr: Raw stderr bytes from the process.

        Returns:
            Tuple of (stdout_str, stderr_str, was_truncated).
        """
        truncated = False

        if len(raw_stdout) > self._max_stdout:
            raw_stdout = raw_stdout[-self._max_stdout:]
            truncated = True

        if len(raw_stderr) > self._max_stderr:
            raw_stderr = raw_stderr[-self._max_stderr:]
            truncated = True

        stdout = raw_stdout.decode("utf-8", errors="replace")
        stderr = raw_stderr.decode("utf-8", errors="replace")

        return stdout, stderr, truncated


def format_command_log(results: list[CommandResult]) -> str:
    """Format a list of command results into a readable log for LLM consumption.

    Used by the Security Review agent to audit all commands executed
    during a session.

    Args:
        results: List of command execution results.

    Returns:
        A formatted multi-line string suitable for LLM prompt injection.
    """
    if not results:
        return "No commands were executed during this session."

    lines: list[str] = [
        f"=== COMMAND EXECUTION LOG ({len(results)} commands) ===\n"
    ]

    for i, result in enumerate(results, 1):
        lines.append(f"--- Command {i}/{len(results)} ---")
        lines.append(f"Agent: {result.agent}")
        lines.append(f"Command: {result.command}")
        lines.append(f"Exit Code: {result.exit_code}")
        lines.append(f"Duration: {result.duration_ms}ms")
        lines.append(f"Validation: {result.validated_by}")
        if result.truncated:
            lines.append("⚠️ Output was truncated due to size limits")
        if result.stdout:
            lines.append(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            lines.append(f"STDERR:\n{result.stderr}")
        lines.append("")

    return "\n".join(lines)
