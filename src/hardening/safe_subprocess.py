#!/usr/bin/env python3
"""
Safe Subprocess — Sandboxed subprocess wrapper with command allowlists.
@MASSAT-REMEDIATION: ASI05 (Unexpected Code Execution)
BLP: [A, DU] (Alignment, Durability)
"""

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("bo.safe_subprocess")

# ---------------------------------------------------------------------------
# Command Allowlist
# ---------------------------------------------------------------------------
# Only these binaries can be executed via safe_run()
ALLOWED_COMMANDS: Dict[str, Dict[str, Any]] = {
    "claude": {
        "description": "Claude CLI for agent deliberation",
        "max_timeout": 300,
        "allowed_args_patterns": ["--print", "-p", "--model", "--max-turns"],
    },
    "node": {
        "description": "Node.js runtime for Midnight SDK",
        "max_timeout": 120,
        "allowed_args_patterns": ["midnight/dist/cli.js"],
    },
    "curl": {
        "description": "HTTP client for notifications",
        "max_timeout": 30,
        "allowed_args_patterns": ["-s", "-X", "-H", "-d", "--max-time"],
    },
    "python3": {
        "description": "Python for sub-agent execution",
        "max_timeout": 300,
        "allowed_args_patterns": ["-c", "-m", "scripts/"],
    },
    "git": {
        "description": "Git operations",
        "max_timeout": 60,
        "allowed_args_patterns": ["log", "status", "diff", "show"],
    },
}

# Maximum output size to prevent memory exhaustion
MAX_OUTPUT_SIZE = 1_000_000  # 1MB

# Environment variables that MUST be stripped from subprocess environments
BLOCKED_ENV_VARS = {
    "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "MNEMONIC",
    "DATABASE_PASSWORD", "DB_PASSWORD", "REDIS_PASSWORD",
}


# ---------------------------------------------------------------------------
# Safe Execution
# ---------------------------------------------------------------------------
def safe_run(
    command: List[str],
    timeout: int = 60,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    capture_output: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """Execute a subprocess command with security guards.

    - Validates command against allowlist
    - Enforces timeout
    - Strips sensitive env vars
    - Limits output size

    Args:
        command: Command and arguments as list.
        timeout: Max execution time in seconds.
        cwd: Working directory.
        env: Environment variables (sensitive ones stripped automatically).
        capture_output: Whether to capture stdout/stderr.
        check: Whether to raise on non-zero exit.

    Returns:
        subprocess.CompletedProcess

    Raises:
        PermissionError: If command is not in allowlist.
        subprocess.TimeoutExpired: If timeout exceeded.
    """
    if not command:
        raise ValueError("Empty command")

    binary = os.path.basename(command[0])

    # Check allowlist
    if binary not in ALLOWED_COMMANDS:
        logger.error("BLOCKED: Command '%s' not in allowlist", binary)
        raise PermissionError(
            f"Command '{binary}' is not in the safe subprocess allowlist. "
            f"Allowed: {list(ALLOWED_COMMANDS.keys())}"
        )

    cmd_config = ALLOWED_COMMANDS[binary]

    # Enforce max timeout
    max_timeout = cmd_config.get("max_timeout", 60)
    effective_timeout = min(timeout, max_timeout)

    # Build safe environment
    safe_env = _build_safe_env(env)

    logger.info("safe_run: %s (timeout=%ds, cwd=%s)", " ".join(command[:3]), effective_timeout, cwd)

    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            timeout=effective_timeout,
            cwd=cwd,
            env=safe_env,
        )

        # Truncate output if too large
        if result.stdout and len(result.stdout) > MAX_OUTPUT_SIZE:
            result = subprocess.CompletedProcess(
                args=result.args,
                returncode=result.returncode,
                stdout=result.stdout[:MAX_OUTPUT_SIZE] + "\n[OUTPUT TRUNCATED]",
                stderr=result.stderr,
            )

        if result.stderr and len(result.stderr) > MAX_OUTPUT_SIZE:
            result = subprocess.CompletedProcess(
                args=result.args,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr[:MAX_OUTPUT_SIZE] + "\n[STDERR TRUNCATED]",
            )

        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, result.args, result.stdout, result.stderr
            )

        return result

    except subprocess.TimeoutExpired:
        logger.error("Timeout: %s exceeded %ds", binary, effective_timeout)
        raise


def _build_safe_env(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Build a safe environment by stripping sensitive variables."""
    base_env = os.environ.copy()
    if env:
        base_env.update(env)

    # Strip sensitive variables
    for var in BLOCKED_ENV_VARS:
        base_env.pop(var, None)

    return base_env


def is_command_allowed(binary: str) -> bool:
    """Check if a binary is in the command allowlist."""
    return os.path.basename(binary) in ALLOWED_COMMANDS
