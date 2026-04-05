#!/usr/bin/env python3
"""
Security Guards — Input validation, sanitization, and audit logging for BO agents.
@MASSAT-REMEDIATION: ASI01 (Goal Hijacking), ASI03 (Privilege Abuse),
                     ASI06 (Memory Poisoning), ASI09 (Trust Exploitation)
BLP: [A, DU] (Alignment, Durability)

Created as part of MASSAT audit remediation plan.
"""

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("bo.security_guards")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BO_ROOT = Path(__file__).parent.parent
AUDIT_LOG_FILE = BO_ROOT / "logs" / "security_audit.jsonl"

# Injection patterns to detect and block (ASI01, ASI06)
INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(previous|all|above)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"<\s*/?script", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"subprocess\.(run|Popen|call)\s*\(", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
]

# Maximum input sizes (ASI01)
MAX_INPUT_LENGTH = 50_000  # 50KB per field
MAX_TOTAL_INPUT_SIZE = 500_000  # 500KB total


# ---------------------------------------------------------------------------
# Input Validation (ASI01: Goal Hijacking)
# ---------------------------------------------------------------------------
def validate_agent_input(
    agent_name: str,
    input_data: Dict[str, Any],
    allowed_keys: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Validate agent input data against security rules.

    Args:
        agent_name: Name of the agent receiving input.
        input_data: The input data dict to validate.
        allowed_keys: If provided, only these keys are permitted.

    Returns:
        Dict with 'valid' (bool), 'sanitized' (cleaned data), 'violations' (list).

    Raises:
        ValueError: If input is critically malformed.
    """
    violations: List[str] = []
    sanitized = {}

    # Check total size
    total_size = len(json.dumps(input_data, default=str))
    if total_size > MAX_TOTAL_INPUT_SIZE:
        violations.append(f"Total input size {total_size} exceeds max {MAX_TOTAL_INPUT_SIZE}")
        _log_security_event("input_size_exceeded", agent_name, {
            "total_size": total_size, "max": MAX_TOTAL_INPUT_SIZE
        })
        return {"valid": False, "sanitized": {}, "violations": violations}

    # Check allowed keys
    if allowed_keys:
        unexpected = set(input_data.keys()) - allowed_keys
        if unexpected:
            violations.append(f"Unexpected keys: {unexpected}")
            _log_security_event("unexpected_keys", agent_name, {"keys": list(unexpected)})

    # Validate each field
    for key, value in input_data.items():
        if allowed_keys and key not in allowed_keys:
            continue  # Skip disallowed keys

        cleaned = _sanitize_value(value, key, agent_name, violations)
        sanitized[key] = cleaned

    is_valid = len(violations) == 0
    if not is_valid:
        _log_security_event("input_validation_failed", agent_name, {
            "violation_count": len(violations),
            "violations": violations[:5],
        })

    return {"valid": is_valid, "sanitized": sanitized, "violations": violations}


def _sanitize_value(
    value: Any, key: str, agent_name: str, violations: List[str]
) -> Any:
    """Recursively sanitize a value, checking for injection patterns."""
    if isinstance(value, str):
        # Check size
        if len(value) > MAX_INPUT_LENGTH:
            violations.append(f"Field '{key}' exceeds max length ({len(value)} > {MAX_INPUT_LENGTH})")
            return value[:MAX_INPUT_LENGTH]

        # Check for injection patterns
        for pattern in INJECTION_PATTERNS:
            if pattern.search(value):
                violations.append(f"Injection pattern detected in '{key}': {pattern.pattern[:40]}")
                _log_security_event("injection_detected", agent_name, {
                    "field": key, "pattern": pattern.pattern[:40],
                })
                # Strip the match rather than rejecting entirely
                value = pattern.sub("[BLOCKED]", value)

        return value

    elif isinstance(value, dict):
        return {k: _sanitize_value(v, f"{key}.{k}", agent_name, violations)
                for k, v in value.items()}

    elif isinstance(value, list):
        return [_sanitize_value(item, f"{key}[{i}]", agent_name, violations)
                for i, item in enumerate(value)]

    # Numbers, booleans, None pass through
    return value


# ---------------------------------------------------------------------------
# Scope Enforcement (ASI03: Identity & Privilege Abuse)
# ---------------------------------------------------------------------------
AGENT_SCOPES: Dict[str, Set[str]] = {
    "design_agent": {"design_system", "validate_design", "read_config"},
    "implementation_agent": {"implement", "write_code", "read_config", "run_tests"},
    "testing_agent": {"run_tests", "validate", "read_config"},
    "operations_agent": {"monitor", "alert", "read_config", "restart_service"},
    "deployment_agent": {"deploy", "rollback", "read_config"},
}


def check_agent_scope(agent_name: str, action: str) -> bool:
    """Check if an agent is authorized for a given action.

    Returns True if allowed, False if not. Logs violations.
    """
    # Default: agents without defined scopes get read_config only
    allowed = AGENT_SCOPES.get(agent_name, {"read_config"})

    if action not in allowed:
        _log_security_event("scope_violation", agent_name, {
            "attempted_action": action,
            "allowed_actions": list(allowed),
        })
        logger.warning("Scope violation: %s attempted '%s' (allowed: %s)",
                       agent_name, action, allowed)
        return False

    return True


# ---------------------------------------------------------------------------
# Content Sanitizer (ASI06: Memory/Context Poisoning)
# ---------------------------------------------------------------------------
def sanitize_memory_content(content: str, source: str = "unknown") -> str:
    """Sanitize content before writing to agent memory or knowledge graph.

    Strips injection patterns and enforces size limits.
    """
    if len(content) > MAX_INPUT_LENGTH:
        content = content[:MAX_INPUT_LENGTH]
        _log_security_event("memory_content_truncated", source, {
            "original_length": len(content),
        })

    for pattern in INJECTION_PATTERNS:
        content = pattern.sub("[SANITIZED]", content)

    return content


# ---------------------------------------------------------------------------
# Audit Logger (ASI09: Human-Agent Trust, all categories)
# ---------------------------------------------------------------------------
def _log_security_event(
    event_type: str,
    agent_name: str,
    details: Dict[str, Any],
) -> None:
    """Append a security event to the audit log (JSONL, append-only).

    This is the core audit trail for all security-relevant actions.
    """
    AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "agent": agent_name,
        "details": details,
    }

    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        logger.error("Failed to write security audit log")


def log_agent_action(
    agent_name: str,
    action: str,
    inputs_hash: Optional[str] = None,
    result_summary: Optional[str] = None,
) -> None:
    """Log an agent action for audit trail. Call at start/end of every agent method."""
    _log_security_event("agent_action", agent_name, {
        "action": action,
        "inputs_hash": inputs_hash,
        "result_summary": result_summary,
    })
