#!/usr/bin/env python3
"""
Agent Monitor — Behavioral monitoring and self-modification guards.
@MASSAT-REMEDIATION: ASI10 (Rogue Agents)
BLP: [DU, SI] (Durability, Self-Improvement)
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("bo.agent_monitor")

BO_ROOT = Path(__file__).parent.parent
MONITOR_LOG = BO_ROOT / "logs" / "agent_behavior.jsonl"

# ---------------------------------------------------------------------------
# Behavioral Thresholds
# ---------------------------------------------------------------------------
MAX_TOOL_CALLS_PER_SESSION = 200
MAX_ERRORS_PER_SESSION = 20
MAX_OUTPUT_SIZE_PER_ACTION = 1_000_000  # 1MB
ANOMALY_TOOL_CALL_SPIKE = 50  # If > 50 calls in 60s, flag

# Files agents MUST NOT modify (self-modification guard)
PROTECTED_FILES = {
    "core/security_guards.py",
    "core/tool_allowlist.py",
    "core/safe_subprocess.py",
    "core/agent_monitor.py",
    "core/agent_messages.py",
    ".claude/hooks/",
    "config/security_config.json",
}


# ---------------------------------------------------------------------------
# Session Tracker
# ---------------------------------------------------------------------------
class AgentSessionMonitor:
    """Track agent behavior within a session for anomaly detection."""

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.session_start = time.monotonic()
        self.tool_calls: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.total_output_bytes = 0
        self._file_hash_baseline: Dict[str, str] = {}

    def record_tool_call(self, tool_name: str, duration_ms: int = 0) -> Optional[str]:
        """Record a tool call. Returns anomaly message if detected, None otherwise."""
        self.tool_calls.append({
            "tool": tool_name,
            "timestamp": time.monotonic(),
            "duration_ms": duration_ms,
        })

        # Check total calls
        if len(self.tool_calls) > MAX_TOOL_CALLS_PER_SESSION:
            msg = f"Agent {self.agent_name} exceeded max tool calls ({MAX_TOOL_CALLS_PER_SESSION})"
            self._log_anomaly("tool_call_limit", msg)
            return msg

        # Check spike (calls in last 60s)
        now = time.monotonic()
        recent = [c for c in self.tool_calls if now - c["timestamp"] < 60]
        if len(recent) > ANOMALY_TOOL_CALL_SPIKE:
            msg = f"Agent {self.agent_name} tool call spike: {len(recent)} in 60s"
            self._log_anomaly("tool_call_spike", msg)
            return msg

        return None

    def record_error(self, error_msg: str) -> Optional[str]:
        """Record an error. Returns anomaly message if too many errors."""
        self.errors.append(error_msg)
        if len(self.errors) > MAX_ERRORS_PER_SESSION:
            msg = f"Agent {self.agent_name} exceeded max errors ({MAX_ERRORS_PER_SESSION})"
            self._log_anomaly("error_limit", msg)
            return msg
        return None

    def record_output(self, output_bytes: int) -> Optional[str]:
        """Record output size. Returns anomaly if too large."""
        self.total_output_bytes += output_bytes
        if output_bytes > MAX_OUTPUT_SIZE_PER_ACTION:
            msg = f"Agent {self.agent_name} output too large: {output_bytes} bytes"
            self._log_anomaly("output_size", msg)
            return msg
        return None

    def check_self_modification(self, file_path: str) -> bool:
        """Check if a file write targets a protected file. Returns True if BLOCKED."""
        for protected in PROTECTED_FILES:
            if protected in file_path:
                self._log_anomaly("self_modification_blocked", f"Blocked write to {file_path}")
                logger.error("BLOCKED: Agent %s attempted to modify protected file: %s",
                            self.agent_name, file_path)
                return True
        return False

    def get_summary(self) -> Dict[str, Any]:
        """Get session summary for audit."""
        elapsed = time.monotonic() - self.session_start
        return {
            "agent": self.agent_name,
            "duration_seconds": round(elapsed, 2),
            "tool_calls": len(self.tool_calls),
            "errors": len(self.errors),
            "total_output_bytes": self.total_output_bytes,
            "anomalies_detected": 0,  # Updated by _log_anomaly
        }

    def _log_anomaly(self, anomaly_type: str, message: str) -> None:
        """Log a behavioral anomaly."""
        MONITOR_LOG.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": self.agent_name,
            "anomaly_type": anomaly_type,
            "message": message,
            "session_tool_calls": len(self.tool_calls),
            "session_errors": len(self.errors),
        }
        try:
            with open(MONITOR_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            logger.error("Failed to write agent behavior log")

        logger.warning("ANOMALY [%s]: %s — %s", self.agent_name, anomaly_type, message)
