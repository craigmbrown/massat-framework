#!/usr/bin/env python3
"""
Tool Allowlist — Per-agent tool whitelists with parameter validation.
@MASSAT-REMEDIATION: ASI02 (Tool Misuse and Exploitation)
BLP: [A] (Alignment)
"""

import logging
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, ValidationError

logger = logging.getLogger("bo.tool_allowlist")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
class ToolParameter(BaseModel):
    """Schema for a single tool parameter."""
    name: str
    type: str  # "str", "int", "float", "bool", "list", "dict"
    required: bool = True
    max_length: Optional[int] = None  # For strings


class ToolDefinition(BaseModel):
    """Definition of an allowed tool with parameter schema."""
    name: str
    description: str
    parameters: List[ToolParameter] = []
    max_calls_per_session: int = 100


# ---------------------------------------------------------------------------
# Per-Agent Allowlists
# ---------------------------------------------------------------------------
AGENT_TOOL_ALLOWLISTS: Dict[str, List[ToolDefinition]] = {
    "design_agent": [
        ToolDefinition(
            name="read_config",
            description="Read configuration files",
            parameters=[ToolParameter(name="config_path", type="str", max_length=500)],
        ),
        ToolDefinition(
            name="generate_architecture",
            description="Generate system architecture spec",
            parameters=[
                ToolParameter(name="markets", type="list"),
                ToolParameter(name="oracles", type="list"),
                ToolParameter(name="features", type="list"),
            ],
        ),
        ToolDefinition(
            name="validate_design",
            description="Validate a design specification",
            parameters=[ToolParameter(name="design", type="dict")],
        ),
    ],
    "implementation_agent": [
        ToolDefinition(
            name="read_config",
            description="Read configuration files",
            parameters=[ToolParameter(name="config_path", type="str", max_length=500)],
        ),
        ToolDefinition(
            name="write_code",
            description="Write code to a file",
            parameters=[
                ToolParameter(name="file_path", type="str", max_length=500),
                ToolParameter(name="content", type="str", max_length=50000),
            ],
        ),
        ToolDefinition(
            name="run_tests",
            description="Execute test suite",
            parameters=[ToolParameter(name="test_path", type="str", max_length=500)],
        ),
    ],
    "testing_agent": [
        ToolDefinition(
            name="run_tests",
            description="Execute test suite",
            parameters=[ToolParameter(name="test_path", type="str", max_length=500)],
        ),
        ToolDefinition(
            name="read_config",
            description="Read configuration files",
            parameters=[ToolParameter(name="config_path", type="str", max_length=500)],
        ),
    ],
    "operations_agent": [
        ToolDefinition(
            name="read_config",
            description="Read configuration files",
            parameters=[ToolParameter(name="config_path", type="str", max_length=500)],
        ),
        ToolDefinition(
            name="check_health",
            description="Check service health",
            parameters=[ToolParameter(name="service_name", type="str", max_length=100)],
        ),
        ToolDefinition(
            name="send_alert",
            description="Send monitoring alert",
            parameters=[
                ToolParameter(name="severity", type="str", max_length=20),
                ToolParameter(name="message", type="str", max_length=1000),
            ],
        ),
    ],
    "deployment_agent": [
        ToolDefinition(
            name="read_config",
            description="Read configuration files",
            parameters=[ToolParameter(name="config_path", type="str", max_length=500)],
        ),
        ToolDefinition(
            name="deploy",
            description="Deploy a service",
            parameters=[
                ToolParameter(name="service_name", type="str", max_length=100),
                ToolParameter(name="version", type="str", max_length=50),
            ],
        ),
        ToolDefinition(
            name="rollback",
            description="Rollback a deployment",
            parameters=[
                ToolParameter(name="service_name", type="str", max_length=100),
                ToolParameter(name="target_version", type="str", max_length=50),
            ],
        ),
    ],
}


# ---------------------------------------------------------------------------
# Validation Functions
# ---------------------------------------------------------------------------
def is_tool_allowed(agent_name: str, tool_name: str) -> bool:
    """Check if a tool is in the agent's allowlist."""
    allowlist = AGENT_TOOL_ALLOWLISTS.get(agent_name, [])
    return any(t.name == tool_name for t in allowlist)


def validate_tool_call(
    agent_name: str,
    tool_name: str,
    parameters: Dict[str, Any],
) -> Dict[str, Any]:
    """Validate a tool call against the agent's allowlist.

    Returns:
        Dict with 'allowed' (bool), 'violations' (list), 'tool_def' (if found).
    """
    violations: List[str] = []

    # Check if tool is in allowlist
    allowlist = AGENT_TOOL_ALLOWLISTS.get(agent_name, [])
    tool_def = None
    for t in allowlist:
        if t.name == tool_name:
            tool_def = t
            break

    if tool_def is None:
        violations.append(f"Tool '{tool_name}' not in allowlist for '{agent_name}'")
        allowed_names = [t.name for t in allowlist]
        logger.warning("Tool not allowed: %s attempted %s (allowed: %s)",
                       agent_name, tool_name, allowed_names)
        return {"allowed": False, "violations": violations, "tool_def": None}

    # Validate parameters against schema
    for param_def in tool_def.parameters:
        if param_def.required and param_def.name not in parameters:
            violations.append(f"Missing required parameter: {param_def.name}")

        if param_def.name in parameters:
            value = parameters[param_def.name]

            # Type checking
            expected_types = {
                "str": str, "int": int, "float": (int, float),
                "bool": bool, "list": list, "dict": dict,
            }
            expected = expected_types.get(param_def.type)
            if expected and not isinstance(value, expected):
                violations.append(
                    f"Parameter '{param_def.name}' type mismatch: "
                    f"expected {param_def.type}, got {type(value).__name__}"
                )

            # Length checking for strings
            if param_def.max_length and isinstance(value, str):
                if len(value) > param_def.max_length:
                    violations.append(
                        f"Parameter '{param_def.name}' too long: "
                        f"{len(value)} > {param_def.max_length}"
                    )

    return {
        "allowed": len(violations) == 0,
        "violations": violations,
        "tool_def": tool_def,
    }


def get_allowed_tools(agent_name: str) -> List[str]:
    """Get the list of tool names allowed for an agent."""
    return [t.name for t in AGENT_TOOL_ALLOWLISTS.get(agent_name, [])]
