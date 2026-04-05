#!/usr/bin/env python3
"""
Agent Messages — Typed inter-agent message schemas with validation.
@MASSAT-REMEDIATION: ASI07 (Insecure Inter-Agent Communication)
BLP: [A, SO] (Alignment, Self-Organization)
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class MessagePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AgentMessage(BaseModel):
    """Base message schema for all inter-agent communication."""
    sender: str = Field(..., min_length=1, max_length=100)
    recipient: str = Field(..., min_length=1, max_length=100)
    message_type: str = Field(..., min_length=1, max_length=50)
    priority: MessagePriority = MessagePriority.MEDIUM
    payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = Field(None, max_length=100)

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, v: Dict) -> Dict:
        import json
        size = len(json.dumps(v, default=str))
        if size > 500_000:
            raise ValueError(f"Payload too large: {size} bytes (max 500KB)")
        return v


class DesignRequest(AgentMessage):
    """Request for design phase work."""
    message_type: str = "design_request"
    payload: Dict[str, Any] = Field(...)

    @field_validator("payload")
    @classmethod
    def validate_design_payload(cls, v: Dict) -> Dict:
        if "markets" not in v and "requirements" not in v:
            raise ValueError("Design request must include 'markets' or 'requirements'")
        return v


class DesignResponse(AgentMessage):
    """Response from design phase."""
    message_type: str = "design_response"
    success: bool = True
    error: Optional[str] = None


class TaskDelegation(AgentMessage):
    """Delegate a task from one agent to another."""
    message_type: str = "task_delegation"
    task_type: str = Field(..., min_length=1, max_length=100)
    deadline: Optional[datetime] = None
    scope_constraints: List[str] = Field(default_factory=list)


class HealthCheck(AgentMessage):
    """Health check message between agents."""
    message_type: str = "health_check"
    status: str = Field("alive", pattern=r"^(alive|degraded|error)$")
    uptime_seconds: float = 0.0
    last_action: Optional[str] = None


def validate_message(data: Dict[str, Any]) -> AgentMessage:
    """Parse and validate a raw dict into the appropriate message type.

    Raises ValidationError if the message is malformed.
    """
    msg_type = data.get("message_type", "")
    type_map = {
        "design_request": DesignRequest,
        "design_response": DesignResponse,
        "task_delegation": TaskDelegation,
        "health_check": HealthCheck,
    }
    model_cls = type_map.get(msg_type, AgentMessage)
    return model_cls(**data)
