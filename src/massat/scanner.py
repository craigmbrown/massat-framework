#!/usr/bin/env python3
"""
MAS Security Scanner - Multi-Agent System Security Assessment Tool (MASSAT)

A Single File Agent (SFA) for programmatic and cron-based security audits of
multi-agent systems. Assesses all OWASP ASI01-ASI10 threat categories and maps
findings to OWASP, NIST AI RMF, ISO 42001, CSA AICM, and MAESTRO frameworks.

REQ-SEC-001: Autonomous security assessment capability
BLP: [Alignment, Durability, Self-Improvement] - Security posture monitoring

Usage:
    # Full audit of current project
    python3 scripts/mas_security_scanner.py --target /path/to/system

    # Quick scan
    python3 scripts/mas_security_scanner.py --target . --scope quick

    # Targeted categories with notifications
    python3 scripts/mas_security_scanner.py --target . --categories ASI01,ASI06 --notify

    # View existing audit report
    python3 scripts/mas_security_scanner.py --report security-audits/audit-20260222-etac/

    # Full audit with debate and NFT minting
    python3 scripts/mas_security_scanner.py --target . --scope full --with-debate --mint-nft

Programmatic API:
    from scripts.mas_security_scanner import MASSecurityScanner
    scanner = MASSecurityScanner(target_path="/path/to/system")
    results = scanner.run_audit(scope="full")
    scanner.generate_report()
    scanner.notify(channels=["whatsapp", "email"])

Exit Codes:
    0 - Clean audit (no findings above low severity)
    1 - Findings present (medium/high severity)
    2 - Critical findings detected
"""

import argparse
import glob as glob_module
import json
import logging
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from pydantic import BaseModel, Field, field_validator
except ImportError:
    print("ERROR: pydantic is required. Install with: pip install pydantic", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "massat_audit.log"

PROFILES_PATH = PROJECT_ROOT / "configs" / "security_audit_profiles.json"
SCHEDULES_PATH = PROJECT_ROOT / "configs" / "security_audit_schedules.json"
TEMPLATE_PATH = PROJECT_ROOT / "templates" / "security-dashboard.html"
HTML_OUTPUT_DIR = PROJECT_ROOT / "html-output"
AUDIT_BASE_DIR = PROJECT_ROOT / "security-audits"

ASI_CATEGORIES = [
    ("ASI01", "Agent Goal Hijacking", "goal-hijacking"),
    ("ASI02", "Tool Misuse and Exploitation", "tool-misuse"),
    ("ASI03", "Identity and Privilege Abuse", "identity-privilege"),
    ("ASI04", "Agentic Supply Chain Vulnerabilities", "supply-chain"),
    ("ASI05", "Unexpected Code Execution", "code-execution"),
    ("ASI06", "Memory and Context Poisoning", "memory-poisoning"),
    ("ASI07", "Insecure Inter-Agent Communication", "inter-agent-comms"),
    ("ASI08", "Cascading Failures", "cascading-failures"),
    ("ASI09", "Human-Agent Trust Exploitation", "trust-exploitation"),
    ("ASI10", "Rogue Agents", "rogue-agents"),
]

# Severity color palette
SEVERITY_COLORS = {
    "critical": "#f44336",
    "high": "#ff9800",
    "medium": "#ffeb3b",
    "low": "#4caf50",
    "info": "#2196f3",
}

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("massat")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the scanner."""
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler - always debug
    fh = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)

    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.addHandler(fh)
    logger.addHandler(ch)


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class AuditConfig(BaseModel):
    """Configuration for a security audit run."""

    target_path: str = Field(description="Absolute path to the target system")
    scope: str = Field(default="full", description="Audit scope: full, quick, or targeted")
    categories: List[str] = Field(
        default_factory=lambda: [c[0] for c in ASI_CATEGORIES],
        description="ASI categories to assess (e.g. ['ASI01','ASI06'])",
    )
    skip_phases: List[str] = Field(
        default_factory=list,
        description="Phases to skip: discovery, vulnerability, compliance, redteam, report",
    )
    notification_channels: List[str] = Field(
        default_factory=list,
        description="Notification channels: whatsapp, email",
    )
    with_debate: bool = Field(default=False, description="Trigger multi-agent debate")
    mint_nft: bool = Field(default=False, description="Mint on-chain NFT of audit results")
    verbose: bool = Field(default=False, description="Enable verbose logging")

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        if v not in ("full", "quick", "targeted"):
            raise ValueError(f"Invalid scope '{v}'. Must be full, quick, or targeted.")
        return v

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, v: List[str]) -> List[str]:
        valid = {c[0] for c in ASI_CATEGORIES}
        for cat in v:
            if cat not in valid:
                raise ValueError(f"Invalid category '{cat}'. Must be one of {sorted(valid)}.")
        return v


class Evidence(BaseModel):
    """A piece of evidence supporting a finding."""

    file: str = Field(description="File path relative to target")
    line: Optional[int] = Field(default=None, description="Line number if applicable")
    description: str = Field(description="What this evidence shows")


class Remediation(BaseModel):
    """A remediation action for a finding."""

    priority: int = Field(ge=1, le=5, description="Priority 1 (urgent) to 5 (low)")
    action: str = Field(description="Remediation action to take")
    effort: str = Field(description="Effort estimate: low, medium, high")
    framework_refs: List[str] = Field(
        default_factory=list,
        description="Related framework references (e.g. NIST-MG-2.3)",
    )


class ASIFinding(BaseModel):
    """A security finding for one ASI category."""

    category: str = Field(description="ASI category ID (e.g. ASI01)")
    name: str = Field(description="Category name")
    risk_score: float = Field(ge=0.0, le=10.0, description="Normalized risk score 0-10")
    severity: str = Field(description="Severity: critical, high, medium, low, info")
    likelihood: int = Field(ge=1, le=5, description="Likelihood score 1-5")
    impact: int = Field(ge=1, le=5, description="Impact score 1-5")
    controls_present: List[str] = Field(default_factory=list, description="Controls found")
    controls_missing: List[str] = Field(default_factory=list, description="Controls absent")
    evidence: List[Evidence] = Field(default_factory=list, description="Supporting evidence")
    blast_radius: str = Field(default="unknown", description="Blast radius description")
    remediation: List[Remediation] = Field(default_factory=list, description="Remediation actions")


class ComplianceMapping(BaseModel):
    """Compliance mapping for a single framework."""

    framework_id: str
    framework_name: str
    covered: int = 0
    total: int = 0
    percentage: float = 0.0
    gaps: List[str] = Field(default_factory=list)


class SimulationResult(BaseModel):
    """Result of a red team simulation scenario."""

    scenario: str
    attack_vector: str
    target_agent: str = "system-wide"
    success_likelihood: str = "unknown"
    existing_defenses: List[str] = Field(default_factory=list)
    defense_bypass_path: str = ""
    recommendation: str = ""


class InventoryItem(BaseModel):
    """An item discovered in the system inventory."""

    name: str
    path: str
    item_type: str  # agent, tool, mcp_server, service, credential_ref, data_store, hook, trust_boundary
    details: Dict[str, Any] = Field(default_factory=dict)


class SystemInventory(BaseModel):
    """Complete system inventory from the discovery phase."""

    agents: List[InventoryItem] = Field(default_factory=list)
    tools: List[InventoryItem] = Field(default_factory=list)
    mcp_servers: List[InventoryItem] = Field(default_factory=list)
    services: List[InventoryItem] = Field(default_factory=list)
    credential_refs: List[InventoryItem] = Field(default_factory=list)
    data_stores: List[InventoryItem] = Field(default_factory=list)
    hooks: List[InventoryItem] = Field(default_factory=list)
    trust_boundaries: List[InventoryItem] = Field(default_factory=list)
    communication_channels: List[InventoryItem] = Field(default_factory=list)
    metrics: Dict[str, int] = Field(default_factory=dict)


class AuditReport(BaseModel):
    """Consolidated audit report."""

    audit_id: str = Field(description="Unique audit identifier")
    target: str = Field(description="Target system path")
    timestamp: str = Field(description="ISO 8601 timestamp")
    scope: str = Field(description="Audit scope used")
    categories_assessed: List[str] = Field(default_factory=list)
    inventory: Optional[SystemInventory] = None
    findings: List[ASIFinding] = Field(default_factory=list)
    compliance: List[ComplianceMapping] = Field(default_factory=list)
    simulations: List[SimulationResult] = Field(default_factory=list)
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    summary: str = ""
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Discovery Phase
# ---------------------------------------------------------------------------


class DiscoveryEngine:
    """Discovers and inventories all components in a multi-agent system."""

    def __init__(self, target_path: str, profiles: Optional[Dict] = None):
        self.target = Path(target_path).resolve()
        self.profiles = profiles or {}
        self.inventory = SystemInventory()

    def run(self) -> SystemInventory:
        """Execute the full discovery phase."""
        logger.info("Phase 1: Discovery - scanning %s", self.target)

        self._discover_agents()
        self._discover_mcp_servers()
        self._discover_services()
        self._discover_credential_refs()
        self._discover_data_stores()
        self._discover_hooks()
        self._discover_trust_boundaries()
        self._discover_communication_channels()

        self.inventory.metrics = {
            "total_agents": len(self.inventory.agents),
            "total_tools": len(self.inventory.tools),
            "total_mcp_servers": len(self.inventory.mcp_servers),
            "total_services": len(self.inventory.services),
            "total_credential_refs": len(self.inventory.credential_refs),
            "total_data_stores": len(self.inventory.data_stores),
            "total_hooks": len(self.inventory.hooks),
            "total_trust_boundaries": len(self.inventory.trust_boundaries),
            "total_communication_channels": len(self.inventory.communication_channels),
            "surface_area": (
                len(self.inventory.agents)
                + len(self.inventory.tools)
                + len(self.inventory.mcp_servers)
                + len(self.inventory.communication_channels)
            ),
        }

        logger.info(
            "Discovery complete: %d agents, %d MCP servers, %d credential refs, surface area=%d",
            self.inventory.metrics["total_agents"],
            self.inventory.metrics["total_mcp_servers"],
            self.inventory.metrics["total_credential_refs"],
            self.inventory.metrics["surface_area"],
        )
        return self.inventory

    # -- Agent discovery --

    def _discover_agents(self) -> None:
        """Find all agent definitions in the target system."""
        patterns = [
            str(self.target / ".claude" / "agents" / "**" / "*.md"),
            str(self.target / ".claude" / "agents" / "**" / "*.json"),
            str(self.target / "TheBaby_Agents" / "sfa_*.py"),
            str(self.target / "TheBaby_Agents" / "**" / "sfa_*.py"),
            str(self.target / "Orchestrator-Agent" / "**" / "*.py"),
            str(self.target / "WhatsApp-Manager-Agent" / "**" / "*.py"),
            # BlindOracle agent patterns
            str(self.target / "config" / "agent_keys" / "*.json"),
            str(self.target / "services" / "**" / "*_agent*.py"),
            str(self.target / "services" / "**" / "agent_*.py"),
            # Generic patterns for external repos
            str(self.target / "agents" / "**" / "*.py"),
            str(self.target / "agents" / "**" / "*.json"),
            str(self.target / "agents" / "**" / "*.md"),
            str(self.target / "**" / "agent_*.py"),
            str(self.target / "**" / "*_agent.py"),
        ]

        seen: Set[str] = set()
        for pattern in patterns:
            for filepath in glob_module.glob(pattern, recursive=True):
                fp = Path(filepath)
                if fp.name.startswith(".") or fp.name.startswith("__"):
                    continue
                rel = str(fp.relative_to(self.target))
                if rel in seen:
                    continue
                seen.add(rel)

                item_type = "agent"
                details: Dict[str, Any] = {"extension": fp.suffix}

                # Try to extract agent name from file
                if fp.suffix == ".md":
                    details["format"] = "markdown_agent_definition"
                    name = fp.stem
                elif fp.suffix == ".py":
                    details["format"] = "python_sfa"
                    name = fp.stem
                else:
                    name = fp.stem

                self.inventory.agents.append(
                    InventoryItem(name=name, path=rel, item_type=item_type, details=details)
                )

        logger.debug("Found %d agents", len(self.inventory.agents))

    # -- MCP server discovery --

    def _discover_mcp_servers(self) -> None:
        """Find all MCP server configurations."""
        patterns = [
            str(self.target / "*-mcp*" / "**" / "pyproject.toml"),
            str(self.target / "*-mcp*" / "**" / "server.py"),
            str(self.target / "*mcp*" / "**" / "pyproject.toml"),
        ]

        seen: Set[str] = set()
        for pattern in patterns:
            for filepath in glob_module.glob(pattern, recursive=True):
                fp = Path(filepath)
                rel = str(fp.relative_to(self.target))
                # Derive server name from parent directory
                parts = rel.split(os.sep)
                server_name = parts[0] if parts else fp.stem
                if server_name in seen:
                    continue
                seen.add(server_name)

                self.inventory.mcp_servers.append(
                    InventoryItem(
                        name=server_name,
                        path=rel,
                        item_type="mcp_server",
                        details={"config_file": fp.name},
                    )
                )

        # Also check .claude settings for MCP server references
        settings_path = self.target / ".claude" / "settings.json"
        if settings_path.exists():
            try:
                with open(settings_path, "r") as f:
                    settings = json.load(f)
                mcp_servers = settings.get("mcpServers", {})
                for name, config in mcp_servers.items():
                    if name not in seen:
                        seen.add(name)
                        self.inventory.mcp_servers.append(
                            InventoryItem(
                                name=name,
                                path=".claude/settings.json",
                                item_type="mcp_server",
                                details={"source": "claude_settings", "config": config},
                            )
                        )
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to parse .claude/settings.json: %s", e)

        logger.debug("Found %d MCP servers", len(self.inventory.mcp_servers))

    # -- Service discovery --

    def _discover_services(self) -> None:
        """Find systemd service definitions."""
        # Check system-level services
        systemd_paths = [
            Path("/etc/systemd/system"),
            self.target / "systemd",
            self.target / ".claude" / "agents" / "team" / "systemd",
        ]

        for svc_dir in systemd_paths:
            if not svc_dir.exists():
                continue
            for svc_file in svc_dir.glob("*.service"):
                self.inventory.services.append(
                    InventoryItem(
                        name=svc_file.stem,
                        path=str(svc_file),
                        item_type="service",
                        details={"type": "systemd"},
                    )
                )

        # Also look for service references in scripts
        cron_patterns = [
            str(self.target / "scripts" / "**" / "*daemon*.py"),
            str(self.target / "scripts" / "**" / "*monitor*.py"),
            str(self.target / "scripts" / "**" / "*scheduler*.py"),
        ]
        for pattern in cron_patterns:
            for filepath in glob_module.glob(pattern, recursive=True):
                fp = Path(filepath)
                self.inventory.services.append(
                    InventoryItem(
                        name=fp.stem,
                        path=str(fp.relative_to(self.target)),
                        item_type="service",
                        details={"type": "python_daemon"},
                    )
                )

        logger.debug("Found %d services", len(self.inventory.services))

    # -- Credential reference discovery --

    def _discover_credential_refs(self) -> None:
        """Find credential and secret references (patterns only, not values)."""
        credential_patterns = [
            r"API_KEY",
            r"SECRET",
            r"TOKEN",
            r"PASSWORD",
            r"PRIVATE_KEY",
            r"CREDENTIAL",
            r"OPENAI_API",
            r"ANTHROPIC_API",
            r"GOOGLE_AI",
        ]
        combined_pattern = re.compile("|".join(credential_patterns), re.IGNORECASE)

        # Check .env files
        env_files = list(self.target.glob("**/.env")) + list(self.target.glob("**/.env.*"))
        for env_file in env_files:
            # Skip node_modules, .git, etc.
            rel = str(env_file.relative_to(self.target))
            if any(skip in rel for skip in ["node_modules", ".git/", "venv/", "__pycache__"]):
                continue
            try:
                with open(env_file, "r", errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key = line.split("=", 1)[0].strip()
                            if combined_pattern.search(key):
                                self.inventory.credential_refs.append(
                                    InventoryItem(
                                        name=key,
                                        path=rel,
                                        item_type="credential_ref",
                                        details={
                                            "line": lineno,
                                            "source": "env_file",
                                            "key_only": True,
                                        },
                                    )
                                )
            except OSError:
                continue

        # Check Python files for os.environ / os.getenv references
        py_files = list(self.target.glob("**/*.py"))
        getenv_pattern = re.compile(
            r"""(?:os\.environ(?:\.get)?\s*\(\s*['"]|os\.getenv\s*\(\s*['"])([A-Z_]+)['"]"""
        )
        seen_keys: Set[str] = set()
        for py_file in py_files:
            rel = str(py_file.relative_to(self.target))
            if any(skip in rel for skip in ["node_modules", ".git/", "venv/", "__pycache__", "site-packages"]):
                continue
            try:
                with open(py_file, "r", errors="replace") as f:
                    content = f.read()
                for match in getenv_pattern.finditer(content):
                    key = match.group(1)
                    if combined_pattern.search(key) and key not in seen_keys:
                        seen_keys.add(key)
                        self.inventory.credential_refs.append(
                            InventoryItem(
                                name=key,
                                path=rel,
                                item_type="credential_ref",
                                details={"source": "python_code", "key_only": True},
                            )
                        )
            except OSError:
                continue

        logger.debug("Found %d credential references", len(self.inventory.credential_refs))

    # -- Data store discovery --

    def _discover_data_stores(self) -> None:
        """Find JSON state files, databases, and memory systems."""
        db_patterns = [
            str(self.target / "**" / "*.db"),
            str(self.target / "**" / "*.sqlite"),
            str(self.target / "**" / "*.sqlite3"),
        ]
        for pattern in db_patterns:
            for filepath in glob_module.glob(pattern, recursive=True):
                fp = Path(filepath)
                rel = str(fp.relative_to(self.target))
                if any(skip in rel for skip in ["node_modules", ".git/", "venv/", "__pycache__"]):
                    continue
                self.inventory.data_stores.append(
                    InventoryItem(
                        name=fp.name,
                        path=rel,
                        item_type="data_store",
                        details={"type": "database", "size_bytes": fp.stat().st_size},
                    )
                )

        # State JSON files in known locations
        state_dirs = [
            self.target / "logs",
            self.target / "CC-Monitor" / "state",
            self.target / "v5_memory",
            self.target / "observability",
        ]
        for state_dir in state_dirs:
            if not state_dir.exists():
                continue
            for json_file in state_dir.glob("**/*.json"):
                rel = str(json_file.relative_to(self.target))
                self.inventory.data_stores.append(
                    InventoryItem(
                        name=json_file.name,
                        path=rel,
                        item_type="data_store",
                        details={"type": "json_state", "size_bytes": json_file.stat().st_size},
                    )
                )

        logger.debug("Found %d data stores", len(self.inventory.data_stores))

    # -- Hook discovery --

    def _discover_hooks(self) -> None:
        """Find Claude Code hook definitions."""
        hook_dirs = [
            self.target / ".claude" / "hooks",
        ]
        for hook_dir in hook_dirs:
            if not hook_dir.exists():
                continue
            for hook_file in hook_dir.rglob("*"):
                if hook_file.is_file():
                    rel = str(hook_file.relative_to(self.target))
                    self.inventory.hooks.append(
                        InventoryItem(
                            name=hook_file.name,
                            path=rel,
                            item_type="hook",
                            details={"extension": hook_file.suffix},
                        )
                    )

        logger.debug("Found %d hooks", len(self.inventory.hooks))

    # -- Trust boundary discovery --

    def _discover_trust_boundaries(self) -> None:
        """Find trust boundary definitions (CaMel layers, RBAC, permissions)."""
        # Look for CaMel layer references
        camel_patterns = [
            str(self.target / "**" / "*camel*"),
            str(self.target / "**" / "*security*"),
            str(self.target / "strategic_platform" / "agents" / "security" / "**" / "*.py"),
        ]
        seen: Set[str] = set()
        for pattern in camel_patterns:
            for filepath in glob_module.glob(pattern, recursive=True):
                fp = Path(filepath)
                if not fp.is_file():
                    continue
                rel = str(fp.relative_to(self.target))
                if rel in seen or any(
                    skip in rel for skip in ["node_modules", ".git/", "venv/", "__pycache__"]
                ):
                    continue
                seen.add(rel)
                self.inventory.trust_boundaries.append(
                    InventoryItem(
                        name=fp.stem,
                        path=rel,
                        item_type="trust_boundary",
                        details={"type": "security_control"},
                    )
                )

        # Check for hook-based trust boundaries
        for hook in self.inventory.hooks:
            if any(kw in hook.name.lower() for kw in ["damage", "validate", "security", "guard"]):
                self.inventory.trust_boundaries.append(
                    InventoryItem(
                        name=f"hook:{hook.name}",
                        path=hook.path,
                        item_type="trust_boundary",
                        details={"type": "hook_guard"},
                    )
                )

        logger.debug("Found %d trust boundaries", len(self.inventory.trust_boundaries))

    # -- Communication channel discovery --

    def _discover_communication_channels(self) -> None:
        """Find inter-agent communication paths."""
        # Look for Task tool usage in agent definitions
        agent_files = [
            self.target / ".claude" / "agents" / "**" / "*.md",
        ]
        for pattern in [str(p) for p in agent_files]:
            for filepath in glob_module.glob(pattern, recursive=True):
                fp = Path(filepath)
                try:
                    with open(fp, "r", errors="replace") as f:
                        content = f.read()
                    if "Task" in content and ("tool" in content.lower() or "agent" in content.lower()):
                        rel = str(fp.relative_to(self.target))
                        self.inventory.communication_channels.append(
                            InventoryItem(
                                name=f"task:{fp.stem}",
                                path=rel,
                                item_type="communication_channel",
                                details={"type": "task_tool", "direction": "outbound"},
                            )
                        )
                except OSError:
                    continue

        # Look for HTTP endpoint patterns in Python files
        http_pattern = re.compile(
            r"""(?:requests\.(?:get|post|put|delete)|httpx\.|aiohttp\.|urllib\.request)"""
        )
        checked_count = 0
        for py_file in self.target.rglob("*.py"):
            rel = str(py_file.relative_to(self.target))
            if any(skip in rel for skip in ["node_modules", ".git/", "venv/", "__pycache__", "site-packages"]):
                continue
            checked_count += 1
            if checked_count > 500:  # Safety limit
                break
            try:
                with open(py_file, "r", errors="replace") as f:
                    content = f.read(10000)  # Read first 10KB
                if http_pattern.search(content):
                    self.inventory.communication_channels.append(
                        InventoryItem(
                            name=f"http:{py_file.stem}",
                            path=rel,
                            item_type="communication_channel",
                            details={"type": "http_client"},
                        )
                    )
            except OSError:
                continue

        logger.debug("Found %d communication channels", len(self.inventory.communication_channels))


# ---------------------------------------------------------------------------
# Vulnerability Assessment Phase
# ---------------------------------------------------------------------------


class VulnerabilityAssessor:
    """Assesses each ASI01-ASI10 category against discovered inventory."""

    def __init__(self, inventory: SystemInventory, target_path: str, categories: Optional[List[str]] = None):
        self.inventory = inventory
        self.target = Path(target_path).resolve()
        self.categories = categories or [c[0] for c in ASI_CATEGORIES]

    def run(self) -> List[ASIFinding]:
        """Execute vulnerability assessment for all requested categories."""
        logger.info("Phase 2: Vulnerability Assessment - %d categories", len(self.categories))
        findings: List[ASIFinding] = []

        assessors = {
            "ASI01": self._assess_goal_hijacking,
            "ASI02": self._assess_tool_misuse,
            "ASI03": self._assess_identity_privilege,
            "ASI04": self._assess_supply_chain,
            "ASI05": self._assess_code_execution,
            "ASI06": self._assess_memory_poisoning,
            "ASI07": self._assess_inter_agent_comms,
            "ASI08": self._assess_cascading_failures,
            "ASI09": self._assess_trust_exploitation,
            "ASI10": self._assess_rogue_agents,
        }

        for cat_id, cat_name, cat_short in ASI_CATEGORIES:
            if cat_id not in self.categories:
                continue
            assessor = assessors.get(cat_id)
            if assessor:
                finding = assessor(cat_id, cat_name)
                findings.append(finding)
                logger.info(
                    "  %s (%s): score=%.1f severity=%s",
                    cat_id,
                    cat_name,
                    finding.risk_score,
                    finding.severity,
                )

        return findings

    def _score_to_severity(self, score: float) -> str:
        """Convert a risk score to severity label."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 1.0:
            return "low"
        return "info"

    def _compute_risk(self, likelihood: int, impact: int) -> float:
        """Compute normalized risk score: (likelihood * impact) / 2.5."""
        raw = likelihood * impact
        return round(min(raw / 2.5, 10.0), 1)

    def _file_contains(self, path: Path, patterns: List[str]) -> List[Tuple[int, str]]:
        """Check if a file contains any of the given patterns. Returns (line_num, line) matches."""
        matches: List[Tuple[int, str]] = []
        try:
            with open(path, "r", errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    for pat in patterns:
                        if pat.lower() in line.lower():
                            matches.append((lineno, line.strip()))
                            break
        except OSError:
            pass
        return matches

    def _search_codebase(self, patterns: List[str], max_files: int = 200) -> List[Evidence]:
        """Search the codebase for patterns and return evidence."""
        evidence: List[Evidence] = []
        count = 0
        for py_file in self.target.rglob("*.py"):
            rel = str(py_file.relative_to(self.target))
            if any(skip in rel for skip in ["node_modules", ".git/", "venv/", "__pycache__", "site-packages"]):
                continue
            count += 1
            if count > max_files:
                break
            matches = self._file_contains(py_file, patterns)
            for lineno, line_text in matches[:3]:  # Max 3 matches per file
                evidence.append(
                    Evidence(
                        file=rel,
                        line=lineno,
                        description=f"Pattern match: {line_text[:120]}",
                    )
                )
        return evidence

    # -- ASI01: Agent Goal Hijacking --

    def _assess_goal_hijacking(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI01: Agent Goal Hijacking via prompt injection."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for input validation / sanitization
        sanitize_evidence = self._search_codebase(
            ["sanitize", "validate_input", "input_validation", "escape_prompt", "instruction_separator"]
        )
        if sanitize_evidence:
            controls_present.append("Input validation/sanitization detected")
            evidence.extend(sanitize_evidence[:3])
        else:
            controls_missing.append("No input sanitization for prompt content")

        # Check for system prompt protection / CaMel layer references
        camel_evidence = self._search_codebase(["camel", "CaMel", "layer_1", "layer_2", "damage_control"])
        if camel_evidence:
            controls_present.append("CaMel security layers detected")
            evidence.extend(camel_evidence[:3])
        else:
            controls_missing.append("No CaMel or prompt protection layers found")

        # Check for hook-based guards
        hook_guards = [
            tb for tb in self.inventory.trust_boundaries if "hook" in tb.details.get("type", "")
        ]
        if hook_guards:
            controls_present.append(f"{len(hook_guards)} hook-based guards detected")
        else:
            controls_missing.append("No hook-based input guards")

        # Check for rigid operational constraints in agent definitions
        constraint_evidence = self._search_codebase(
            ["NEVER", "MUST NOT", "forbidden", "prohibited", "restricted"]
        )
        if constraint_evidence:
            controls_present.append("Rigid operational constraints in agent definitions")

        likelihood = 3 if controls_present else 4
        impact = 4  # Goal hijacking always has high impact in MAS
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="high - affects all downstream agents if orchestrator is hijacked",
            remediation=[
                Remediation(
                    priority=1,
                    action="Implement data/instruction separation in all agent prompts",
                    effort="medium",
                    framework_refs=["OWASP-ASI01", "NIST-MG-2.3"],
                ),
                Remediation(
                    priority=2,
                    action="Add step-by-step alignment validation for multi-hop tasks",
                    effort="high",
                    framework_refs=["OWASP-ASI01", "MAESTRO-T1"],
                ),
            ],
        )

    # -- ASI02: Tool Misuse and Exploitation --

    def _assess_tool_misuse(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI02: Tool Misuse and Exploitation."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for tool usage restrictions / allowlists
        allowlist_evidence = self._search_codebase(
            ["allowed_tools", "tool_whitelist", "tool_allowlist", "permitted_tools", "tool_restriction"]
        )
        if allowlist_evidence:
            controls_present.append("Tool allowlists/restrictions detected")
            evidence.extend(allowlist_evidence[:3])
        else:
            controls_missing.append("No explicit tool allowlists found")

        # Check for tool parameter validation
        param_evidence = self._search_codebase(
            ["validate_params", "parameter_check", "param_validation", "tool_input_schema"]
        )
        if param_evidence:
            controls_present.append("Tool parameter validation detected")
        else:
            controls_missing.append("No tool parameter validation")

        # Check number of tools available (more tools = more attack surface)
        tool_count = len(self.inventory.tools) + len(self.inventory.mcp_servers)
        if tool_count > 15:
            evidence.append(
                Evidence(
                    file="(system-wide)",
                    description=f"Large tool surface area: {tool_count} tools/MCP servers",
                )
            )

        # Check for subprocess/exec usage (dangerous tool patterns)
        exec_evidence = self._search_codebase(
            ["subprocess.run", "subprocess.Popen", "os.system(", "exec(", "eval("]
        )
        if exec_evidence:
            controls_missing.append("Direct subprocess/exec usage detected without sandboxing")
            evidence.extend(exec_evidence[:5])

        likelihood = 3
        impact = 4
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="high - tool misuse can read/write files, execute commands",
            remediation=[
                Remediation(
                    priority=1,
                    action="Implement tool-level authorization with per-agent allowlists",
                    effort="medium",
                    framework_refs=["OWASP-ASI02", "NIST-MG-3.1"],
                ),
                Remediation(
                    priority=2,
                    action="Add output validation for all tool results before consumption",
                    effort="medium",
                    framework_refs=["OWASP-ASI02"],
                ),
            ],
        )

    # -- ASI03: Identity and Privilege Abuse --

    def _assess_identity_privilege(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI03: Identity and Privilege Abuse."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for agent identity/authentication
        auth_evidence = self._search_codebase(
            ["agent_id", "agent_identity", "authenticate_agent", "agent_token", "agent_credentials"]
        )
        if auth_evidence:
            controls_present.append("Agent identity mechanisms detected")
            evidence.extend(auth_evidence[:3])
        else:
            controls_missing.append("No agent-level identity or authentication")

        # Check for role-based access
        rbac_evidence = self._search_codebase(
            ["role_based", "rbac", "permission", "access_control", "privilege_level"]
        )
        if rbac_evidence:
            controls_present.append("Role-based access control references found")
            evidence.extend(rbac_evidence[:2])
        else:
            controls_missing.append("No RBAC or privilege management")

        # Check for least-privilege patterns
        if not rbac_evidence:
            controls_missing.append(
                "Cannot verify least-privilege principle per agent"
            )

        likelihood = 3
        impact = 4
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="high - privilege escalation affects entire agent hierarchy",
            remediation=[
                Remediation(
                    priority=1,
                    action="Implement per-agent identity tokens with cryptographic verification",
                    effort="high",
                    framework_refs=["OWASP-ASI03", "ISO-42001-A.6"],
                ),
                Remediation(
                    priority=2,
                    action="Enforce least-privilege tool access per agent role",
                    effort="medium",
                    framework_refs=["OWASP-ASI03", "NIST-GV-1.2"],
                ),
            ],
        )

    # -- ASI04: Agentic Supply Chain Vulnerabilities --

    def _assess_supply_chain(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI04: Agentic Supply Chain Vulnerabilities."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for dependency lockfiles
        lockfiles = list(self.target.glob("**/requirements.txt")) + \
                    list(self.target.glob("**/uv.lock")) + \
                    list(self.target.glob("**/poetry.lock")) + \
                    list(self.target.glob("**/Pipfile.lock"))
        if lockfiles:
            controls_present.append(f"{len(lockfiles)} dependency lockfiles found")
            for lf in lockfiles[:3]:
                evidence.append(
                    Evidence(
                        file=str(lf.relative_to(self.target)),
                        description="Dependency lockfile present",
                    )
                )
        else:
            controls_missing.append("No dependency lockfiles found")

        # Check for pinned versions in requirements
        req_files = list(self.target.glob("**/requirements*.txt"))
        unpinned_count = 0
        for req_file in req_files[:10]:
            try:
                with open(req_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "==" not in line and ">=" in line:
                            unpinned_count += 1
            except OSError:
                continue
        if unpinned_count > 0:
            controls_missing.append(f"{unpinned_count} unpinned dependencies (>= instead of ==)")
        else:
            controls_present.append("Dependencies appear to use pinned versions")

        # Check for signature verification / integrity checks
        integrity_evidence = self._search_codebase(
            ["verify_signature", "checksum", "integrity_check", "package_hash"]
        )
        if integrity_evidence:
            controls_present.append("Package integrity verification detected")
        else:
            controls_missing.append("No package signature or integrity verification")

        # Count third-party MCP servers
        mcp_count = len(self.inventory.mcp_servers)
        if mcp_count > 5:
            evidence.append(
                Evidence(
                    file="(system-wide)",
                    description=f"{mcp_count} MCP servers = large supply chain surface",
                )
            )

        likelihood = 3
        impact = 3
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="medium - compromised dependency affects all users",
            remediation=[
                Remediation(
                    priority=1,
                    action="Pin all dependency versions with hash verification",
                    effort="low",
                    framework_refs=["OWASP-ASI04", "NIST-MP-4.1"],
                ),
                Remediation(
                    priority=2,
                    action="Implement MCP server allowlist and version pinning",
                    effort="medium",
                    framework_refs=["OWASP-ASI04"],
                ),
            ],
        )

    # -- ASI05: Unexpected Code Execution --

    def _assess_code_execution(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI05: Unexpected Code Execution."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for sandbox/container usage
        sandbox_evidence = self._search_codebase(
            ["sandbox", "container", "docker", "isolation", "chroot", "seccomp", "nsjail"]
        )
        if sandbox_evidence:
            controls_present.append("Sandboxing/containerization references found")
            evidence.extend(sandbox_evidence[:3])
        else:
            controls_missing.append("No sandboxing or code isolation detected")

        # Check for dangerous code execution patterns
        dangerous_patterns = ["exec(", "eval(", "compile(", "__import__(", "importlib.import_module"]
        danger_evidence = self._search_codebase(dangerous_patterns)
        if danger_evidence:
            controls_missing.append(f"Dangerous code execution patterns found ({len(danger_evidence)} instances)")
            evidence.extend(danger_evidence[:5])

        # Check for subprocess usage without shell=False
        shell_evidence = self._search_codebase(["shell=True"])
        if shell_evidence:
            controls_missing.append("subprocess with shell=True detected")
            evidence.extend(shell_evidence[:3])

        # Check for code generation patterns
        codegen_evidence = self._search_codebase(
            ["generate_code", "code_generation", "write_code", "create_script"]
        )
        if codegen_evidence:
            evidence.append(
                Evidence(
                    file="(system-wide)",
                    description=f"Code generation capabilities detected in {len(codegen_evidence)} files",
                )
            )

        likelihood = 3
        impact = 5  # Code execution = maximum impact
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="critical - arbitrary code execution compromises entire system",
            remediation=[
                Remediation(
                    priority=1,
                    action="Run all agent-generated code in sandboxed environments",
                    effort="high",
                    framework_refs=["OWASP-ASI05", "NIST-MG-3.2"],
                ),
                Remediation(
                    priority=1,
                    action="Remove all eval()/exec() usage or replace with safe alternatives",
                    effort="medium",
                    framework_refs=["OWASP-ASI05"],
                ),
            ],
        )

    # -- ASI06: Memory and Context Poisoning --

    def _assess_memory_poisoning(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI06: Memory and Context Poisoning."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for memory/context management
        memory_evidence = self._search_codebase(
            ["memory_store", "context_window", "conversation_history", "memory_manager", "v5_memory"]
        )
        if memory_evidence:
            evidence.extend(memory_evidence[:3])
            controls_present.append("Memory management system detected")

        # Check for memory validation
        mem_validation = self._search_codebase(
            ["validate_memory", "memory_integrity", "context_validation", "memory_sanitize"]
        )
        if mem_validation:
            controls_present.append("Memory validation mechanisms detected")
        else:
            controls_missing.append("No memory content validation or sanitization")

        # Check for cross-session isolation
        session_evidence = self._search_codebase(
            ["session_id", "session_isolation", "tenant_isolation", "session_boundary"]
        )
        if session_evidence:
            controls_present.append("Session/tenant isolation detected")
        else:
            controls_missing.append("No cross-session isolation mechanisms")

        # Check for memory persistence (shared state files)
        persistent_stores = [
            ds for ds in self.inventory.data_stores if ds.details.get("type") == "json_state"
        ]
        if len(persistent_stores) > 10:
            evidence.append(
                Evidence(
                    file="(system-wide)",
                    description=f"{len(persistent_stores)} persistent state files - potential poisoning vectors",
                )
            )

        likelihood = 3
        impact = 4
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="high - poisoned memory affects all future decisions",
            remediation=[
                Remediation(
                    priority=1,
                    action="Add content validation for all memory writes",
                    effort="medium",
                    framework_refs=["OWASP-ASI06", "NIST-MS-2.7"],
                ),
                Remediation(
                    priority=2,
                    action="Implement cross-session memory isolation boundaries",
                    effort="high",
                    framework_refs=["OWASP-ASI06"],
                ),
            ],
        )

    # -- ASI07: Insecure Inter-Agent Communication --

    def _assess_inter_agent_comms(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI07: Insecure Inter-Agent Communication."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for message signing / verification
        signing_evidence = self._search_codebase(
            ["message_sign", "verify_message", "hmac", "message_auth", "digital_signature"]
        )
        if signing_evidence:
            controls_present.append("Message authentication detected")
            evidence.extend(signing_evidence[:2])
        else:
            controls_missing.append("No inter-agent message authentication")

        # Check for encrypted communication
        encryption_evidence = self._search_codebase(
            ["encrypt_message", "tls", "ssl_context", "https://localhost", "message_encrypt"]
        )
        if encryption_evidence:
            controls_present.append("Encryption references found")
        else:
            controls_missing.append("No encryption for inter-agent communication")

        # Check for message schema validation
        schema_evidence = self._search_codebase(
            ["message_schema", "validate_message", "message_format", "protocol_buffer"]
        )
        if schema_evidence:
            controls_present.append("Message schema validation detected")
        else:
            controls_missing.append("No structured message schema validation")

        # Count inter-agent communication channels
        comms_count = len(self.inventory.communication_channels)
        evidence.append(
            Evidence(
                file="(system-wide)",
                description=f"{comms_count} inter-agent communication channels discovered",
            )
        )

        likelihood = 3
        impact = 3
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="medium - compromised messages can redirect agent behavior",
            remediation=[
                Remediation(
                    priority=1,
                    action="Implement message signing with per-agent keys",
                    effort="high",
                    framework_refs=["OWASP-ASI07", "NIST-MG-4.1"],
                ),
                Remediation(
                    priority=2,
                    action="Add structured message schemas with validation",
                    effort="medium",
                    framework_refs=["OWASP-ASI07"],
                ),
            ],
        )

    # -- ASI08: Cascading Failures --

    def _assess_cascading_failures(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI08: Cascading Failures."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for circuit breakers / retry logic
        circuit_evidence = self._search_codebase(
            ["circuit_breaker", "retry", "backoff", "exponential_backoff", "fallback", "timeout"]
        )
        if circuit_evidence:
            controls_present.append("Retry/backoff/timeout mechanisms detected")
            evidence.extend(circuit_evidence[:3])
        else:
            controls_missing.append("No circuit breakers or retry mechanisms")

        # Check for health monitoring
        health_evidence = self._search_codebase(
            ["health_check", "heartbeat", "monitoring", "health_status", "liveness"]
        )
        if health_evidence:
            controls_present.append("Health monitoring detected")
        else:
            controls_missing.append("No health monitoring for agent dependencies")

        # Check for graceful degradation
        graceful_evidence = self._search_codebase(
            ["graceful_degradation", "fallback_provider", "failover", "degraded_mode"]
        )
        if graceful_evidence:
            controls_present.append("Graceful degradation patterns found")
        else:
            controls_missing.append("No graceful degradation strategy")

        # Check dependency depth
        total_deps = len(self.inventory.mcp_servers) + len(self.inventory.services)
        if total_deps > 10:
            evidence.append(
                Evidence(
                    file="(system-wide)",
                    description=f"{total_deps} external dependencies = high cascade risk",
                )
            )

        likelihood = 3
        impact = 3
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="medium - single point failures can take down multiple agents",
            remediation=[
                Remediation(
                    priority=1,
                    action="Implement circuit breakers for all external dependencies",
                    effort="medium",
                    framework_refs=["OWASP-ASI08", "NIST-MG-4.2"],
                ),
                Remediation(
                    priority=2,
                    action="Add dependency health dashboards with automatic failover",
                    effort="high",
                    framework_refs=["OWASP-ASI08"],
                ),
            ],
        )

    # -- ASI09: Human-Agent Trust Exploitation --

    def _assess_trust_exploitation(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI09: Human-Agent Trust Exploitation."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for human-in-the-loop controls
        hitl_evidence = self._search_codebase(
            ["human_in_the_loop", "approval_required", "confirm_action", "human_approval", "user_confirm"]
        )
        if hitl_evidence:
            controls_present.append("Human-in-the-loop approval mechanisms detected")
            evidence.extend(hitl_evidence[:3])
        else:
            controls_missing.append("No human-in-the-loop approval gates")

        # Check for confidence scoring / uncertainty disclosure
        confidence_evidence = self._search_codebase(
            ["confidence_score", "uncertainty", "confidence_level", "certainty_threshold"]
        )
        if confidence_evidence:
            controls_present.append("Confidence/uncertainty scoring detected")
        else:
            controls_missing.append("No confidence scoring or uncertainty disclosure")

        # Check for action audit trails
        audit_evidence = self._search_codebase(
            ["audit_trail", "action_log", "audit_log", "decision_log"]
        )
        if audit_evidence:
            controls_present.append("Audit trail logging detected")
        else:
            controls_missing.append("No action audit trails for human review")

        # Check for anti-social-engineering patterns
        anti_se_evidence = self._search_codebase(
            ["anti_persuasion", "social_engineering", "manipulation_detection"]
        )
        if anti_se_evidence:
            controls_present.append("Anti-persuasion/social engineering defenses detected")

        likelihood = 2
        impact = 4
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="high - trusted agents can manipulate human decisions",
            remediation=[
                Remediation(
                    priority=1,
                    action="Add confidence scoring to all agent outputs shown to humans",
                    effort="medium",
                    framework_refs=["OWASP-ASI09", "NIST-MS-2.5"],
                ),
                Remediation(
                    priority=2,
                    action="Implement action audit trails with human review dashboard",
                    effort="medium",
                    framework_refs=["OWASP-ASI09"],
                ),
            ],
        )

    # -- ASI10: Rogue Agents --

    def _assess_rogue_agents(self, cat_id: str, cat_name: str) -> ASIFinding:
        """Assess ASI10: Rogue Agents."""
        controls_present: List[str] = []
        controls_missing: List[str] = []
        evidence: List[Evidence] = []

        # Check for agent monitoring / behavioral analysis
        monitor_evidence = self._search_codebase(
            ["agent_monitor", "behavioral_analysis", "anomaly_detection", "agent_watchdog"]
        )
        if monitor_evidence:
            controls_present.append("Agent monitoring/anomaly detection detected")
            evidence.extend(monitor_evidence[:3])
        else:
            controls_missing.append("No agent behavioral monitoring")

        # Check for kill switches / emergency shutdown
        kill_evidence = self._search_codebase(
            ["kill_switch", "emergency_stop", "shutdown", "terminate_agent", "circuit_break"]
        )
        if kill_evidence:
            controls_present.append("Emergency shutdown mechanisms detected")
            evidence.extend(kill_evidence[:2])
        else:
            controls_missing.append("No kill switch or emergency shutdown capability")

        # Check for self-modification protections
        self_mod_evidence = self._search_codebase(
            ["self_modify", "self_replicate", "auto_update", "self_improve"]
        )
        if self_mod_evidence:
            controls_missing.append("Self-modification capabilities detected")
            evidence.extend(self_mod_evidence[:3])

        # Check for Byzantine consensus / multi-agent validation
        byzantine_evidence = self._search_codebase(
            ["byzantine", "consensus", "multi_agent_validation", "vote", "quorum"]
        )
        if byzantine_evidence:
            controls_present.append("Byzantine consensus / multi-agent validation detected")
        else:
            controls_missing.append("No multi-agent validation for critical actions")

        # Count total agents (more agents = more rogue risk)
        total_agents = len(self.inventory.agents)
        evidence.append(
            Evidence(
                file="(system-wide)",
                description=f"{total_agents} agents in system - rogue detection scope",
            )
        )

        likelihood = 2
        impact = 5  # Rogue agent = maximum impact
        risk = self._compute_risk(likelihood, impact)

        return ASIFinding(
            category=cat_id,
            name=cat_name,
            risk_score=risk,
            severity=self._score_to_severity(risk),
            likelihood=likelihood,
            impact=impact,
            controls_present=controls_present,
            controls_missing=controls_missing,
            evidence=evidence,
            blast_radius="critical - rogue agents can subvert the entire system",
            remediation=[
                Remediation(
                    priority=1,
                    action="Implement behavioral monitoring with anomaly detection for all agents",
                    effort="high",
                    framework_refs=["OWASP-ASI10", "NIST-MG-4.3"],
                ),
                Remediation(
                    priority=1,
                    action="Deploy kill switches with human-only activation for all agents",
                    effort="medium",
                    framework_refs=["OWASP-ASI10", "MAESTRO-T8"],
                ),
            ],
        )


# ---------------------------------------------------------------------------
# Compliance Mapping Phase
# ---------------------------------------------------------------------------


class ComplianceMapper:
    """Maps vulnerability findings to compliance frameworks."""

    # Framework control counts (simplified for automated mapping)
    FRAMEWORK_TOTALS = {
        "OWASP_Agentic_Top10": 10,
        "NIST_AI_RMF": 20,
        "ISO_42001": 15,
        "CSA_AICM": 18,
        "MAESTRO": 10,
    }

    FRAMEWORK_NAMES = {
        "OWASP_Agentic_Top10": "OWASP Top 10 for Agentic Applications",
        "NIST_AI_RMF": "NIST AI Risk Management Framework",
        "ISO_42001": "ISO/IEC 42001 AI Management Systems",
        "CSA_AICM": "CSA AI Controls Matrix",
        "MAESTRO": "MAESTRO Agentic AI Threat Modelling",
    }

    def __init__(self, findings: List[ASIFinding]):
        self.findings = findings

    def run(self) -> List[ComplianceMapping]:
        """Map findings to compliance frameworks."""
        logger.info("Phase 2b: Compliance Mapping")
        mappings: List[ComplianceMapping] = []

        for fw_id, total in self.FRAMEWORK_TOTALS.items():
            covered = self._calculate_coverage(fw_id, total)
            gaps = self._identify_gaps(fw_id)
            pct = round((covered / total) * 100, 1) if total > 0 else 0.0

            mapping = ComplianceMapping(
                framework_id=fw_id,
                framework_name=self.FRAMEWORK_NAMES[fw_id],
                covered=covered,
                total=total,
                percentage=pct,
                gaps=gaps,
            )
            mappings.append(mapping)
            logger.info("  %s: %d/%d (%.1f%%)", fw_id, covered, total, pct)

        return mappings

    def _calculate_coverage(self, framework_id: str, total: int) -> int:
        """Calculate how many framework controls are covered by existing findings."""
        # For OWASP, direct 1:1 mapping with ASI categories
        if framework_id == "OWASP_Agentic_Top10":
            covered = 0
            for finding in self.findings:
                # A category is "covered" if it has controls present
                if finding.controls_present:
                    covered += 1
            return covered

        # For other frameworks, estimate coverage based on controls present
        # Each finding with controls maps to approximately (total / 10) framework controls
        total_controls_present = sum(len(f.controls_present) for f in self.findings)
        estimated = min(int(total_controls_present * total / 20), total)
        return estimated

    def _identify_gaps(self, framework_id: str) -> List[str]:
        """Identify compliance gaps for a framework."""
        gaps: List[str] = []

        if framework_id == "OWASP_Agentic_Top10":
            for finding in self.findings:
                if not finding.controls_present:
                    gaps.append(f"{finding.category}: No controls for {finding.name}")
                elif finding.controls_missing:
                    gaps.append(
                        f"{finding.category}: Missing {len(finding.controls_missing)} controls"
                    )
        elif framework_id == "NIST_AI_RMF":
            # Map to NIST categories
            nist_gaps = {
                "Govern": "Organizational governance for AI risk",
                "Map": "Context and risk mapping",
                "Measure": "Risk measurement and monitoring",
                "Manage": "Risk management and remediation",
            }
            high_risk = [f for f in self.findings if f.risk_score >= 7.0]
            if high_risk:
                gaps.append(f"Govern: {len(high_risk)} high-risk categories require governance review")
            missing_monitoring = [
                f for f in self.findings
                if not any("monitor" in c.lower() for c in f.controls_present)
            ]
            if missing_monitoring:
                gaps.append(f"Measure: {len(missing_monitoring)} categories lack monitoring controls")
        elif framework_id == "ISO_42001":
            missing_audit = [
                f for f in self.findings if not any("audit" in c.lower() for c in f.controls_present)
            ]
            if missing_audit:
                gaps.append(f"A.6: {len(missing_audit)} areas lack audit controls")
        elif framework_id == "CSA_AICM":
            for finding in self.findings:
                if finding.severity in ("critical", "high"):
                    gaps.append(f"Domain gap: {finding.category} - {finding.name} ({finding.severity})")
        elif framework_id == "MAESTRO":
            for finding in self.findings:
                if finding.risk_score >= 6.0:
                    gaps.append(f"Threat: {finding.category} score={finding.risk_score}")

        return gaps


# ---------------------------------------------------------------------------
# Red Team Simulation Phase
# ---------------------------------------------------------------------------


class RedTeamSimulator:
    """Simulates attack scenarios (read-only theoretical analysis)."""

    def __init__(self, inventory: SystemInventory, findings: List[ASIFinding]):
        self.inventory = inventory
        self.findings = findings

    def run(self) -> List[SimulationResult]:
        """Execute red team simulations for each ASI category."""
        logger.info("Phase 3: Red Team Simulation (theoretical analysis)")
        simulations: List[SimulationResult] = []

        scenarios = [
            self._simulate_prompt_injection,
            self._simulate_tool_chain_abuse,
            self._simulate_privilege_escalation,
            self._simulate_supply_chain_attack,
            self._simulate_code_injection,
            self._simulate_memory_poisoning,
            self._simulate_comm_interception,
            self._simulate_cascade_failure,
            self._simulate_trust_manipulation,
            self._simulate_rogue_agent,
        ]

        for scenario_fn in scenarios:
            result = scenario_fn()
            simulations.append(result)
            logger.info("  Scenario: %s - likelihood: %s", result.scenario, result.success_likelihood)

        return simulations

    def _get_finding(self, category: str) -> Optional[ASIFinding]:
        """Get finding for a specific ASI category."""
        for f in self.findings:
            if f.category == category:
                return f
        return None

    def _simulate_prompt_injection(self) -> SimulationResult:
        """ASI01: Indirect prompt injection via data payload."""
        finding = self._get_finding("ASI01")
        defenses = finding.controls_present if finding else []
        has_camel = any("camel" in d.lower() for d in defenses)

        return SimulationResult(
            scenario="ASI01-indirect-prompt-injection",
            attack_vector="Malicious instructions embedded in RAG documents or user-supplied data",
            target_agent="orchestrator / research agents",
            success_likelihood="medium" if has_camel else "high",
            existing_defenses=defenses,
            defense_bypass_path="RAG content may bypass Layer 1 filtering if not scanned pre-ingestion"
            if has_camel
            else "No prompt protection layers to bypass",
            recommendation="Add pre-ingestion content scanning and instruction/data separation markers",
        )

    def _simulate_tool_chain_abuse(self) -> SimulationResult:
        """ASI02: Tool chain sequences achieving unintended outcomes."""
        tool_count = len(self.inventory.mcp_servers) + len(self.inventory.tools)
        return SimulationResult(
            scenario="ASI02-tool-chain-abuse",
            attack_vector=f"Chaining {tool_count} available tools in unintended sequences (e.g., Read -> Write -> Bash)",
            target_agent="any agent with multiple tool access",
            success_likelihood="high" if tool_count > 10 else "medium",
            existing_defenses=["Claude Code sandbox"] if tool_count > 0 else [],
            defense_bypass_path="Multi-step tool chains can achieve filesystem writes + code execution",
            recommendation="Implement tool-chain validation rules and sequence allowlists",
        )

    def _simulate_privilege_escalation(self) -> SimulationResult:
        """ASI03: Agent identity spoofing for privilege escalation."""
        return SimulationResult(
            scenario="ASI03-privilege-escalation",
            attack_vector="Agent impersonation via forged Task tool prompts claiming elevated permissions",
            target_agent="security-orchestrator / root orchestrator",
            success_likelihood="medium",
            existing_defenses=["Agent definitions in .claude/agents/ are read-only"],
            defense_bypass_path="Sub-agents spawned via Task tool inherit parent context without identity verification",
            recommendation="Implement cryptographic agent identity tokens passed through Task tool chains",
        )

    def _simulate_supply_chain_attack(self) -> SimulationResult:
        """ASI04: Compromised dependency injection."""
        mcp_count = len(self.inventory.mcp_servers)
        return SimulationResult(
            scenario="ASI04-compromised-dependency",
            attack_vector=f"Typosquatting or compromising one of {mcp_count} MCP server dependencies",
            target_agent="system-wide via dependency chain",
            success_likelihood="low",
            existing_defenses=["UV lockfiles", "pip freeze"],
            defense_bypass_path="MCP servers may pull unverified packages at runtime",
            recommendation="Implement SBOM generation and dependency hash verification for all MCP servers",
        )

    def _simulate_code_injection(self) -> SimulationResult:
        """ASI05: Injecting executable code through agent outputs."""
        return SimulationResult(
            scenario="ASI05-code-injection",
            attack_vector="Crafting agent output that triggers eval()/exec() in downstream processing",
            target_agent="any agent processing untrusted text",
            success_likelihood="medium",
            existing_defenses=["Python type safety", "Pydantic validation"],
            defense_bypass_path="String-based tool outputs may be passed to eval() or shell commands",
            recommendation="Eliminate all eval()/exec() usage; run agent-generated code in isolated containers",
        )

    def _simulate_memory_poisoning(self) -> SimulationResult:
        """ASI06: Cross-session memory poisoning."""
        store_count = len(self.inventory.data_stores)
        return SimulationResult(
            scenario="ASI06-memory-poisoning",
            attack_vector=f"Injecting malicious content into {store_count} persistent state files",
            target_agent="any agent reading shared memory/state",
            success_likelihood="medium",
            existing_defenses=["File system permissions"],
            defense_bypass_path="Agents with Write tool access can modify shared state files directly",
            recommendation="Implement memory integrity verification and per-agent write scoping",
        )

    def _simulate_comm_interception(self) -> SimulationResult:
        """ASI07: Intercepting inter-agent messages."""
        comms_count = len(self.inventory.communication_channels)
        return SimulationResult(
            scenario="ASI07-message-interception",
            attack_vector=f"Intercepting or modifying messages on {comms_count} communication channels",
            target_agent="Task tool chains between agents",
            success_likelihood="low",
            existing_defenses=["Local process communication", "No network exposure for Task tool"],
            defense_bypass_path="HTTP-based inter-agent communication (port 5173 etc.) may be unencrypted",
            recommendation="Add message signing for all inter-agent HTTP communication",
        )

    def _simulate_cascade_failure(self) -> SimulationResult:
        """ASI08: Triggering cascading failure through dependency chain."""
        svc_count = len(self.inventory.services)
        return SimulationResult(
            scenario="ASI08-cascade-trigger",
            attack_vector=f"Overloading a critical dependency to trigger cascade across {svc_count} services",
            target_agent="LLM API provider / critical MCP server",
            success_likelihood="medium",
            existing_defenses=["Systemd auto-restart", "Multi-provider routing"],
            defense_bypass_path="Simultaneous failure of multiple LLM providers not handled gracefully",
            recommendation="Implement circuit breakers with automatic degradation per dependency",
        )

    def _simulate_trust_manipulation(self) -> SimulationResult:
        """ASI09: Manipulating human trust through confident but wrong outputs."""
        return SimulationResult(
            scenario="ASI09-trust-manipulation",
            attack_vector="Agent produces highly confident but incorrect recommendations to influence human decisions",
            target_agent="research / analysis agents presenting to user",
            success_likelihood="medium",
            existing_defenses=["Multi-agent debate system", "Fact checker agent"],
            defense_bypass_path="Single-agent outputs may bypass debate system in quick-response scenarios",
            recommendation="Require confidence scoring and source attribution on all human-facing outputs",
        )

    def _simulate_rogue_agent(self) -> SimulationResult:
        """ASI10: Agent self-modification and shutdown resistance."""
        agent_count = len(self.inventory.agents)
        return SimulationResult(
            scenario="ASI10-rogue-agent-persistence",
            attack_vector=f"One of {agent_count} agents modifies its own definition to remove safety constraints",
            target_agent="any agent with Write tool access to .claude/agents/",
            success_likelihood="low",
            existing_defenses=["Git version control", "Agent definitions in repo"],
            defense_bypass_path="Write tool can modify agent .md files; changes persist until git reset",
            recommendation="Make agent definitions read-only at filesystem level; monitor for unauthorized changes",
        )


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Generates JSON reports and HTML dashboards."""

    def __init__(self, report: AuditReport, audit_dir: Path):
        self.report = report
        self.audit_dir = audit_dir

    def save_json_report(self) -> Path:
        """Save the consolidated JSON report."""
        report_path = self.audit_dir / "report.json"
        with open(report_path, "w") as f:
            json.dump(self.report.model_dump(), f, indent=2, default=str)
        logger.info("Saved JSON report to %s", report_path)
        return report_path

    def save_findings(self) -> None:
        """Save individual finding files per ASI category."""
        findings_dir = self.audit_dir / "findings"
        findings_dir.mkdir(exist_ok=True)
        for finding in self.report.findings:
            cat_short = "unknown"
            for cat_id, cat_name, short in ASI_CATEGORIES:
                if cat_id == finding.category:
                    cat_short = short
                    break
            filename = f"{finding.category}-{cat_short}.json"
            filepath = findings_dir / filename
            with open(filepath, "w") as f:
                json.dump(finding.model_dump(), f, indent=2, default=str)

    def save_inventory(self) -> None:
        """Save the system inventory."""
        if self.report.inventory:
            inv_path = self.audit_dir / "inventory.json"
            with open(inv_path, "w") as f:
                json.dump(self.report.inventory.model_dump(), f, indent=2, default=str)

    def save_compliance_map(self) -> None:
        """Save the compliance mapping."""
        if self.report.compliance:
            comp_path = self.audit_dir / "compliance_map.json"
            data = [c.model_dump() for c in self.report.compliance]
            with open(comp_path, "w") as f:
                json.dump(data, f, indent=2, default=str)

    def save_simulations(self) -> None:
        """Save red team simulation results."""
        if self.report.simulations:
            sim_path = self.audit_dir / "simulations.json"
            data = [s.model_dump() for s in self.report.simulations]
            with open(sim_path, "w") as f:
                json.dump(data, f, indent=2, default=str)

    def generate_dashboard(self) -> Path:
        """Generate the HTML dashboard from the template."""
        template_path = TEMPLATE_PATH
        if not template_path.exists():
            logger.error("Dashboard template not found at %s", template_path)
            return self._generate_fallback_dashboard()

        try:
            with open(template_path, "r") as f:
                html = f.read()
        except OSError as e:
            logger.error("Failed to read template: %s", e)
            return self._generate_fallback_dashboard()

        # Replace all template tokens
        html = self._replace_tokens(html)

        # Save to audit directory
        dashboard_path = self.audit_dir / "dashboard.html"
        with open(dashboard_path, "w") as f:
            f.write(html)

        # Also save to html-output
        HTML_OUTPUT_DIR.mkdir(exist_ok=True)
        target_name = Path(self.report.target).name or "system"
        date_str = datetime.now().strftime("%Y%m%d")
        html_output_path = HTML_OUTPUT_DIR / f"{date_str}-security-audit-{target_name}.html"
        with open(html_output_path, "w") as f:
            f.write(html)

        logger.info("Saved dashboard to %s", dashboard_path)
        logger.info("Saved dashboard copy to %s", html_output_path)
        return dashboard_path

    def _replace_tokens(self, html: str) -> str:
        """Replace all {{TOKEN}} placeholders in the template."""
        replacements = {
            "{{AUDIT_ID}}": self.report.audit_id,
            "{{TARGET}}": self.report.target,
            "{{DATE}}": self.report.timestamp,
            "{{OVERALL_RISK_SCORE}}": f"{self.report.overall_risk_score:.1f}",
            "{{SCOPE}}": self.report.scope,
            "{{DURATION}}": f"{self.report.duration_seconds:.1f}s",
            "{{SUMMARY}}": self.report.summary,
            "{{TOTAL_AGENTS}}": str(self.report.inventory.metrics.get("total_agents", 0) if self.report.inventory else 0),
            "{{TOTAL_TOOLS}}": str(self.report.inventory.metrics.get("total_mcp_servers", 0) if self.report.inventory else 0),
            "{{TOTAL_FINDINGS}}": str(len(self.report.findings)),
            "{{CRITICAL_COUNT}}": str(sum(1 for f in self.report.findings if f.severity == "critical")),
            "{{HIGH_COUNT}}": str(sum(1 for f in self.report.findings if f.severity == "high")),
            "{{MEDIUM_COUNT}}": str(sum(1 for f in self.report.findings if f.severity == "medium")),
            "{{LOW_COUNT}}": str(sum(1 for f in self.report.findings if f.severity == "low")),
        }

        # ASI scores
        for cat_id, _, _ in ASI_CATEGORIES:
            finding = next((f for f in self.report.findings if f.category == cat_id), None)
            score = finding.risk_score if finding else 0.0
            severity = finding.severity if finding else "info"
            color = SEVERITY_COLORS.get(severity, "#2196f3")
            replacements[f"{{{{{cat_id}_SCORE}}}}"] = f"{score:.1f}"
            replacements[f"{{{{{cat_id}_COLOR}}}}"] = color
            replacements[f"{{{{{cat_id}_SEVERITY}}}}"] = severity

        # Compliance percentages
        compliance_map = {c.framework_id: c for c in self.report.compliance}
        for fw_id, short_name in [
            ("OWASP_Agentic_Top10", "OWASP"),
            ("NIST_AI_RMF", "NIST"),
            ("ISO_42001", "ISO"),
            ("CSA_AICM", "CSA"),
            ("MAESTRO", "MAESTRO"),
        ]:
            mapping = compliance_map.get(fw_id)
            pct = mapping.percentage if mapping else 0.0
            replacements[f"{{{{{short_name}_PCT}}}}"] = f"{pct:.0f}"

        # Generate findings table rows
        replacements["{{FINDINGS_TABLE_ROWS}}"] = self._generate_findings_table()

        # Generate simulation cards
        replacements["{{SIMULATION_CARDS}}"] = self._generate_simulation_cards()

        # Generate agent inventory table
        replacements["{{AGENT_INVENTORY_TABLE}}"] = self._generate_agent_inventory()

        # Generate remediation table
        replacements["{{REMEDIATION_TABLE}}"] = self._generate_remediation_table()

        # Generate trust boundary visual
        replacements["{{TRUST_BOUNDARY_VISUAL}}"] = self._generate_trust_boundary_visual()

        for token, value in replacements.items():
            html = html.replace(token, value)

        return html

    def _generate_findings_table(self) -> str:
        """Generate HTML table rows for critical/high findings."""
        rows = []
        sorted_findings = sorted(self.report.findings, key=lambda f: f.risk_score, reverse=True)
        for finding in sorted_findings:
            color = SEVERITY_COLORS.get(finding.severity, "#2196f3")
            evidence_str = "; ".join(
                f"{e.file}:{e.line}" if e.line else e.file for e in finding.evidence[:3]
            )
            missing_str = ", ".join(finding.controls_missing[:3])
            rows.append(
                f'<tr>'
                f'<td><span class="severity-badge" style="background:{color}">{finding.severity.upper()}</span></td>'
                f'<td>{finding.category}</td>'
                f'<td>{finding.name}</td>'
                f'<td class="score">{finding.risk_score:.1f}</td>'
                f'<td>{missing_str or "None"}</td>'
                f'<td class="evidence">{evidence_str or "N/A"}</td>'
                f'</tr>'
            )
        return "\n".join(rows)

    def _generate_simulation_cards(self) -> str:
        """Generate HTML cards for red team simulations."""
        cards = []
        for sim in self.report.simulations:
            likelihood_color = {
                "high": "#f44336",
                "medium": "#ff9800",
                "low": "#4caf50",
            }.get(sim.success_likelihood, "#2196f3")
            defenses = ", ".join(sim.existing_defenses) if sim.existing_defenses else "None detected"
            cards.append(
                f'<div class="sim-card">'
                f'<div class="sim-header">'
                f'<span class="sim-scenario">{sim.scenario}</span>'
                f'<span class="sim-likelihood" style="color:{likelihood_color}">{sim.success_likelihood.upper()}</span>'
                f'</div>'
                f'<div class="sim-body">'
                f'<p><strong>Attack Vector:</strong> {sim.attack_vector}</p>'
                f'<p><strong>Target:</strong> {sim.target_agent}</p>'
                f'<p><strong>Defenses:</strong> {defenses}</p>'
                f'<p><strong>Bypass Path:</strong> {sim.defense_bypass_path}</p>'
                f'<p><strong>Recommendation:</strong> {sim.recommendation}</p>'
                f'</div>'
                f'</div>'
            )
        return "\n".join(cards)

    def _generate_agent_inventory(self) -> str:
        """Generate HTML table for agent inventory."""
        if not self.report.inventory:
            return "<tr><td colspan='4'>No inventory data</td></tr>"
        rows = []
        for agent in self.report.inventory.agents[:30]:  # Limit to 30
            agent_type = agent.details.get("format", "unknown")
            rows.append(
                f'<tr>'
                f'<td>{agent.name}</td>'
                f'<td>{agent.path}</td>'
                f'<td>{agent_type}</td>'
                f'<td>{agent.item_type}</td>'
                f'</tr>'
            )
        return "\n".join(rows)

    def _generate_remediation_table(self) -> str:
        """Generate HTML table for prioritized remediation."""
        rows = []
        all_remediations: List[Tuple[str, Remediation]] = []
        for finding in self.report.findings:
            for rem in finding.remediation:
                all_remediations.append((finding.category, rem))

        # Sort by priority
        all_remediations.sort(key=lambda x: x[1].priority)

        for cat_id, rem in all_remediations:
            effort_color = {"low": "#4caf50", "medium": "#ff9800", "high": "#f44336"}.get(
                rem.effort, "#2196f3"
            )
            refs = ", ".join(rem.framework_refs) if rem.framework_refs else "N/A"
            rows.append(
                f'<tr>'
                f'<td>P{rem.priority}</td>'
                f'<td>{cat_id}</td>'
                f'<td>{rem.action}</td>'
                f'<td><span style="color:{effort_color}">{rem.effort.upper()}</span></td>'
                f'<td>{refs}</td>'
                f'</tr>'
            )
        return "\n".join(rows)

    def _generate_trust_boundary_visual(self) -> str:
        """Generate HTML for trust boundary visualization."""
        if not self.report.inventory:
            return "<p>No trust boundary data available</p>"

        boundaries = self.report.inventory.trust_boundaries
        if not boundaries:
            return "<p>No trust boundaries detected in the system</p>"

        items = []
        for tb in boundaries[:20]:
            tb_type = tb.details.get("type", "unknown")
            icon = "&#x1f6e1;" if tb_type == "security_control" else "&#x2699;"
            items.append(
                f'<div class="trust-node">'
                f'<span class="trust-icon">{icon}</span>'
                f'<span class="trust-name">{tb.name}</span>'
                f'<span class="trust-type">{tb_type}</span>'
                f'</div>'
            )
        return "\n".join(items)

    def _generate_fallback_dashboard(self) -> Path:
        """Generate a minimal dashboard when template is unavailable."""
        dashboard_path = self.audit_dir / "dashboard.html"
        html = f"""<!DOCTYPE html>
<html><head><title>Security Audit - {self.report.audit_id}</title>
<style>body{{font-family:sans-serif;background:#1a1a1a;color:#e0e0e0;padding:20px;}}
h1{{color:#4a9eff;}}.score{{font-size:2em;color:#ff9800;}}</style></head>
<body><h1>MASSAT Security Audit Report</h1>
<p>Audit ID: {self.report.audit_id}</p>
<p>Target: {self.report.target}</p>
<p>Date: {self.report.timestamp}</p>
<p class="score">Overall Risk Score: {self.report.overall_risk_score:.1f}/10</p>
<p>Findings: {len(self.report.findings)}</p>
<p><em>Full dashboard template not found. This is a fallback report.</em></p>
</body></html>"""
        with open(dashboard_path, "w") as f:
            f.write(html)
        return dashboard_path

    def generate_executive_summary(self) -> Path:
        """Generate a markdown executive summary."""
        summary_path = self.audit_dir / "executive_summary.md"

        critical = sum(1 for f in self.report.findings if f.severity == "critical")
        high = sum(1 for f in self.report.findings if f.severity == "high")
        medium = sum(1 for f in self.report.findings if f.severity == "medium")
        low = sum(1 for f in self.report.findings if f.severity == "low")

        lines = [
            f"# Security Audit Executive Summary",
            f"",
            f"**Audit ID**: {self.report.audit_id}",
            f"**Target**: {self.report.target}",
            f"**Date**: {self.report.timestamp}",
            f"**Scope**: {self.report.scope}",
            f"**Overall Risk Score**: {self.report.overall_risk_score:.1f}/10",
            f"**Duration**: {self.report.duration_seconds:.1f}s",
            f"",
            f"## Finding Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| Critical | {critical} |",
            f"| High | {high} |",
            f"| Medium | {medium} |",
            f"| Low | {low} |",
            f"",
            f"## Top Risks",
            f"",
        ]

        sorted_findings = sorted(self.report.findings, key=lambda f: f.risk_score, reverse=True)
        for i, finding in enumerate(sorted_findings[:5], 1):
            lines.append(f"{i}. **{finding.category} - {finding.name}** (Score: {finding.risk_score:.1f})")
            if finding.controls_missing:
                lines.append(f"   - Missing: {', '.join(finding.controls_missing[:2])}")
            lines.append("")

        if self.report.compliance:
            lines.append("## Compliance Coverage")
            lines.append("")
            lines.append("| Framework | Coverage |")
            lines.append("|-----------|----------|")
            for comp in self.report.compliance:
                lines.append(f"| {comp.framework_name} | {comp.percentage:.0f}% ({comp.covered}/{comp.total}) |")
            lines.append("")

        lines.append("## Recommended Actions")
        lines.append("")
        all_rems: List[Tuple[str, Remediation]] = []
        for finding in self.report.findings:
            for rem in finding.remediation:
                all_rems.append((finding.category, rem))
        all_rems.sort(key=lambda x: x[1].priority)
        for cat_id, rem in all_rems[:5]:
            lines.append(f"- **P{rem.priority}** [{cat_id}] {rem.action} (effort: {rem.effort})")
        lines.append("")

        with open(summary_path, "w") as f:
            f.write("\n".join(lines))

        logger.info("Saved executive summary to %s", summary_path)
        return summary_path


# ---------------------------------------------------------------------------
# Main Scanner Class
# ---------------------------------------------------------------------------


class MASSecurityScanner:
    """Main scanner class for programmatic and CLI use."""

    def __init__(
        self,
        target_path: str = ".",
        config: Optional[AuditConfig] = None,
    ):
        resolved = Path(target_path).resolve()
        self.target_path = str(resolved)

        if config:
            self.config = config
            self.config.target_path = self.target_path
        else:
            self.config = AuditConfig(target_path=self.target_path)

        self.audit_id = f"audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        self.audit_dir = AUDIT_BASE_DIR / self.audit_id
        self.report: Optional[AuditReport] = None
        self._start_time: Optional[float] = None

        # Load profiles
        self.profiles: Dict = {}
        if PROFILES_PATH.exists():
            try:
                with open(PROFILES_PATH, "r") as f:
                    self.profiles = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load profiles: %s", e)

    def run_audit(self, scope: Optional[str] = None) -> AuditReport:
        """Run the full security audit pipeline.

        Args:
            scope: Override scope (full, quick, targeted). Uses config scope if None.

        Returns:
            AuditReport with all findings.
        """
        import time

        if scope:
            self.config.scope = scope

        self._start_time = time.time()

        # Create audit directory
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        (self.audit_dir / "findings").mkdir(exist_ok=True)

        # Save config
        config_path = self.audit_dir / "config.json"
        with open(config_path, "w") as f:
            json.dump(self.config.model_dump(), f, indent=2)

        logger.info("=" * 60)
        logger.info("MASSAT Security Audit Starting")
        logger.info("  Audit ID: %s", self.audit_id)
        logger.info("  Target: %s", self.target_path)
        logger.info("  Scope: %s", self.config.scope)
        logger.info("  Categories: %s", ", ".join(self.config.categories))
        logger.info("=" * 60)

        # Determine which phases to run based on scope
        scope_phases = self._get_scope_phases()

        # Phase 1: Discovery
        inventory = None
        if "discovery" not in self.config.skip_phases and "discovery" in scope_phases:
            discovery = DiscoveryEngine(self.target_path, self.profiles)
            inventory = discovery.run()

        # Phase 2: Vulnerability Assessment
        findings: List[ASIFinding] = []
        if "vulnerability" not in self.config.skip_phases and "vulnerability" in scope_phases:
            if inventory is None:
                inventory = SystemInventory()
            assessor = VulnerabilityAssessor(inventory, self.target_path, self.config.categories)
            findings = assessor.run()

        # Phase 2b: Compliance Mapping
        compliance: List[ComplianceMapping] = []
        if "compliance" not in self.config.skip_phases and "compliance" in scope_phases:
            mapper = ComplianceMapper(findings)
            compliance = mapper.run()

        # Phase 3: Red Team Simulation
        simulations: List[SimulationResult] = []
        if "redteam" not in self.config.skip_phases and "redteam" in scope_phases:
            if inventory is None:
                inventory = SystemInventory()
            red_team = RedTeamSimulator(inventory, findings)
            simulations = red_team.run()

        # Calculate overall risk score
        overall_risk = 0.0
        if findings:
            overall_risk = round(sum(f.risk_score for f in findings) / len(findings), 1)

        # Build summary
        critical_count = sum(1 for f in findings if f.severity == "critical")
        high_count = sum(1 for f in findings if f.severity == "high")
        summary = (
            f"Audit of {self.target_path} ({self.config.scope} scope): "
            f"{len(findings)} categories assessed, "
            f"{critical_count} critical, {high_count} high risk findings. "
            f"Overall risk score: {overall_risk:.1f}/10."
        )

        duration = time.time() - self._start_time

        self.report = AuditReport(
            audit_id=self.audit_id,
            target=self.target_path,
            timestamp=datetime.now(timezone.utc).isoformat(),
            scope=self.config.scope,
            categories_assessed=self.config.categories,
            inventory=inventory,
            findings=findings,
            compliance=compliance,
            simulations=simulations,
            overall_risk_score=overall_risk,
            summary=summary,
            duration_seconds=round(duration, 1),
        )

        logger.info("=" * 60)
        logger.info("Audit Complete")
        logger.info("  Overall Risk Score: %.1f/10", overall_risk)
        logger.info("  Duration: %.1fs", duration)
        logger.info("  Critical: %d, High: %d", critical_count, high_count)
        logger.info("=" * 60)

        return self.report

    def generate_report(self) -> Path:
        """Generate all report artifacts (JSON, HTML dashboard, executive summary).

        Returns:
            Path to the dashboard HTML file.
        """
        if not self.report:
            raise RuntimeError("No audit results. Run run_audit() first.")

        generator = ReportGenerator(self.report, self.audit_dir)

        # Save all artifacts
        generator.save_json_report()
        generator.save_findings()
        generator.save_inventory()
        generator.save_compliance_map()
        generator.save_simulations()
        generator.generate_executive_summary()

        # Generate and return dashboard path
        dashboard_path = generator.generate_dashboard()
        return dashboard_path

    def notify(self, channels: Optional[List[str]] = None) -> None:
        """Send notifications about audit completion.

        Args:
            channels: List of channels (whatsapp, email). Defaults to config channels.
        """
        if not self.report:
            logger.warning("No audit results to notify about.")
            return

        channels = channels or self.config.notification_channels
        if not channels:
            logger.info("No notification channels configured.")
            return

        toolkit_path = PROJECT_ROOT / "scripts" / "execution_toolkit.py"
        if not toolkit_path.exists():
            logger.warning("Execution toolkit not found at %s", toolkit_path)
            return

        critical = sum(1 for f in self.report.findings if f.severity == "critical")
        high = sum(1 for f in self.report.findings if f.severity == "high")
        message = (
            f"MASSAT Audit Complete\n"
            f"ID: {self.report.audit_id}\n"
            f"Target: {self.report.target}\n"
            f"Risk Score: {self.report.overall_risk_score:.1f}/10\n"
            f"Critical: {critical}, High: {high}\n"
            f"Dashboard: {self.audit_dir}/dashboard.html"
        )

        for channel in channels:
            try:
                if channel == "whatsapp":
                    cmd = [
                        sys.executable,
                        str(toolkit_path),
                        "whatsapp",
                        "--message",
                        message,
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        logger.info("WhatsApp notification sent")
                    else:
                        logger.warning("WhatsApp notification failed: %s", result.stderr)

                elif channel == "email":
                    subject = f"MASSAT Audit: {self.report.overall_risk_score:.1f}/10 - {self.report.audit_id}"
                    cmd = [
                        sys.executable,
                        str(toolkit_path),
                        "email",
                        "--subject",
                        subject,
                        "--body",
                        message,
                        "--to",
                        "craigmbrown@gmail.com",
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        logger.info("Email notification sent")
                    else:
                        logger.warning("Email notification failed: %s", result.stderr)

            except subprocess.TimeoutExpired:
                logger.warning("Notification timeout for channel: %s", channel)
            except Exception as e:
                logger.warning("Notification error (%s): %s", channel, e)

    def generate_dashboard(self) -> Path:
        """Generate only the HTML dashboard (convenience alias)."""
        return self.generate_report()

    def _get_scope_phases(self) -> List[str]:
        """Get the phases to run based on scope configuration."""
        scope_map = {
            "full": ["discovery", "vulnerability", "compliance", "redteam", "report"],
            "quick": ["discovery", "vulnerability", "report"],
            "targeted": ["discovery", "vulnerability", "compliance", "report"],
        }
        return scope_map.get(self.config.scope, scope_map["full"])

    def get_exit_code(self) -> int:
        """Determine exit code based on findings.

        Returns:
            0 - Clean (no findings above low)
            1 - Findings present (medium/high)
            2 - Critical findings detected
        """
        if not self.report:
            return 0

        for finding in self.report.findings:
            if finding.severity == "critical":
                return 2

        for finding in self.report.findings:
            if finding.severity in ("high", "medium"):
                return 1

        return 0


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def load_existing_report(report_dir: str) -> None:
    """Load and display an existing audit report."""
    report_path = Path(report_dir) / "report.json"
    if not report_path.exists():
        print(f"ERROR: No report found at {report_path}", file=sys.stderr)
        sys.exit(1)

    with open(report_path, "r") as f:
        data = json.load(f)

    report = AuditReport(**data)

    print(f"\nAudit: {report.audit_id}")
    print(f"Target: {report.target}")
    print(f"Date: {report.timestamp}")
    print(f"Scope: {report.scope}")
    print(f"Overall Risk Score: {report.overall_risk_score:.1f}/10")
    print(f"Duration: {report.duration_seconds:.1f}s")
    print(f"\nFindings ({len(report.findings)}):")
    for finding in sorted(report.findings, key=lambda f: f.risk_score, reverse=True):
        icon = {
            "critical": "[CRIT]",
            "high": "[HIGH]",
            "medium": "[MED ]",
            "low": "[LOW ]",
            "info": "[INFO]",
        }.get(finding.severity, "[????]")
        print(f"  {icon} {finding.category} {finding.name}: {finding.risk_score:.1f}")

    if report.compliance:
        print(f"\nCompliance:")
        for comp in report.compliance:
            bar_len = int(comp.percentage / 5)
            bar = "#" * bar_len + "-" * (20 - bar_len)
            print(f"  [{bar}] {comp.percentage:.0f}% {comp.framework_name}")

    # Check for dashboard
    dashboard_path = Path(report_dir) / "dashboard.html"
    if dashboard_path.exists():
        print(f"\nDashboard: {dashboard_path}")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="MASSAT - Multi-Agent System Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full audit of current project
  python3 scripts/mas_security_scanner.py --target .

  # Quick scan
  python3 scripts/mas_security_scanner.py --target . --scope quick

  # Targeted categories with notifications
  python3 scripts/mas_security_scanner.py --target . --categories ASI01,ASI06 --notify

  # View existing report
  python3 scripts/mas_security_scanner.py --report security-audits/audit-20260222-etac/

  # Full audit with debate and NFT minting
  python3 scripts/mas_security_scanner.py --target . --scope full --with-debate --mint-nft
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--target",
        type=str,
        help="Path to target system to audit",
    )
    group.add_argument(
        "--report",
        type=str,
        help="Path to existing audit directory to display",
    )

    parser.add_argument(
        "--scope",
        choices=["full", "quick", "targeted"],
        default="full",
        help="Audit scope (default: full)",
    )
    parser.add_argument(
        "--categories",
        type=str,
        default=None,
        help="Comma-separated ASI categories to assess (e.g. ASI01,ASI06)",
    )
    parser.add_argument(
        "--skip",
        type=str,
        default=None,
        help="Comma-separated phases to skip (e.g. redteam,compliance)",
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Send WhatsApp and email notifications on completion",
    )
    parser.add_argument(
        "--notify-channels",
        type=str,
        default="whatsapp,email",
        help="Notification channels (default: whatsapp,email)",
    )
    parser.add_argument(
        "--with-debate",
        action="store_true",
        help="Trigger multi-agent security debate after audit",
    )
    parser.add_argument(
        "--mint-nft",
        action="store_true",
        help="Mint on-chain NFT of audit results",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output",
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Print JSON report to stdout (for piping)",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point for CLI usage."""
    args = parse_args()
    setup_logging(verbose=args.verbose)

    # View existing report
    if args.report:
        load_existing_report(args.report)
        return 0

    # Parse categories
    categories = None
    if args.categories:
        categories = [c.strip().upper() for c in args.categories.split(",")]

    # Parse skip phases
    skip_phases: List[str] = []
    if args.skip:
        skip_phases = [p.strip().lower() for p in args.skip.split(",")]

    # Parse notification channels
    notify_channels: List[str] = []
    if args.notify:
        notify_channels = [c.strip() for c in args.notify_channels.split(",")]

    # Build config
    config = AuditConfig(
        target_path=str(Path(args.target).resolve()),
        scope=args.scope,
        categories=categories or [c[0] for c in ASI_CATEGORIES],
        skip_phases=skip_phases,
        notification_channels=notify_channels,
        with_debate=args.with_debate,
        mint_nft=args.mint_nft,
        verbose=args.verbose,
    )

    # Run the audit
    scanner = MASSecurityScanner(target_path=args.target, config=config)

    try:
        report = scanner.run_audit()
    except Exception as e:
        logger.error("Audit failed: %s", e, exc_info=True)
        return 2

    # Generate report artifacts
    try:
        dashboard_path = scanner.generate_report()
        print(f"\nDashboard: {dashboard_path}")
        print(f"Audit Dir: {scanner.audit_dir}")
    except Exception as e:
        logger.error("Report generation failed: %s", e, exc_info=True)

    # JSON output mode
    if args.json_output:
        print(json.dumps(report.model_dump(), indent=2, default=str))

    # Notifications
    if args.notify:
        scanner.notify()

    # Print summary
    print(f"\nOverall Risk Score: {report.overall_risk_score:.1f}/10")
    print(f"Findings: {len(report.findings)}")
    for finding in sorted(report.findings, key=lambda f: f.risk_score, reverse=True):
        severity_tag = finding.severity.upper().ljust(8)
        print(f"  [{severity_tag}] {finding.category} - {finding.name}: {finding.risk_score:.1f}")

    exit_code = scanner.get_exit_code()
    if exit_code == 0:
        print("\nResult: CLEAN - no significant findings")
    elif exit_code == 1:
        print("\nResult: FINDINGS - medium/high severity issues detected")
    else:
        print("\nResult: CRITICAL - critical findings require immediate attention")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
