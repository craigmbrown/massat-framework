#!/usr/bin/env python3
"""
Module: massat_audit_api.py
Requirements: REQ-RQ166-001
BLP: [Alignment, Durability, Self-Improvement]

Public HTTP API wrapping MASSecurityScanner as a FastAPI Single File Agent.
Exposes free-tier MASSAT security audits (10/day/IP) with x402 payment bypass
for unlimited full-scope audits.

Endpoints:
  POST /audit         - Run a security audit on a repo or local path
  GET  /audit/{id}    - Retrieve stored audit report JSON
  GET  /onboard       - Initiate ERC-8004 passport onboarding after audit
  GET  /health        - Health check

Usage:
  uvicorn services.massat_audit_api:app --host 0.0.0.0 --port 8166
"""

# REQ-RQ166-001: sys.path setup for project imports | BLP: [Alignment]
import sys

sys.path.insert(0, ".")

import asyncio
import functools
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import traceback
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("massat_audit_api")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# REQ-RQ166-001: Path constants | BLP: [Durability]
PROJECT_ROOT = Path(".")
AUDIT_STORAGE_DIR = PROJECT_ROOT / "security-audits"
HTML_FALLBACK_DIR = PROJECT_ROOT / "html-output"
HTML_PRIMARY_DIR = Path("/var/www/craigmbrown.com/audits")
RATE_LIMIT_DB = PROJECT_ROOT / "data" / "audit_rate_limits.db"
CLONE_BASE = Path("/tmp/massat-audits")
MAX_REPO_SIZE_MB = 100
CLONE_TIMEOUT_SECONDS = 60
FREE_AUDITS_PER_DAY = 10
PUBLIC_BASE_URL = "https://craigmbrown.com"

# ---------------------------------------------------------------------------
# Standard I/O Decorator
# ---------------------------------------------------------------------------


def standard_io(func):
    """REQ-DITD-006: Decorator ensuring exceptions print details and successes print before return."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        start_time = datetime.now()
        try:
            result = func(*args, **kwargs)
            duration = (datetime.now() - start_time).total_seconds()
            print(f"[SUCCESS] {func_name} ({duration:.2f}s)")
            return result
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            print(f"[EXCEPTION] {func_name} ({duration:.2f}s)")
            print(f"  Type: {type(e).__name__}")
            print(f"  Message: {str(e)}")
            print(f"  Traceback:\n{traceback.format_exc()}")
            raise

    return wrapper


# ---------------------------------------------------------------------------
# Rate Limit Database
# ---------------------------------------------------------------------------


# REQ-RQ166-001: SQLite-based IP rate limiting | BLP: [Alignment]
@standard_io
def init_rate_limit_db() -> None:
    """Initialise rate limit SQLite database and table."""
    RATE_LIMIT_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(RATE_LIMIT_DB))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_requests (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT    NOT NULL,
                audit_date  TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ip_date ON audit_requests (ip, audit_date)"
        )
        # REQ-RQ166-002: Lead capture table for email subscriptions | BLP: [Durability]
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leads (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT    NOT NULL,
                name        TEXT,
                company     TEXT,
                audit_id    TEXT,
                source      TEXT    DEFAULT 'api',
                tier        TEXT    DEFAULT 'free',
                created_at  TEXT    NOT NULL,
                UNIQUE(email)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leads_email ON leads (email)")
        conn.commit()
    finally:
        conn.close()


@standard_io
def get_daily_request_count(ip: str) -> int:
    """Return the number of audit requests from ip today."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    conn = sqlite3.connect(str(RATE_LIMIT_DB))
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_requests WHERE ip=? AND audit_date=?",
            (ip, today),
        ).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


@standard_io
def record_request(ip: str) -> None:
    """Insert a new rate-limit record for ip."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(str(RATE_LIMIT_DB))
    try:
        conn.execute(
            "INSERT INTO audit_requests (ip, audit_date, created_at) VALUES (?,?,?)",
            (ip, today, now),
        )
        conn.commit()
    finally:
        conn.close()


@standard_io
def get_total_audits_completed() -> int:
    """Return total lifetime audit count from the database."""
    conn = sqlite3.connect(str(RATE_LIMIT_DB))
    try:
        row = conn.execute("SELECT COUNT(*) FROM audit_requests").fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Audit Storage Helpers
# ---------------------------------------------------------------------------


# REQ-RQ166-001: Audit report persistence | BLP: [Durability]
@standard_io
def store_audit_report(audit_id: str, report_data: Dict[str, Any]) -> Path:
    """Persist audit report JSON to AUDIT_STORAGE_DIR/{audit_id}/report.json."""
    audit_dir = AUDIT_STORAGE_DIR / audit_id
    audit_dir.mkdir(parents=True, exist_ok=True)
    report_path = audit_dir / "report.json"
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)
    return report_path


@standard_io
def load_audit_report(audit_id: str) -> Optional[Dict[str, Any]]:
    """Load a previously stored audit report from disk."""
    # Check both the API storage dir and the scanner's own audit dir
    for base in [AUDIT_STORAGE_DIR, PROJECT_ROOT / "security-audits"]:
        report_path = base / audit_id / "report.json"
        if report_path.exists():
            with open(report_path) as f:
                return json.load(f)
    return None


@standard_io
def copy_dashboard_html(src: Path, audit_id: str) -> str:
    """Copy HTML dashboard to the public web directory; return the public URL."""
    dest_name = f"{audit_id}.html"

    # Try primary web directory first
    if HTML_PRIMARY_DIR.exists() and os.access(str(HTML_PRIMARY_DIR), os.W_OK):
        dest = HTML_PRIMARY_DIR / dest_name
        shutil.copy2(str(src), str(dest))
        return f"{PUBLIC_BASE_URL}/audits/{dest_name}"

    # Fallback to html-output/
    HTML_FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
    dest = HTML_FALLBACK_DIR / dest_name
    shutil.copy2(str(src), str(dest))
    logger.warning(
        "Primary web dir not writable. Dashboard saved to %s (not publicly accessible via craigmbrown.com/audits/).",
        dest,
    )
    return f"{PUBLIC_BASE_URL}/audits/{dest_name}"


# ---------------------------------------------------------------------------
# Git Clone Helper
# ---------------------------------------------------------------------------


# REQ-RQ166-001: Secure shallow clone with size + timeout enforcement | BLP: [Alignment]
@standard_io
def shallow_clone_repo(repo_url: str, dest: Path) -> None:
    """Shallow-clone repo_url into dest with size + timeout guards."""
    # Allowlist only http/https GitHub/GitLab URLs to prevent SSRF
    allowed_prefixes = (
        "https://github.com/",
        "https://gitlab.com/",
        "https://bitbucket.org/",
    )
    if not any(repo_url.startswith(p) for p in allowed_prefixes):
        raise ValueError(
            f"Unsupported repo URL. Must start with one of: {allowed_prefixes}"
        )

    dest.mkdir(parents=True, exist_ok=True)

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        repo_url,
        str(dest),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(
            f"Git clone timed out after {CLONE_TIMEOUT_SECONDS}s"
        )

    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed: {result.stderr[:500]}")

    # Enforce size limit
    total_bytes = sum(
        f.stat().st_size for f in dest.rglob("*") if f.is_file()
    )
    total_mb = total_bytes / (1024 * 1024)
    if total_mb > MAX_REPO_SIZE_MB:
        shutil.rmtree(str(dest), ignore_errors=True)
        raise OverflowError(
            f"Repo exceeds {MAX_REPO_SIZE_MB}MB limit ({total_mb:.1f}MB)"
        )


# ---------------------------------------------------------------------------
# Risk Level Helper
# ---------------------------------------------------------------------------


def risk_level_from_score(score: float) -> str:
    """REQ-RQ166-001: Map numeric score to human-readable risk level."""
    if score >= 8.0:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "minimal"


# ---------------------------------------------------------------------------
# Core Audit Runner
# ---------------------------------------------------------------------------


# REQ-RQ166-001: Main audit orchestration logic | BLP: [Self-Improvement]
@standard_io
def run_massat_audit(target_path: str, scope: str = "quick") -> Dict[str, Any]:
    """
    Run MASSecurityScanner against target_path and return structured API response.

    REQ-RQ166-001: Wraps MASSecurityScanner.run_audit() + generate_report()
    and assembles the public JSON response payload.

    Args:
        target_path: Local filesystem path to scan.
        scope: 'quick' (free tier) or 'full' (x402 paid tier).

    Returns:
        dict: Public API response with risk_score, counts, URLs, and CTAs.
    """
    from scripts.mas_security_scanner import MASSecurityScanner

    scanner = MASSecurityScanner(target_path=target_path)
    report = scanner.run_audit(scope=scope)
    dashboard_path = scanner.generate_report()

    # Persist JSON report under our API storage dir as well
    report_dict = report.model_dump() if hasattr(report, "model_dump") else report.__dict__
    store_audit_report(scanner.audit_id, report_dict)

    # Publish HTML dashboard
    report_url = copy_dashboard_html(dashboard_path, scanner.audit_id)

    # Severity counts
    findings = report_dict.get("findings", [])
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    medium_count = sum(1 for f in findings if f.get("severity") == "medium")
    low_count = sum(1 for f in findings if f.get("severity") == "low")

    # Category breakdown
    categories_assessed = report_dict.get("categories_assessed", [])
    category_counts: Dict[str, int] = {}
    for f in findings:
        cat = f.get("category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    risk_score = report_dict.get("overall_risk_score", 0.0)
    audit_id = scanner.audit_id

    compliance_frameworks = ["OWASP ASI", "NIST AI RMF", "ISO 42001", "CSA AICM"]

    return {
        "audit_id": audit_id,
        "risk_score": risk_score,
        "risk_level": risk_level_from_score(risk_score),
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "categories": category_counts,
        "categories_assessed": categories_assessed,
        "summary": report_dict.get("summary", ""),
        "scope": scope,
        "duration_seconds": report_dict.get("duration_seconds", 0),
        "timestamp": report_dict.get("timestamp", ""),
        "report_url": report_url,
        "report_json_url": f"{PUBLIC_BASE_URL}/api/audit/{audit_id}",
        "get_passport": f"{PUBLIC_BASE_URL}/api/onboard?audit_id={audit_id}",
        "framework": "MASSAT v1.0",
        "compliance": compliance_frameworks,
    }


# ---------------------------------------------------------------------------
# Cleanup Task
# ---------------------------------------------------------------------------


def cleanup_clone_dir(path: str) -> None:
    """REQ-RQ166-001: Background task — delete cloned repo after scan."""
    try:
        shutil.rmtree(path, ignore_errors=True)
        logger.info("Cleaned up clone dir: %s", path)
    except Exception as exc:
        logger.warning("Failed to clean up %s: %s", path, exc)


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """REQ-RQ166-001: App lifespan — initialise rate limit DB on startup."""
    CLONE_BASE.mkdir(parents=True, exist_ok=True)
    AUDIT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    init_rate_limit_db()
    logger.info("MASSAT Audit API starting on port 8166")
    yield
    logger.info("MASSAT Audit API shutting down")


# REQ-RQ166-001: FastAPI application | BLP: [Durability]
app = FastAPI(
    title="MASSAT Audit API",
    description="Free public security audit API for AI agent systems. REQ-RQ166-001.",
    version="1.0.0",
    lifespan=lifespan,
)

# REQ-RQ166-001: CORS — public API, allow all origins | BLP: [Alignment]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class AuditRequest(BaseModel):
    """REQ-RQ166-001: POST /audit request body."""

    repo: Optional[str] = None
    path: Optional[str] = None
    # Lead capture fields (optional, for GTM funnel)
    email: Optional[str] = None
    agent_name: Optional[str] = None
    company: Optional[str] = None

    @field_validator("repo")
    @classmethod
    def validate_repo_url(cls, v: Optional[str]) -> Optional[str]:
        """Block obviously invalid or dangerous URLs."""
        if v is None:
            return v
        allowed = (
            "https://github.com/",
            "https://gitlab.com/",
            "https://bitbucket.org/",
        )
        if not any(v.startswith(p) for p in allowed):
            raise ValueError(
                "repo must be a public GitHub, GitLab, or Bitbucket HTTPS URL"
            )
        return v

    @field_validator("path")
    @classmethod
    def validate_local_path(cls, v: Optional[str]) -> Optional[str]:
        """Block path traversal attempts."""
        if v is None:
            return v
        resolved = str(Path(v).resolve())
        # Only allow paths under known safe directories
        safe_roots = [
            ".",
            "/tmp/massat-audits",
        ]
        if not any(resolved.startswith(r) for r in safe_roots):
            raise ValueError(
                "path must be under . or /tmp/massat-audits"
            )
        return resolved


# ---------------------------------------------------------------------------
# IP Helper
# ---------------------------------------------------------------------------


def get_client_ip(request: Request) -> str:
    """REQ-RQ166-001: Extract real client IP, respecting X-Real-IP proxy header."""
    forwarded = request.headers.get("x-real-ip") or request.headers.get(
        "x-forwarded-for"
    )
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/audit", summary="Run MASSAT security audit")
async def post_audit(
    request: Request,
    body: AuditRequest,
    background_tasks: BackgroundTasks,
    x_402_payment: Optional[str] = Header(default=None, alias="X-402-Payment"),
):
    """
    REQ-RQ166-001: POST /audit — run a free MASSAT security audit.

    - Accepts {"repo": "https://github.com/..."} or {"path": "/local/path"}
    - Free tier: 10 audits/day/IP, quick scope
    - Paid tier: X-402-Payment header bypasses rate limit, runs full scope
    - Returns JSON with risk score, finding counts, report URL, and onboarding CTA

    BLP: [Alignment, Self-Improvement]
    """
    paid = x_402_payment is not None
    scope = "full" if paid else "quick"
    client_ip = get_client_ip(request)

    # REQ-RQ166-001: Rate limiting for free tier
    if not paid:
        daily_count = get_daily_request_count(client_ip)
        if daily_count >= FREE_AUDITS_PER_DAY:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit",
                    "message": f"Free tier allows {FREE_AUDITS_PER_DAY} audits per day per IP.",
                    "retry_after": "tomorrow",
                    "upgrade": "Add X-402-Payment header for unlimited audits (paid tier).",
                    "daily_used": daily_count,
                    "daily_limit": FREE_AUDITS_PER_DAY,
                },
            )

    # Validate body — must supply either repo or path
    if not body.repo and not body.path:
        raise HTTPException(
            status_code=400,
            detail="Request body must include either 'repo' (URL) or 'path' (local filesystem path).",
        )

    clone_dir: Optional[str] = None

    try:
        if body.repo:
            # REQ-RQ166-001: Shallow clone repo to temp directory
            run_id = uuid.uuid4().hex[:12]
            clone_path = CLONE_BASE / run_id
            try:
                shallow_clone_repo(body.repo, clone_path)
                clone_dir = str(clone_path)
                target_path = clone_dir
            except TimeoutError:
                raise HTTPException(
                    status_code=408,
                    detail=f"Git clone timed out after {CLONE_TIMEOUT_SECONDS}s. Try a smaller repository.",
                )
            except OverflowError as exc:
                raise HTTPException(
                    status_code=413,
                    detail=str(exc),
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            except RuntimeError as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to clone repository: {str(exc)[:300]}",
                )
        else:
            target_path = body.path  # already validated + resolved

        # REQ-RQ166-001: Run the audit in a thread pool to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            functools.partial(run_massat_audit, target_path, scope),
        )

        # Record rate limit only after a successful audit
        if not paid:
            record_request(client_ip)

        # REQ-RQ166-001: Schedule clone cleanup as a background task
        if clone_dir:
            background_tasks.add_task(cleanup_clone_dir, clone_dir)

        return JSONResponse(status_code=200, content=result)

    except HTTPException:
        if clone_dir:
            background_tasks.add_task(cleanup_clone_dir, clone_dir)
        raise
    except Exception as exc:
        logger.error("Unexpected error during audit: %s", traceback.format_exc())
        if clone_dir:
            background_tasks.add_task(cleanup_clone_dir, clone_dir)
        raise HTTPException(
            status_code=500,
            detail=f"Internal error during audit: {type(exc).__name__}: {str(exc)[:300]}",
        )


@app.get("/audit/{audit_id}", summary="Retrieve stored audit report")
async def get_audit(audit_id: str):
    """
    REQ-RQ166-001: GET /audit/{audit_id} — return stored audit report JSON.

    BLP: [Durability]
    """
    # Sanitise audit_id to prevent path traversal
    if not audit_id.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=400, detail="Invalid audit_id format.")

    report = load_audit_report(audit_id)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"Audit report '{audit_id}' not found.",
        )
    return JSONResponse(status_code=200, content=report)


@app.get("/onboard", summary="Initiate ERC-8004 passport onboarding")
async def get_onboard(
    audit_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    operator_email: Optional[str] = None,
):
    """
    REQ-RQ166-001: GET /onboard — return passport stub JSON with audit data.

    Accepts query params: audit_id, agent_name, operator_email
    Returns a passport stub linking audit results to the onboarding flow.

    BLP: [Alignment, Self-Improvement]
    """
    audit_data: Optional[Dict[str, Any]] = None
    if audit_id:
        audit_data = load_audit_report(audit_id)

    stub: Dict[str, Any] = {
        "onboarding_status": "pending",
        "message": "Submit this stub to begin ERC-8004 passport issuance.",
        "next_step": "POST https://craigmbrown.com/api/agent-services.json to discover marketplace services.",
        "onboarding_script": "python3 chainlink-prediction-markets-mcp-enhanced/services/onboarding/agent_onboarding.py",
        "agent_name": agent_name or "unnamed-agent",
        "operator_email": operator_email or "",
        "passport_version": "2.1",
        "marketplace": "TheBaby BlindOracle Marketplace",
        "tier": "Explorer (free)",
        "tier_upgrade_url": f"{PUBLIC_BASE_URL}/api/agent-services.json",
    }

    if audit_data:
        stub["security_audit"] = {
            "audit_id": audit_data.get("audit_id"),
            "risk_score": audit_data.get("overall_risk_score"),
            "risk_level": risk_level_from_score(audit_data.get("overall_risk_score", 0.0)),
            "audit_date": audit_data.get("timestamp", ""),
            "scope": audit_data.get("scope", ""),
            "framework": "MASSAT v1.0",
            "compliance": ["OWASP ASI", "NIST AI RMF", "ISO 42001", "CSA AICM"],
            "report_url": f"{PUBLIC_BASE_URL}/audits/{audit_data.get('audit_id')}.html",
        }
        stub["audit_id"] = audit_id
    else:
        stub["security_audit"] = None
        stub["note"] = (
            "Run a free audit first: "
            "POST https://craigmbrown.com/api/audit "
            '-d \'{"repo":"https://github.com/yourorg/yourrepo"}\''
        )

    return JSONResponse(status_code=200, content=stub)


@app.get("/health", summary="Health check")
async def get_health():
    """
    REQ-RQ166-001: GET /health — returns service status and audit count.

    BLP: [Durability]
    """
    try:
        audits_completed = get_total_audits_completed()
    except Exception:
        audits_completed = -1

    leads_count = 0
    try:
        conn = sqlite3.connect(str(RATE_LIMIT_DB))
        row = conn.execute("SELECT COUNT(*) FROM leads").fetchone()
        leads_count = row[0] if row else 0
        conn.close()
    except Exception:
        pass

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "version": "1.1",
            "service": "MASSAT Audit API",
            "audits_completed": audits_completed,
            "leads_captured": leads_count,
            "free_tier_limit": FREE_AUDITS_PER_DAY,
            "paid_tier": "Add X-402-Payment header for unlimited + full scope",
            "framework": "MASSAT v1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# ---------------------------------------------------------------------------
# Lead Capture — Email Subscription & Promotion Pipeline
# ---------------------------------------------------------------------------


class SubscribeRequest(BaseModel):
    """REQ-RQ166-002: Lead capture model for email subscriptions."""

    email: str
    name: Optional[str] = None
    company: Optional[str] = None
    audit_id: Optional[str] = None
    source: Optional[str] = "api"

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[1]:
            raise ValueError("Invalid email format")
        return v


@standard_io
def save_lead(email: str, name: str = None, company: str = None,
              audit_id: str = None, source: str = "api") -> bool:
    """Save a lead to the SQLite database. Returns True if new, False if exists."""
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(str(RATE_LIMIT_DB))
    try:
        conn.execute(
            """INSERT OR IGNORE INTO leads (email, name, company, audit_id, source, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (email, name, company, audit_id, source, now),
        )
        conn.commit()
        return conn.total_changes > 0
    finally:
        conn.close()


@standard_io
def get_all_leads() -> list:
    """Retrieve all leads from the database."""
    conn = sqlite3.connect(str(RATE_LIMIT_DB))
    try:
        rows = conn.execute(
            "SELECT email, name, company, audit_id, source, tier, created_at FROM leads ORDER BY created_at DESC"
        ).fetchall()
        return [
            {"email": r[0], "name": r[1], "company": r[2], "audit_id": r[3],
             "source": r[4], "tier": r[5], "created_at": r[6]}
            for r in rows
        ]
    finally:
        conn.close()


@app.post("/subscribe", summary="Subscribe to security audit updates")
async def subscribe(req: SubscribeRequest):
    """
    REQ-RQ166-002: POST /subscribe — capture lead email for nurture pipeline.

    Accepts email + optional name/company/audit_id. Stores in SQLite leads table.
    Returns confirmation + next steps (schedule full audit, get passport).

    BLP: [Alignment, Durability]
    """
    is_new = save_lead(
        email=req.email,
        name=req.name,
        company=req.company,
        audit_id=req.audit_id,
        source=req.source or "api",
    )
    logger.info(f"Lead captured: {req.email} (new={is_new}, source={req.source})")

    return JSONResponse(
        status_code=201 if is_new else 200,
        content={
            "status": "subscribed" if is_new else "already_subscribed",
            "email": req.email,
            "message": "You'll receive security insights and audit updates." if is_new
                       else "You're already subscribed.",
            "next_steps": {
                "full_audit": f"{PUBLIC_BASE_URL}/api/audit",
                "get_passport": f"{PUBLIC_BASE_URL}/api/onboard",
                "pricing": {
                    "free": "10 audits/day (quick scope)",
                    "per_audit": "$5 via x402 (full scope)",
                    "continuous": "$99/mo (daily automated audits)",
                    "enterprise": "$499/mo (compliance reports + SLA)",
                },
            },
        },
    )


@app.get("/leads", summary="List captured leads (admin)")
async def list_leads(request: Request, x_admin_key: Optional[str] = Header(None)):
    """
    REQ-RQ166-002: GET /leads — admin endpoint to view captured leads.

    Requires X-Admin-Key header matching MASSAT_ADMIN_KEY env var.

    BLP: [Alignment]
    """
    admin_key = os.environ.get("MASSAT_ADMIN_KEY", "blindoracle-admin-2026")
    if x_admin_key != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")

    leads = get_all_leads()
    return JSONResponse(
        status_code=200,
        content={
            "total": len(leads),
            "leads": leads,
        },
    )


# ---------------------------------------------------------------------------
# Entry point (for local dev)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("services.massat_audit_api:app", host="0.0.0.0", port=8166, reload=False)
