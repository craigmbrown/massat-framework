#!/usr/bin/env python3
"""
MASSAT Framework - Python Usage Examples

Shows how to use the scanner directly, apply hardening modules,
and interact with the audit API programmatically.
"""

import json
import requests


# =============================================================================
# Example 1: Use the hosted API
# =============================================================================

def audit_via_api(repo_url: str) -> dict:
    """Run a MASSAT audit via the hosted API."""
    response = requests.post(
        "https://craigmbrown.com/api/audit",
        json={"repo": repo_url},
        timeout=120,
    )
    response.raise_for_status()
    result = response.json()

    print(f"Risk Score: {result['risk_score']} ({result['risk_level']})")
    print(f"Findings: C={result['critical']} H={result['high']} M={result['medium']} L={result['low']}")
    print(f"Report: {result['report_url']}")
    return result


# =============================================================================
# Example 2: Use the scanner locally
# =============================================================================

def audit_local_path(path: str) -> dict:
    """Run a MASSAT audit on a local directory."""
    from src.massat.scanner import MASSecurityScanner

    scanner = MASSecurityScanner(target_path=path)
    results = scanner.run_audit(scope="quick")

    print(f"Risk Score: {results['overall_risk_score']}")
    print(f"Categories: {results['categories_assessed']}")
    for finding in results.get("findings", []):
        print(f"  [{finding['severity']}] {finding['category']}: {finding['title']}")

    return results


# =============================================================================
# Example 3: Subscribe for updates
# =============================================================================

def subscribe(email: str, company: str = None) -> dict:
    """Subscribe to MASSAT security update emails."""
    response = requests.post(
        "https://craigmbrown.com/api/subscribe",
        json={"email": email, "company": company, "source": "python_sdk"},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


# =============================================================================
# Example 4: Apply hardening modules to your agents
# =============================================================================

def hardening_example():
    """Demonstrate using MASSAT hardening modules."""

    # Tool allowlist - restrict which tools an agent can use
    from src.hardening.tool_allowlist import ToolAllowlist

    allowlist = ToolAllowlist(
        commands=["git status", "python -m pytest", "curl"],
        file_extensions=[".py", ".json", ".md"],
        blocked_patterns=["sudo", "chmod", "chown", "rm -rf"],
    )
    print(f"Allowed: {allowlist.is_allowed('git status')}")   # True
    print(f"Blocked: {allowlist.is_allowed('sudo rm -rf /')}")  # False

    # Safe subprocess - execute commands with resource limits
    from src.hardening.safe_subprocess import SafeExecutor

    executor = SafeExecutor(
        timeout=30,
        max_memory_mb=256,
        allowed_commands=["python", "node"],
    )
    result = executor.run("python --version")
    print(f"Output: {result}")

    # Agent monitor - track resource usage
    from src.hardening.agent_monitor import ResourceMonitor

    monitor = ResourceMonitor(
        max_cpu_percent=50,
        max_memory_mb=512,
        max_runtime_seconds=300,
    )
    print(f"Monitor configured: {monitor}")


# =============================================================================
# Example 5: Full audit-to-passport flow
# =============================================================================

def full_onboarding_flow(repo_url: str, agent_name: str, email: str):
    """Complete flow: audit -> subscribe -> onboard -> passport."""

    # Step 1: Run audit
    print("Step 1: Running audit...")
    audit = audit_via_api(repo_url)
    audit_id = audit["audit_id"]

    # Step 2: Subscribe for updates
    print("\nStep 2: Subscribing...")
    sub = subscribe(email)
    print(f"  Status: {sub['status']}")

    # Step 3: Onboard for ERC-8004 passport
    print("\nStep 3: Requesting passport...")
    response = requests.get(
        "https://craigmbrown.com/api/onboard",
        params={
            "audit_id": audit_id,
            "agent_name": agent_name,
            "operator_email": email,
        },
        timeout=30,
    )
    passport = response.json()
    print(f"  Passport: {json.dumps(passport, indent=2)}")

    return {"audit": audit, "subscription": sub, "passport": passport}


# =============================================================================
# Run examples
# =============================================================================

if __name__ == "__main__":
    # Uncomment the example you want to run:

    # audit_via_api("https://github.com/octocat/Hello-World")
    # audit_local_path("/path/to/your/agents")
    # subscribe("you@company.com", "Acme AI")
    # hardening_example()
    # full_onboarding_flow("https://github.com/your-org/agents", "my-agent", "you@co.com")

    print("MASSAT Framework - Python Examples")
    print("Uncomment an example in __main__ to run it.")
