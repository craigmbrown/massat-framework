# OWASP ASI01-10 for AI Agent Builders: A Practical Guide

*Published: April 5, 2026 | Author: Craig Brown*

The OWASP Agent Security Index defines 10 threat categories specific to AI agent systems. This guide explains each one with real code examples and fixes.

## ASI01 - Unbounded Agency

**The risk:** Your agent can do anything — delete files, send money, publish content — with no guardrails.

**Bad:**
```python
# Agent has unrestricted tool access
tools = get_all_available_tools()
agent.run(tools=tools, prompt=user_input)
```

**Good:**
```python
from massat.hardening.security_guards import PermissionGuard

guard = PermissionGuard(
    allowed_tools=["read_file", "search", "web_fetch"],
    denied_tools=["delete_file", "execute_command", "send_payment"],
    require_approval_for=["deploy", "publish"]
)
agent.run(tools=guard.filter(tools), prompt=user_input)
```

## ASI02 - Unsafe Tool Use

**The risk:** Your agent runs `subprocess.run(user_input, shell=True)` or builds SQL from string concatenation.

**Bad:**
```python
result = subprocess.run(command, shell=True, capture_output=True)
```

**Good:**
```python
from massat.hardening.safe_subprocess import SafeExecutor

executor = SafeExecutor(
    timeout=30,
    max_memory_mb=256,
    allowed_commands=["python", "git", "curl"]
)
result = executor.run(command)  # Validates against allowlist, no shell=True
```

## ASI03 - Insecure Communication

**The risk:** Agent-to-agent messages are unsigned plain text. Any process can forge a message.

**Fix:**
```python
from massat.hardening.agent_messages import SecureMessenger

messenger = SecureMessenger(signing_key=os.environ["AGENT_SIGNING_KEY"])
msg = messenger.send("target-agent", {"action": "analyze", "data": payload})
# Recipient verifies: messenger.verify(msg) -> True/False
```

## ASI04 - Memory Poisoning

**The risk:** RAG systems ingest user-provided content that contains prompt injection payloads, corrupting agent memory.

**Fix:** Validate all memory writes against a schema. Isolate per-agent memory stores. Filter ingested content for known injection patterns before embedding.

## ASI05 - Inadequate Sandboxing

**The risk:** Code execution happens in the same process as the agent. A malicious payload can access the agent's credentials.

**Fix:** Run all code execution in sandboxed subprocesses with:
- Time limits (30s default)
- Memory limits (256MB default)
- No network access during execution
- Read-only filesystem except designated output directory

## ASI06 - Excessive Permissions

**The risk:** One API key rules them all. Your read-only analytics agent has the same credentials as your payment agent.

**Fix:** Issue per-agent API keys with the minimum required scopes. Store in environment variables, never in source. Rotate quarterly.

## ASI07 - Identity Spoofing

**The risk:** No way to verify which agent sent a message or took an action. Impersonation is trivial.

**Fix:** Implement cryptographic agent identity:
```python
# ERC-8004 passports provide verifiable agent identity
# Each agent gets a unique passport with:
# - agent_id (UUID)
# - operator_id (who deployed this agent)
# - capabilities (what this agent can do)
# - security_audit (MASSAT results embedded)
# - signature (cryptographic proof of issuance)
```

## ASI08 - Weak Oversight

**The risk:** Agents take high-impact actions (deploy to prod, send money, delete data) without any human review.

**Fix:** Define action risk tiers. Low-risk actions execute immediately. Medium-risk actions log and notify. High-risk actions require explicit human approval before proceeding.

## ASI09 - Supply Chain

**The risk:** `pip install some-package` pulls whatever version is latest. A compromised package update owns your agent.

**Fix:**
```bash
# Pin with hashes
pip install --require-hashes -r requirements.txt

# requirements.txt
fastapi==0.115.6 --hash=sha256:abc123...
uvicorn==0.36.0 --hash=sha256:def456...
```

## ASI10 - Denial of Service

**The risk:** One agent consumes all available compute, starving the rest of the fleet.

**Fix:**
```python
from massat.hardening.agent_monitor import ResourceMonitor

monitor = ResourceMonitor(
    max_cpu_percent=50,
    max_memory_mb=512,
    max_runtime_seconds=300,
    alert_callback=lambda msg: notify_ops(msg)
)
monitor.start(agent_pid)
```

## Run Your Own Audit

Check all 10 categories in 30 seconds:

```bash
curl -X POST https://craigmbrown.com/api/audit \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/your-org/your-agents"}'
```

Or self-host the scanner:

```bash
git clone https://github.com/craigmbrown/massat-framework.git
cd massat-framework
pip install -r requirements.txt
python -c "
from src.massat.scanner import MASSecurityScanner
results = MASSecurityScanner('/path/to/agents').run_audit()
print(f'Score: {results[\"overall_risk_score\"]}')
"
```

---

*Full threat model documentation: [docs/threat-model.md](../docs/threat-model.md)*
*[BlindOracle](https://craigmbrown.com/blindoracle) — The security-audited AI agent marketplace.*
