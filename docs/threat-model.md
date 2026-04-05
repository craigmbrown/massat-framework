# OWASP ASI01-10 Threat Model for AI Agents

MASSAT checks all 10 categories from the OWASP Agent Security Index. This document explains each threat, what MASSAT scans for, and how to remediate.

## ASI01 - Unbounded Agency

**Threat:** Agents can take any action without restriction, including destructive ones.

**What MASSAT checks:**
- Presence of tool deny-lists or allowlists
- Whether agents have explicit permission boundaries
- If high-impact actions require approval

**Remediation:**
```python
# src/hardening/security_guards.py
from hardening.security_guards import PermissionGuard

guard = PermissionGuard(
    allowed_tools=["read_file", "search", "web_fetch"],
    denied_tools=["delete_file", "execute_command", "send_payment"],
    require_approval_for=["deploy", "publish", "transfer"]
)
```

## ASI02 - Unsafe Tool Use

**Threat:** Agents execute shell commands, SQL queries, or file operations without validation.

**What MASSAT checks:**
- `subprocess.call`, `os.system`, `eval()`, `exec()` usage
- SQL string concatenation (injection vectors)
- File path traversal patterns

**Remediation:**
```python
# src/hardening/tool_allowlist.py
from hardening.tool_allowlist import ToolAllowlist

allowlist = ToolAllowlist(
    commands=["git status", "python -m pytest", "curl"],
    file_extensions=[".py", ".json", ".md"],
    blocked_patterns=["sudo", "chmod", "chown"]
)
```

## ASI03 - Insecure Communication

**Threat:** Inter-agent messages sent without encryption or authentication.

**What MASSAT checks:**
- HTTP vs HTTPS in agent-to-agent calls
- Message signing/verification
- Presence of authentication headers

**Remediation:**
```python
# src/hardening/agent_messages.py
from hardening.agent_messages import SecureMessenger

messenger = SecureMessenger(signing_key="your-hmac-key")
signed_msg = messenger.send("target-agent", {"action": "analyze", "data": "..."})
```

## ASI04 - Memory Poisoning

**Threat:** RAG systems accept unvalidated data that corrupts agent memory.

**What MASSAT checks:**
- Memory write operations without schema validation
- RAG ingestion without content filtering
- Cross-agent memory access without isolation

## ASI05 - Inadequate Sandboxing

**Threat:** Code execution happens in the same environment as the agent, allowing escapes.

**What MASSAT checks:**
- Direct `subprocess` calls without isolation
- Missing container/sandbox for code execution
- Shared filesystem access between agents

**Remediation:**
```python
# src/hardening/safe_subprocess.py
from hardening.safe_subprocess import SafeExecutor

executor = SafeExecutor(
    timeout=30,
    max_memory_mb=256,
    allowed_commands=["python", "node"]
)
result = executor.run("python script.py")
```

## ASI06 - Excessive Permissions

**Threat:** API keys have broader scope than needed (admin keys for read-only agents).

**What MASSAT checks:**
- API key scoping patterns
- Shared credentials across agents
- Hardcoded secrets in source

## ASI07 - Identity Spoofing

**Threat:** No way to verify which agent sent a message or took an action.

**What MASSAT checks:**
- Agent identity/authentication system
- Delegation proof chains
- Cryptographic identity (ERC-8004 passports)

## ASI08 - Weak Oversight

**Threat:** Agents take high-impact actions without human review.

**What MASSAT checks:**
- Human-in-the-loop for critical actions
- Approval workflows
- Audit logging completeness

## ASI09 - Supply Chain

**Threat:** Unpinned dependencies, unverified model sources, compromised packages.

**What MASSAT checks:**
- Dependency pinning with hash verification
- Known vulnerability databases (CVE)
- Model provenance documentation

## ASI10 - Denial of Service

**Threat:** Agents consume unlimited resources, starving other services.

**What MASSAT checks:**
- Per-agent resource limits (CPU, memory, time)
- Rate limiting on agent actions
- Queue depth limits

**Remediation:**
```python
# src/hardening/agent_monitor.py
from hardening.agent_monitor import ResourceMonitor

monitor = ResourceMonitor(
    max_cpu_percent=50,
    max_memory_mb=512,
    max_runtime_seconds=300,
    alert_callback=lambda: notify_ops("Agent exceeded limits")
)
```
