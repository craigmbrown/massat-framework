# Security Auditing a 94-Agent Fleet: Before & After MASSAT

*Published: April 5, 2026 | Author: Craig Brown*

## The Problem

We run a 94-agent AI fleet across 5 fleet types: Single File Agents (19), Orchestrator agents (13), Communication agents (6), BlindOracle marketplace agents (25), and MCP tool servers (10+). Before MASSAT, we had no systematic way to audit them for security vulnerabilities.

The OWASP Foundation published the Agent Security Index (ASI01-ASI10) in late 2025, covering 10 threat categories specific to AI agents. We built MASSAT to check all 10.

## Before: Score 4.3 (Medium Risk)

Initial audit of the full fleet revealed:
- **0 critical** findings (no active exploits)
- **0 high** findings (no immediate threats)
- **6 medium** findings per fleet (common patterns)
- **4 low** findings per fleet (best practice gaps)

The medium findings clustered around:
1. **ASI01 (Unbounded Agency)** - 4.8 score - Agents had broad tool access with no deny-lists
2. **ASI02 (Unsafe Tool Use)** - 4.8 score - Shell commands available without allowlists
3. **ASI06 (Excessive Permissions)** - API keys scoped too broadly
4. **ASI07 (Identity Spoofing)** - No cryptographic agent identity

## The Hardening Sprint

Over 48 hours we deployed 5 security modules across 30 agents:

1. **`security_guards.py`** - Permission boundaries for ASI01/03/06/09
2. **`tool_allowlist.py`** - Explicit tool allowlists for ASI02
3. **`safe_subprocess.py`** - Sandboxed command execution for ASI05
4. **`agent_messages.py`** - Authenticated inter-agent messaging for ASI07
5. **`agent_monitor.py`** - Resource monitoring and rate limiting for ASI10

Plus: 22 dependencies pinned with hash verification (ASI09).

## After: Score 4.0 (Medium Risk, Improved)

- ASI01: 4.8 -> 3.2 (permission boundaries deployed)
- ASI02: 4.8 -> 3.2 (tool allowlists active)
- Overall: 4.3 -> 4.0 (15% improvement in 48 hours)

## Try It Yourself

Run a free MASSAT audit on your own agent system:

```bash
curl -X POST https://craigmbrown.com/api/audit \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/your-org/your-agent-repo"}'
```

Full whitepaper: [Security Auditing a 94-Agent Fleet](https://tinyurl.com/2dadrqrv)

---

*Craig Brown builds [BlindOracle](https://craigmbrown.com/blindoracle), the security-audited AI agent marketplace.*
