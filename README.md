# MASSAT - Multi-Agent System Security Audit Toolkit

[![MASSAT Audited](https://img.shields.io/badge/MASSAT-Security%20Audited-brightgreen)](https://craigmbrown.com/blindoracle)
[![OWASP ASI](https://img.shields.io/badge/OWASP-ASI01--ASI10-blue)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The open-source security audit framework for AI agent systems. Covers all 10 OWASP Agent Security Index (ASI) categories. Used in production to audit a 94-agent fleet.

## Get a Free Audit in 30 Seconds

```bash
curl -X POST https://craigmbrown.com/api/audit \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/your-org/your-agent-repo"}'
```

Returns JSON with risk score, findings by severity, and link to full HTML report.

## What MASSAT Checks

| Category | OWASP ID | What It Catches |
|----------|----------|----------------|
| Unbounded Agency | ASI01 | Agents with no permission boundaries or tool restrictions |
| Unsafe Tool Use | ASI02 | Direct shell access, unvalidated file operations, SQL injection |
| Insecure Communication | ASI03 | Unencrypted inter-agent messaging, missing TLS |
| Memory Poisoning | ASI04 | RAG injection vectors, unvalidated memory writes |
| Inadequate Sandboxing | ASI05 | Code execution without isolation, container escapes |
| Excessive Permissions | ASI06 | Over-scoped API keys, admin privileges on read-only agents |
| Identity Spoofing | ASI07 | No agent authentication, missing delegation proofs |
| Weak Oversight | ASI08 | No human-in-the-loop for critical actions |
| Supply Chain | ASI09 | Unpinned dependencies, unverified model sources |
| Denial of Service | ASI10 | No rate limiting, unbounded resource consumption |

## API Reference

### `POST /audit` - Run Security Audit

```bash
# Audit a GitHub repo (free, 10/day)
curl -X POST https://craigmbrown.com/api/audit \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/user/agent-repo"}'

# Audit with payment (unlimited, full scope)
curl -X POST https://craigmbrown.com/api/audit \
  -H "Content-Type: application/json" \
  -H "X-402-Payment: <ecash-token>" \
  -d '{"repo": "https://github.com/user/agent-repo"}'
```

**Response:**
```json
{
  "audit_id": "audit-20260405-004858-f31d9003",
  "risk_score": 4.3,
  "risk_level": "medium",
  "critical": 0,
  "high": 0,
  "medium": 6,
  "low": 4,
  "report_url": "https://craigmbrown.com/audits/audit-20260405-004858-f31d9003.html",
  "get_passport": "https://craigmbrown.com/api/onboard?audit_id=audit-20260405-004858-f31d9003",
  "subscribe": "https://craigmbrown.com/api/subscribe"
}
```

### `POST /subscribe` - Get Security Updates

```bash
curl -X POST https://craigmbrown.com/api/subscribe \
  -H "Content-Type: application/json" \
  -d '{"email": "you@company.com", "name": "Your Name", "company": "Acme AI"}'
```

### `GET /audit/{id}` - Retrieve Full Report

```bash
curl https://craigmbrown.com/api/audit/audit-20260405-004858-f31d9003
```

### `GET /health` - Service Status

```bash
curl https://craigmbrown.com/api/audit/health
```

## Pricing

| Tier | Price | What You Get |
|------|-------|-------------|
| Free | $0 | 10 audits/day, quick scope, JSON + HTML report |
| Per-Audit | $5 | Full scope, all 10 ASI categories, detailed recommendations |
| Continuous | $99/mo | Daily automated audits, trend tracking, alerts |
| Enterprise | $499/mo | Compliance reports (NIST AI RMF, ISO 42001), SLA, dedicated support |

Payment via [x402 HTTP protocol](https://github.com/coinbase/x402) with Fedimint ecash.

## Blog Posts

- [Security Auditing a 94-Agent Fleet: Before & After MASSAT](blog/security-auditing-94-agent-fleet.md) - How we went from 4.3 to 4.0 risk score across 30 hardened agents
- [93% of AI Agents Have Zero Security](blog/93-percent-zero-security.md) - Why agent identity and audit infrastructure matters now
- [OWASP ASI01-10 for AI Agent Builders](blog/owasp-asi-guide.md) - Practical guide to each threat category with code examples

## Real Audit Examples

See [`examples/`](examples/) for sanitized production audit reports from 5 different fleet types:
- **SFA Fleet** (19 Single File Agents) - Score: 4.3
- **Orchestrator Fleet** (13 coordination agents) - Score: 4.3
- **Communication Fleet** (6 WhatsApp/notification agents) - Score: 4.3
- **Marketplace Fleet** (25 BlindOracle DeFi agents) - Score: 4.3
- **MCP Server** (Context Oracle tool server) - Score: 4.5

## Connection to BlindOracle

MASSAT is the security layer for the [BlindOracle](https://craigmbrown.com/blindoracle) agent marketplace:

- Every marketplace agent must pass a MASSAT audit before activation
- Audit results are embedded in [ERC-8004 agent passports](https://github.com/craigmbrown/blindoracle-docs)
- Continuous auditing available for marketplace operators ($99/mo)
- Delegation proofs (15 kinds) are verified against MASSAT findings

```
Agent Onboarding Flow:
  1. curl /api/audit     -> Get security score
  2. curl /api/onboard   -> Get ERC-8004 passport (includes audit results)
  3. curl /api/subscribe  -> Join mailing list for security updates
  4. Marketplace active   -> Agent listed on BlindOracle with verified badge
```

## Repository Structure

```
massat-framework/
  README.md              # This file
  LICENSE                # MIT
  api/
    openapi.yaml         # OpenAPI spec for the audit API
  blog/
    security-auditing-94-agent-fleet.md
    93-percent-zero-security.md
    owasp-asi-guide.md
  examples/
    audit-reports/       # Sanitized production audit JSON
    curl/                # Ready-to-run curl examples
  docs/
    getting-started.md   # Quick start guide
    api-reference.md     # Full API docs
    threat-model.md      # OWASP ASI01-10 detailed threat model
  assets/
    massat-badge.svg     # Badge for GitHub READMEs
```

## Links

- **Live API**: [craigmbrown.com/api/audit](https://craigmbrown.com/api/audit)
- **BlindOracle Marketplace**: [craigmbrown.com/blindoracle](https://craigmbrown.com/blindoracle)
- **Agent Passports**: [blindoracle-docs](https://github.com/craigmbrown/blindoracle-docs)
- **Whitepaper**: [Security Auditing a 94-Agent Fleet](https://tinyurl.com/2dadrqrv)

## License

MIT - See [LICENSE](LICENSE) for details.

---

Built by [Craig Brown](https://craigmbrown.com) | Powered by [BlindOracle](https://craigmbrown.com/blindoracle)
