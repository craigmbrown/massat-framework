# Getting Started with MASSAT

## Quick Start (30 seconds)

Run a free security audit on any GitHub repository:

```bash
curl -X POST https://craigmbrown.com/api/audit \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/your-org/your-agent-repo"}'
```

## Understanding Your Results

The response includes:

- **risk_score** (1.0-10.0): Lower is better. Below 3.0 is "low risk".
- **risk_level**: `low`, `medium`, `high`, or `critical`
- **findings**: Grouped by OWASP ASI category with severity and recommendations
- **report_url**: Link to a detailed HTML dashboard

## What Gets Checked

MASSAT scans your codebase for patterns matching all 10 OWASP Agent Security Index categories:

1. Code patterns (subprocess calls, eval, exec)
2. Configuration (API key handling, permission scoping)
3. Dependencies (pinning, known vulnerabilities)
4. Architecture (isolation, sandboxing, monitoring)
5. Identity (authentication, delegation, proofs)

## Next Steps

After your audit:

1. **Fix medium/high findings** using the recommendations in your report
2. **Re-audit** to verify your score improved
3. **Get a passport**: `curl https://craigmbrown.com/api/onboard?audit_id=YOUR_ID` for an ERC-8004 agent passport
4. **Subscribe**: `curl -X POST https://craigmbrown.com/api/subscribe -d '{"email":"you@co.com"}'` for weekly security digests
5. **Go continuous**: $99/mo for daily automated audits with trend tracking

## Links

- [API Reference](api-reference.md)
- [OWASP ASI Threat Model](threat-model.md)
- [BlindOracle Marketplace](https://craigmbrown.com/blindoracle)
