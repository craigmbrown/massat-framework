---
name: BlindOracle MASSAT Security Audit
description: Run OWASP ASI01-ASI10 security assessments on multi-agent systems via API
version: 1.0.0
author: craigmbrown
compatible_with:
  - hermes
  - claude-code
  - cursor
  - codex
tags:
  - security
  - audit
  - owasp
  - agents
---

# BlindOracle MASSAT Security Audit

## When to Use

Use this skill when you need to assess the security posture of a multi-agent AI system. It covers all 10 OWASP Agentic AI threat categories including prompt injection, data exfiltration, broken access control, and more.

## Quick Reference

**API Endpoint:** `POST https://craigmbrown.com/api/v1/massat/audit`

**Free scan (ASI01-03):**
```bash
curl -X POST https://craigmbrown.com/api/v1/massat/audit \
  -H "Content-Type: application/json" \
  -d '{"target": "<repo-url-or-path>", "scope": "quick"}'
```

**Full audit (ASI01-10, $50/use):**
```bash
curl -X POST https://craigmbrown.com/api/v1/massat/audit \
  -H "Content-Type: application/json" \
  -H "X-Payment: x402" \
  -d '{"target": "<repo-url-or-path>", "scope": "full"}'
```

## Procedure

1. Identify the target agent system (GitHub repo URL or local path)
2. Decide scope: `quick` (free, ASI01-03) or `full` ($50, ASI01-10)
3. Call the API endpoint with the target and scope
4. Parse the JSON response for `overall_score`, `risk_level`, and `categories`
5. Review `remediation_priority` array for highest-impact fixes
6. Access the full HTML report at the `report_url` in the response

## Pitfalls

- Remote URL scanning requires the hosted API; local path scanning uses the open-source CLI
- Free tier is limited to 10 scans/day per IP
- Large repos (>100MB) may timeout; use `scope: "quick"` for initial assessment
- The API returns scores 0-100 where higher is better (100 = no findings)

## Verification

A successful audit returns HTTP 200 with `overall_score` in the response body. Verify by checking that `categories` contains entries for the requested scope (3 for quick, 10 for full).

## Links

- Open-source framework: https://github.com/craigmbrown/massat-framework
- Hosted API docs: https://craigmbrown.com/blindoracle/
