# MASSAT API Reference

## Base URL

```
https://craigmbrown.com/api
```

## Authentication

The free tier requires no authentication. Rate limited to 10 audits/day per IP.

For unlimited access, include an `X-402-Payment` header with a valid ecash token.

## Endpoints

### POST /audit

Run a MASSAT security audit on an agent system.

**Request Body:**
```json
{
  "repo": "https://github.com/user/repo",   // GitHub repo URL (cloned + scanned)
  "path": "/local/path/to/agents",            // OR local filesystem path
  "config": {}                                 // OR inline configuration
}
```

Provide exactly one of `repo`, `path`, or `config`.

**Response (200):**
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
  "get_passport": "https://craigmbrown.com/api/onboard?audit_id=...",
  "subscribe": "https://craigmbrown.com/api/subscribe"
}
```

**Error Responses:**
- `400` - Invalid request (bad URL, missing fields)
- `408` - Clone timeout (repo took >60s)
- `413` - Repo too large (>100MB)
- `429` - Rate limit exceeded (10/day for free tier)

### GET /audit/{audit_id}

Retrieve the full JSON report for a completed audit.

**Response (200):** Full audit report with:
- `categories_assessed` - Array of ASI IDs checked
- `findings` - Array of findings with category, severity, title, recommendation
- `inventory` - Detected agents, tools, configs
- `duration_seconds` - How long the scan took

### POST /subscribe

Capture an email for security update notifications.

**Request Body:**
```json
{
  "email": "you@company.com",
  "name": "Your Name",           // optional
  "company": "Acme AI",          // optional
  "audit_id": "audit-...",       // optional, links to a completed audit
  "source": "api"                // optional, tracks where the lead came from
}
```

**Response (201 new / 200 existing):**
```json
{
  "status": "subscribed",
  "email": "you@company.com",
  "message": "You'll receive security insights and audit updates.",
  "next_steps": {
    "full_audit": "https://craigmbrown.com/api/audit",
    "get_passport": "https://craigmbrown.com/api/onboard"
  }
}
```

### GET /onboard

Initiate ERC-8004 passport onboarding after an audit.

**Query Parameters:**
- `audit_id` (required) - The audit to attach to the passport
- `agent_name` (required) - Name for the agent passport
- `operator_email` (required) - Operator contact email

### GET /health

Service health check.

**Response:**
```json
{
  "status": "ok",
  "version": "1.1",
  "service": "MASSAT Audit API",
  "audits_completed": 5,
  "leads_captured": 1,
  "framework": "MASSAT v1.0"
}
```

## Self-Hosting

Run the API locally:

```bash
git clone https://github.com/craigmbrown/massat-framework.git
cd massat-framework
pip install -r requirements.txt
uvicorn src.massat.api:app --host 0.0.0.0 --port 8166
```

Then audit your own agents:

```bash
curl -X POST http://localhost:8166/audit \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/your/agents"}'
```
