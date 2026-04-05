# Self-Hosting MASSAT

Run the complete MASSAT audit infrastructure on your own servers.

## Quick Start

```bash
git clone https://github.com/craigmbrown/massat-framework.git
cd massat-framework
pip install -r requirements.txt
uvicorn src.massat.api:app --host 0.0.0.0 --port 8166
```

## Running the Scanner Directly

The scanner can be used as a Python library without the API:

```python
from src.massat.scanner import MASSecurityScanner

scanner = MASSecurityScanner(target_path="/path/to/your/agents")
results = scanner.run_audit(scope="quick")

print(f"Risk Score: {results['overall_risk_score']}")
for finding in results['findings']:
    print(f"  [{finding['severity']}] {finding['category']}: {finding['title']}")
```

## Systemd Service

For production, run as a systemd service:

```ini
# /etc/systemd/system/massat-audit-api.service
[Unit]
Description=MASSAT Audit API
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/massat-framework
ExecStart=/opt/massat-framework/venv/bin/uvicorn src.massat.api:app --host 127.0.0.1 --port 8166
Restart=always
RestartSec=5
Environment=MASSAT_ADMIN_KEY=your-secret-key

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now massat-audit-api
```

## Nginx Reverse Proxy

```nginx
location /api/audit {
    proxy_pass http://127.0.0.1:8166/audit;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 120s;
}
```

## Using the Hardening Modules

The `src/hardening/` directory contains drop-in security modules:

```python
# Apply tool allowlists to your agents
from src.hardening.tool_allowlist import ToolAllowlist
from src.hardening.security_guards import PermissionGuard
from src.hardening.safe_subprocess import SafeExecutor
from src.hardening.agent_messages import SecureMessenger
from src.hardening.agent_monitor import ResourceMonitor
```

Each module is a standalone Python file with no external dependencies beyond the standard library.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MASSAT_ADMIN_KEY` | `blindoracle-admin-2026` | Admin API key for `/leads` endpoint |
| `PYTHONPATH` | `.` | Should include the repo root |

## Contributing

1. Fork the repo
2. Add detection rules to `src/massat/scanner.py`
3. Add hardening modules to `src/hardening/`
4. Submit a PR with examples in `examples/`
