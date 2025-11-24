## Module 3: Authorization Analyzer

Automates authorization checks using only base URLs. The module crawls protected areas, detects privilege boundaries, and runs the five controls specified in the blueprint.

### Controls Implemented

| ID  | Control                        | Description |
| --- | ------------------------------ | ----------- |
| 018 | Role_Based_Access_Control      | Attempts to access admin-like pages without proper session |
| 019 | User_State_Management          | Checks whether sessions/cookies are required to view protected pages |
| 020 | Database_Permission_Controls   | Looks for IDOR/sequential ID vulnerabilities |
| 021 | OS_Level_Access_Restrictions   | Probes for directory traversal/static file exposure |
| 022 | API_Authorization              | Ensures API endpoints reject missing/malformed tokens |

### Workflow
1. **Discovery** – BFS crawl with admin/API hints and traversal markers.
2. **Classification** – record pages, protected pages (status 401/403 or admin keywords), API endpoints.
3. **Control Execution** – run the five controls using shared sessions.
4. **Evidence & Output** – structured `targets[]` entry per base URL with detailed findings.

### Usage

#### Single Target
```bash
python3 run_module.py --module=3 \
  --target=https://example.com \
  --depth=2 \
  --max-pages=60 \
  --debug
```

#### Multiple Targets
```
# authz_targets.txt
https://portal.dev.local
https://admin.qa.local
```
```bash
python3 run_module.py --module=3 \
  --target-file=authz_targets.txt \
  --depth=2 --max-pages=50
```

#### Standalone
```bash
python3 module3_authorization/main.py \
  --target=https://authz.staging \
  --depth=2 --max-pages=40
```

**Parameters**
- `--target`, `--target-file`: base URLs to scan (file format: one URL per line).
- `--depth`: BFS depth (default 2).
- `--max-pages`: per-target page limit (default 60).
- `--debug`: verbose logging.
- Credentials/tokens for API checks should be defined in `config/config.yaml`.

### Output
- JSON matches module schema with `targets[]`, `controls`, `evidence.pages`, `protected_pages`, `api_endpoints`, `findings`, and per-target summaries.

### Configuration
- Optional credential entries (`credentials.api_key`, etc.) from `config/config.yaml` are used for API tests.

### Testing
- `pytest module3_authorization/tests` (smoke tests for discovery and control helpers).

