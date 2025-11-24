# Module 2: Authentication Analyzer

Module 2 verifies the authentication surface of a target application using only base URLs (no manual endpoint lists). It crawls login-related pages, classifies forms, and runs seven authentication controls defined in the Phase 1 blueprint.

## Controls Covered

| ID  | Control                     | Methodology (high level)                                |
| --- | --------------------------- | ------------------------------------------------------- |
| 011 | Password_Policy             | Parse login/password-change forms for policy hints      |
| 012 | Login_Error_Messages        | Compare verbose vs generic login errors                 |
| 013 | Last_Login_Message          | Detect “last login” messaging post-authentication       |
| 014 | Password_Encryption_Transit | Ensure login forms submit over HTTPS                    |
| 015 | Password_Change_Process     | Attempt weak password changes to test enforcement       |
| 016 | Multi_Factor_Authentication | Detect MFA prompts, tokens, and textual signals         |
| 017 | API_Authentication          | Probe API endpoints w/without tokens for proper gating  |

## Workflow

1. **Target ingestion** – via `--target` or `--target-file`.
2. **Auth discovery** – BFS crawl (depth configurable) plus login keyword detection; forms are classified (login, password change, MFA, API).
3. **Control execution** – each control module inspects the discovered forms/endpoints, using credentials from `config/config.yaml` when available.
4. **Evidence packaging** – per-target record includes discovered forms/pages, findings per control, and summary counts.

## Usage

### Single Target

```bash
python3 run_module.py --module=2 \
  --target=https://login.example.com \
  --depth=2 \
  --max-pages=40 \
  --debug
```

### Multiple Targets

```
# auth_targets.txt
https://auth.dev.local
https://auth.qa.local
```

```bash
python3 run_module.py --module=2 \
  --target-file=auth_targets.txt \
  --depth=2 --max-pages=50
```

### Standalone

```bash
python3 module2_authentication/main.py \
  --target=https://auth.staging \
  --depth=2 --max-pages=30
```

**Parameter summary**

- `--target`, `--target-file`: base URLs to assess (file must have one URL per line).
- `--depth`: crawling depth (default 2).
- `--max-pages`: maximum pages/forms per target (defaults to 40).
- `--config-dir`: override config path if needed (default `./config`).
- Credentials (`credentials.username`, `password`, `api_key`) should be placed in `config/config.yaml`.

## Output

- JSON slugged as `authentication_analyzer.json` (via `common.JSONWriter`) with:
  - `targets[]`: each target has `controls`, `evidence.pages/forms`, `findings`, and `summary`.
  - `summary`: overall totals.
- Schema validated via `common.schema_validator.MODULE_OUTPUT_SCHEMA`.

## Configuration

- `config/config.yaml` → `credentials.username`, `credentials.password`, `credentials.api_key`.
- Optional overrides (add if needed):
  ```yaml
  modules:
    module2:
      discovery:
        depth: 2
        max_pages: 40
  ```

## Testing

- `pytest module2_authentication/tests` (smoke tests for discovery + password policy + login errors).

## Notes / Safety

- Module 2 uses only lightweight HTTP requests—no destructive actions. Password-change checks submit intentionally weak data but do not persist real changes (requests are best run against staging/test environments).
- MFA detection is heuristic (based on textual cues).
- API authentication check requires `credentials.api_key` if you want to test successful token usage. Without a token, it only verifies unauthenticated access is blocked (`not_tested` otherwise).

