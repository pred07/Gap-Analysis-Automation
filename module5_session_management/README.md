# Module 5: Session Management Analyzer

## Overview

Module 5 automates the assessment of **7 security controls** related to session management, cookie security, and session fixation prevention. This module validates session handling mechanisms, cookie flags, and token management.

## Controls Covered

| Control ID | Control Name | Description | Severity |
|------------|--------------|-------------|----------|
| 035 | Session_Timeout | Session timeout implementation | Medium |
| 036 | Session_ID_Randomness | Session ID randomness and unpredictability | High |
| 037 | Session_Not_In_URL | Session ID not exposed in URL | High |
| 038 | Cookie_Flags | Secure cookie flags (Secure, HttpOnly, SameSite) | High |
| 039 | Server_Side_Validation | Server-side session validation | Critical |
| 040 | Token_Expiry | Token expiration and refresh | High |
| 041 | Session_Fixation_Prevention | Session fixation attack prevention | High |

## Tools Used

- **Python requests** - HTTP/HTTPS testing and session handling
- **BeautifulSoup** - HTML parsing
- **Custom analyzers** - Cookie inspection and session validation

## Usage

### Basic Usage

```bash
# Run against single target
python run_module.py --module=5 --target https://example.com

# Run with debug logging
python run_module.py --module=5 --target https://example.com --debug

# Run against multiple targets
python run_module.py --module=5 --target-file targets.txt
```

### Advanced Options

```bash
python -m module5_session_management.main \
  --target https://example.com \
  --depth 3 \
  --max-pages 60 \
  --debug
```

## Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | Single target URL | From config |
| `--target-file` | File with URLs (one per line) | None |
| `--depth` | Discovery crawl depth | 2 |
| `--max-pages` | Maximum pages to crawl | 40 |
| `--debug` | Enable verbose logging | False |
| `--config-dir` | Configuration directory | config |

## Output Format

The module generates a JSON file at `outputs/module5.json`:

```json
{
  "module": "Session Management Analyzer",
  "module_number": 5,
  "timestamp": "2025-11-25T09:15:00Z",
  "targets": [
    {
      "target": "https://example.com",
      "controls": {
        "Session_Timeout": "pass",
        "Session_ID_Randomness": "pass",
        "Session_Not_In_URL": "pass",
        "Cookie_Flags": "fail",
        "Server_Side_Validation": "pass",
        "Token_Expiry": "not_tested",
        "Session_Fixation_Prevention": "pass"
      },
      "evidence": {
        "pages": [...],
        "login_pages": [...],
        "findings": [...]
      },
      "summary": {
        "total": 7,
        "passed": 5,
        "failed": 1,
        "not_tested": 1
      }
    }
  ],
  "summary": {
    "total_controls": 7,
    "passed": 5,
    "failed": 1,
    "not_tested": 1
  }
}
```

## Control Evaluation Logic

### Session Timeout (035)
- Checks if session cookies have expiry times
- Validates timeout implementation
- **Pass**: Cookies have expiry set
- **Fail**: No timeout detected

### Session ID Randomness (036)
- Analyzes session ID length and complexity
- Detects weak patterns (numeric-only, too short)
- **Pass**: Strong, random session IDs (16+ chars, mixed)
- **Fail**: Weak session IDs detected

### Session Not In URL (037)
- Scans URLs for session ID parameters
- Detects patterns like `?session=`, `?sid=`, `?jsessionid=`
- **Pass**: No session IDs in URLs
- **Fail**: Session IDs exposed in URLs

### Cookie Flags (038)
- Validates Secure, HttpOnly, and SameSite flags
- Checks session and authentication cookies
- **Pass**: All security flags present
- **Fail**: Missing security flags

### Server-Side Validation (039)
- Tests protected pages without authentication
- Checks for proper access control
- **Pass**: Protected pages require authentication
- **Fail**: Protected pages accessible without session

### Token Expiry (040)
- Checks JWT and bearer tokens for expiry
- Validates token cookies have expiration
- **Pass**: Tokens have expiry set
- **Fail**: Tokens without expiry

### Session Fixation Prevention (041)
- Tests if session ID changes after login
- Validates session regeneration
- **Pass**: Session ID regenerated
- **Fail**: Session ID not changed (fixation risk)

## Configuration

### Credentials (config/config.yaml)

For session timeout and fixation testing:

```yaml
credentials:
  username: "test_user"
  password: "test_password"
```

## Execution Time

- **Standard scan**: 3-8 minutes
- **With deep crawling**: 5-12 minutes

## Examples

### Example 1: Basic Session Check

```bash
python run_module.py --module=5 --target https://example.com --debug
```

### Example 2: Deep Session Analysis

```bash
python run_module.py --module=5 \
  --target https://app.example.com \
  --depth 3 \
  --max-pages 60
```

### Example 3: Multiple Targets

Create `targets.txt`:
```
https://app.example.com
https://admin.example.com
```

Run:
```bash
python run_module.py --module=5 --target-file targets.txt
```

## Integration

### With run_all.sh

Module 5 is automatically included in the full system scan:

```bash
./run_all.sh
```

### With CI/CD

```yaml
- name: Run Module 5
  run: |
    python run_module.py --module=5 --target ${{ secrets.TARGET_URL }}
```

## Troubleshooting

### No Session Cookies Found

```
Warning: No session cookies detected
```

**Solution**: Ensure the target has login functionality or session-based features.

### Credentials Not Provided

```
Warning: No credentials provided for testing
```

**Solution**: Add credentials to `config/config.yaml`:
```yaml
credentials:
  username: "test_user"
  password: "test_password"
```

## License

Part of the Security Controls GAP Analysis System - Phase 1
