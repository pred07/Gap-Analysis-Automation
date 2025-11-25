# Module 6: Logging & Monitoring Analyzer

## Overview

Module 6 automates the assessment of **8 security controls** related to logging, monitoring, and audit trails. This module analyzes log files and documentation to verify comprehensive logging practices, log integrity, and retention policies.

## Controls Covered

| Control ID | Control Name | Description | Severity |
|------------|--------------|-------------|----------|
| 042 | Authentication_Logging | Authentication events logging | High |
| 043 | Authorization_Logging | Authorization events logging | High |
| 044 | Access_Logging | System access logging | Medium |
| 045 | Error_Logging | Error and exception logging | Medium |
| 046 | Security_Event_Logging | Security events logging | High |
| 047 | Audit_Trail_Completeness | Complete audit trail maintenance | High |
| 048 | Log_Integrity | Log integrity and tamper protection | High |
| 049 | Log_Retention | Log retention and archival | Medium |

## Tools Used

- **Log file parsers** - Custom Python parsers
- **Keyword matchers** - Pattern-based log analysis
- **Document analyzers** - Policy extraction

## Usage

### Basic Usage

```bash
# Analyze log files from directory
python run_module.py --module=6 --log-path /var/log/application/

# Analyze with policy documents
python run_module.py --module=6 \
  --log-path /var/log/ \
  --document-path evidence/logging_policies/

# Attempt log discovery from target
python run_module.py --module=6 --target https://example.com
```

### Advanced Options

```bash
python -m module6_logging_monitoring.main \
  --log-path /var/log/myapp/ \
  --document-path evidence/policies/ \
  --debug
```

## Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | Target URL for log discovery | From config |
| `--log-path` | Path to log files or directory | None |
| `--document-path` | Path to policy documents | None |
| `--debug` | Enable verbose logging | False |
| `--config-dir` | Configuration directory | config |

## Output Format

The module generates a JSON file at `outputs/module6.json`:

```json
{
  "module": "Logging & Monitoring Analyzer",
  "module_number": 6,
  "timestamp": "2025-11-25T09:25:00Z",
  "controls": {
    "Authentication_Logging": "pass",
    "Authorization_Logging": "pass",
    "Access_Logging": "pass",
    "Error_Logging": "pass",
    "Security_Event_Logging": "fail",
    "Audit_Trail_Completeness": "pass",
    "Log_Integrity": "not_tested",
    "Log_Retention": "pass"
  },
  "evidence": {
    "log_files": [...],
    "documents": [...],
    "findings": [...]
  },
  "summary": {
    "total": 8,
    "passed": 6,
    "failed": 1,
    "not_tested": 1
  }
}
```

## Control Evaluation Logic

### Authentication Logging (042)
- Searches for authentication keywords in logs
- Keywords: login, logout, authenticate, sign in, sign out
- **Pass**: Authentication events found in logs
- **Fail**: No authentication logging detected

### Authorization Logging (043)
- Searches for authorization keywords
- Keywords: access denied, permission denied, unauthorized, authorized
- **Pass**: Authorization events found
- **Fail**: No authorization logging

### Access Logging (044)
- Looks for access log patterns
- Patterns: IP addresses, HTTP methods, status codes
- **Pass**: Access logs detected
- **Fail**: No access logging

### Error Logging (045)
- Searches for error keywords
- Keywords: error, exception, fatal, critical, warning
- **Pass**: Error logging found
- **Fail**: No error logging

### Security Event Logging (046)
- Searches for security event keywords
- Keywords: security, attack, intrusion, breach, vulnerability
- **Pass**: Security events logged
- **Fail**: No security event logging

### Audit Trail Completeness (047)
- Checks for essential audit components
- Components: timestamp, user, action, result
- **Pass**: All components present
- **Fail**: Missing audit trail components

### Log Integrity (048)
- Checks for integrity protection measures
- Keywords: hash, checksum, digital signature, immutable
- **Pass**: Integrity measures found
- **Fail**: No integrity protection

### Log Retention (049)
- Checks for retention policies
- Keywords: retention, archival, rotation, backup
- **Pass**: Retention policy found
- **Fail**: No retention policy

## Log File Requirements

### Supported Log Formats
- Plain text (.log, .txt)
- Any text-based log format

### Sample Log Structure

```
2025-11-25 09:15:23 [INFO] User 'admin' logged in from 192.168.1.100
2025-11-25 09:16:45 [WARN] Failed login attempt for user 'test' from 192.168.1.200
2025-11-25 09:17:12 [ERROR] Database connection failed: timeout
2025-11-25 09:18:30 [INFO] User 'admin' accessed /admin/users
```

## Examples

### Example 1: Analyze Application Logs

```bash
python run_module.py --module=6 --log-path /var/log/myapp/
```

### Example 2: Analyze with Policies

```bash
# Create policy document
mkdir -p evidence/logging_policies
cat > evidence/logging_policies/policy.txt << EOF
Logging Policy:
- All authentication events must be logged
- Logs must be retained for 90 days
- Log integrity protected with SHA-256 hashes
EOF

# Run analysis
python run_module.py --module=6 \
  --log-path /var/log/myapp/ \
  --document-path evidence/logging_policies/
```

### Example 3: Create Test Logs

```bash
# Create sample log file
mkdir -p test_logs
cat > test_logs/app.log << EOF
2025-11-25 09:00:00 [INFO] Application started
2025-11-25 09:01:15 [INFO] User 'admin' logged in successfully
2025-11-25 09:02:30 [WARN] Failed login attempt for user 'test'
2025-11-25 09:03:45 [ERROR] Database query failed: connection timeout
2025-11-25 09:05:00 [INFO] Security scan completed: no threats detected
EOF

# Analyze
python run_module.py --module=6 --log-path test_logs/
```

## Integration

### With run_all.sh

Module 6 is automatically included in the full system scan:

```bash
./run_all.sh
```

### With CI/CD

```yaml
- name: Run Module 6
  run: |
    python run_module.py --module=6 --log-path /var/log/app/
```

## Troubleshooting

### No Log Files Found

```
Warning: No log files provided
```

**Solution**: Specify log path:
```bash
python run_module.py --module=6 --log-path /var/log/application/
```

### Log File Too Large

The module reads only the first 100KB of each log file to avoid memory issues.

**Solution**: For large logs, consider:
- Using log rotation
- Analyzing recent logs only
- Splitting logs into smaller files

## License

Part of the Security Controls GAP Analysis System - Phase 1
