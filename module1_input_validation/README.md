# Module 1: Input & Data Validation Analyzer

## Overview

Module 1 tests for injection flaws and input validation vulnerabilities using a combination of industry-standard tools and custom fuzzing techniques.

## Controls Tested (10)

| ID  | Control Name                   | Description                          | Severity |
|-----|--------------------------------|--------------------------------------|----------|
| 001 | SQL Injection                  | SQL injection vulnerability testing  | Critical |
| 002 | XSS                           | Cross-Site Scripting testing         | High     |
| 003 | HTTP Request Smuggling        | HTTP protocol manipulation testing   | High     |
| 004 | Client-Side Validation        | Client validation bypass testing     | Medium   |
| 005 | File Upload Validation        | File upload restriction testing      | High     |
| 006 | XML Validation                | XML injection testing                | Medium   |
| 007 | Schema Validation             | Input schema validation testing      | Medium   |
| 008 | Content-Type Validation       | Content-Type header testing          | Low      |
| 009 | Buffer Overflow (Basic)       | Basic buffer overflow testing        | High     |
| 010 | DOS (Basic)                   | Basic denial of service testing      | Medium   |

## Tools Used

### 1. OWASP ZAP
- **Purpose**: Web application scanning
- **Tests**: SQL injection, XSS, and general web vulnerabilities
- **Execution Time**: 5-10 minutes
- **Path**: Configured in `config/tool_paths.yaml`

### 2. Nikto
- **Purpose**: Web server scanning
- **Tests**: Server misconfigurations, outdated software
- **Execution Time**: 3-8 minutes
- **Path**: Usually `/usr/bin/nikto`

### 3. Custom Python Fuzzer
- **Purpose**: Targeted payload testing
- **Tests**: SQLi, XSS, file upload, XML injection, buffer overflow
- **Execution Time**: 2-5 minutes
- **Implementation**: `fuzzer.py`

## Usage

### Run Module 1 Standalone

```bash
# Basic run
python3 module1_input_validation/main.py

# With custom target
python3 module1_input_validation/main.py --target https://example.com

# With debug mode
python3 module1_input_validation/main.py --debug
```

### Run from Parent Directory

```bash
# Using run_module.py (when created)
python3 run_module.py --module=1

# With options
python3 run_module.py --module=1 --target=https://example.com --debug
```

### Programmatic Usage

```python
from module1_input_validation import Module1Analyzer
from common import load_config, get_logger

# Initialize
config = load_config()
logger = get_logger("module1")

# Create analyzer
analyzer = Module1Analyzer(config, logger)

# Execute tests
results = analyzer.execute()

# Check results
print(f"Controls tested: {len(results['controls'])}")
print(f"Output file: {results['output_file']}")
```

## Configuration

### config/config.yaml

```yaml
target:
  url: "https://your-target.com"

execution:
  timeout: 600  # Module 1 needs longer timeout for ZAP
```

### config/tool_paths.yaml

```yaml
tools:
  zap: "/opt/zaproxy/zap.sh"
  nikto: "/usr/bin/nikto"
```

## Output

### JSON Output Structure

```json
{
  "module": "Input & Data Validation",
  "timestamp": "2025-11-20T10:30:00Z",
  "target": "https://example.com",
  "controls": {
    "SQL_Injection": "pass",
    "XSS": "fail",
    "HTTP_Request_Smuggling": "pass",
    "Client_Side_Validation": "pass",
    "File_Upload_Validation": "fail",
    "XML_Validation": "pass",
    "Schema_Validation": "pass",
    "Content_Type_Validation": "pass",
    "Buffer_Overflow_Basic": "pass",
    "DOS_Basic": "pass"
  },
  "evidence": {
    "logs": "logs/module1.log",
    "reports": [
      "outputs/zap_scan_report.xml",
      "outputs/nikto_scan_report.txt"
    ],
    "details": "Module 1 completed. Tested 10/10 controls. Pass rate: 80.0%"
  },
  "summary": {
    "total": 10,
    "passed": 8,
    "failed": 2,
    "not_tested": 0
  }
}
```

### Output Location

- **JSON Report**: `outputs/input_and_data_validation.json`
- **ZAP Report**: `outputs/zap_scan_report.xml`
- **Nikto Report**: `outputs/nikto_scan_report.txt`
- **Logs**: `logs/module1.log`

## Test Methodology

### SQL Injection Testing
1. ZAP active scan with SQLi rules
2. Custom fuzzer with 10+ payloads
3. Error message analysis
4. Database error detection

### XSS Testing
1. ZAP XSS scan
2. Custom fuzzer with reflected XSS payloads
3. DOM-based XSS detection
4. Response analysis for payload reflection

### File Upload Testing
1. Dangerous extension testing (.php, .asp, .jsp, etc.)
2. Content-Type bypass attempts
3. Double extension testing
4. MIME type validation

### Buffer Overflow Testing
1. Large input string injection
2. Response time analysis
3. Error code monitoring
4. Connection stability testing

## Troubleshooting

### ZAP Not Found

```bash
# Check ZAP installation
ls -la /opt/zaproxy/zap.sh

# Update path in config/tool_paths.yaml
tools:
  zap: "/your/path/to/zap.sh"
```

### Nikto Scan Timeout

```bash
# Increase timeout in config/config.yaml
modules:
  module1:
    timeout: 900  # 15 minutes
```

### SSL Certificate Errors

```bash
# Disable SSL verification (testing only)
# Add to fuzzer.py: verify=False in requests
```

### Permission Issues

```bash
# Fix output directory permissions
chmod 755 outputs logs
```

## Performance

### Typical Execution Times

| Component        | Time      |
|------------------|-----------|
| ZAP Quick Scan   | 5-10 min  |
| Nikto Scan       | 3-8 min   |
| Custom Fuzzer    | 2-5 min   |
| **Total**        | **10-23 min** |

### Optimization Tips

1. **Use ZAP Quick Scan** instead of active scan for faster results
2. **Limit Nikto tuning** to specific categories
3. **Reduce fuzzer payloads** for time-sensitive scans
4. **Enable parallel execution** in config

## Security Considerations

### Safe Testing Practices

1. **Get authorization** before scanning any target
2. **Use test environments** when possible
3. **Rate limit requests** to avoid DoS
4. **Review legal implications** of security testing

### Payload Safety

- All fuzzing payloads are detection-only
- No exploit code is executed
- No persistent changes to target
- Payloads are sanitized in logs

## Integration

### CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
- name: Run Module 1
  run: |
    python3 run_module.py --module=1 --target=${{ secrets.TARGET_URL }}
```

### Custom Extensions

```python
# Add custom fuzzer payloads
from module1_input_validation.fuzzer import InputFuzzer

fuzzer = InputFuzzer(target_url)
fuzzer.SQL_PAYLOADS.append("YOUR_CUSTOM_PAYLOAD")
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Nikto Documentation](https://github.com/sullo/nikto)
- [SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

## Support

For issues or questions:
- Check logs: `logs/module1.log`
- Review configuration: `config/config.yaml`
- Enable debug mode: `--debug` flag
