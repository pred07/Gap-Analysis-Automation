# Security Controls GAP Analysis System - Module Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [Module 1: Input & Data Validation](#module-1-input--data-validation)
3. [Module 2: Authentication](#module-2-authentication)
4. [Module 3: Authorization](#module-3-authorization)
5. [Module 4: Sensitive Data Protection](#module-4-sensitive-data-protection)
6. [Module 5: Session Management](#module-5-session-management)
7. [Module 6: Logging & Monitoring](#module-6-logging--monitoring)
8. [Module 7: API Security](#module-7-api-security)
9. [Module 8: Infrastructure & Containers](#module-8-infrastructure--containers)
10. [Usage Guide](#usage-guide)

---

## System Overview

### Purpose

The Security Controls GAP Analysis System is an automated security testing framework that validates 65 security controls across 8 modules. It identifies security gaps in web applications, APIs, and infrastructure.

### Architecture

- **8 Modules** - Each focuses on a specific security domain
- **65 Controls** - Individual security checks
- **Modular Design** - Run modules independently or together
- **JSON Output** - Structured results for automation

### Total Coverage

| Category | Controls | Module |
|----------|----------|--------|
| Input Validation | 10 | Module 1 |
| Authentication | 7 | Module 2 |
| Authorization | 5 | Module 3 |
| Data Protection | 12 | Module 4 |
| Session Management | 7 | Module 5 |
| Logging & Monitoring | 8 | Module 6 |
| API Security | 10 | Module 7 |
| Infrastructure | 6 | Module 8 |

---

## Module 1: Input & Data Validation

### Overview

Validates that user input is properly sanitized and validated to prevent injection attacks and ensure data integrity.

### Security Controls (10)

| ID | Control | What It Tests |
|----|---------|---------------|
| 001 | SQL Injection | Tests if SQL queries can be manipulated via user input |
| 002 | XSS (Cross-Site Scripting) | Tests if malicious JavaScript can be injected |
| 003 | Command Injection | Tests if OS commands can be executed via input |
| 004 | Path Traversal | Tests if files outside allowed directories can be accessed |
| 005 | LDAP Injection | Tests LDAP query manipulation vulnerabilities |
| 006 | XML Injection | Tests XML External Entity (XXE) vulnerabilities |
| 007 | File Upload Validation | Tests if dangerous file types can be uploaded |
| 008 | Input Length Validation | Tests buffer overflow and DoS via long inputs |
| 009 | Data Type Validation | Tests if incorrect data types are rejected |
| 010 | Output Encoding | Tests if output is properly encoded to prevent XSS |

### How It Works

1. **Discovery** - Crawls target to find input points (forms, parameters, file uploads)
2. **Testing** - Sends malicious payloads to each input point
3. **Analysis** - Checks if payloads were blocked, sanitized, or executed
4. **Reporting** - Generates pass/fail status for each control

### Tools Used

- **OWASP ZAP** (optional) - Automated vulnerability scanner
- **Nikto** (optional) - Web server scanner
- **Custom fuzzing** - Targeted payload injection

### Usage

```bash
# Basic scan
python run_module.py --module=1 --target https://example.com --debug

# With ZAP scanner
python run_module.py --module=1 --target https://example.com --enable-zap

# Multiple targets
python run_module.py --module=1 --target-file targets.txt --depth 3
```

### Example Output

```json
{
  "SQL_Injection": "pass",
  "XSS": "fail",
  "Command_Injection": "pass",
  "File_Upload": "not_tested"
}
```

---

## Module 2: Authentication

### Overview

Tests authentication mechanisms including password policies, login security, and multi-factor authentication.

### Security Controls (7)

| ID | Control | What It Tests |
|----|---------|---------------|
| 011 | Password Policy | Validates password complexity requirements |
| 012 | Login Error Messages | Ensures errors don't reveal user existence |
| 013 | Last Login Message | Checks if last login timestamp is displayed |
| 014 | Password Encryption in Transit | Validates HTTPS usage for login forms |
| 015 | Password Change Process | Tests password change security requirements |
| 016 | Multi-Factor Authentication | Detects MFA implementation |
| 017 | API Authentication | Tests API token/key validation |

### How It Works

1. **Discovery** - Identifies login pages, password forms, API endpoints
2. **Testing** - Tests weak passwords, analyzes error messages, checks HTTPS
3. **Analysis** - Evaluates password strength requirements and MFA presence
4. **Reporting** - Reports authentication security status

### Usage

```bash
# Basic authentication test
python run_module.py --module=2 --target https://example.com/login --debug

# With credentials (configure in config/config.yaml)
python run_module.py --module=2 --target https://example.com --debug
```

---

## Module 3: Authorization

### Overview

Validates access control mechanisms to ensure users can only access resources they're authorized for.

### Security Controls (5)

| ID | Control | What It Tests |
|----|---------|---------------|
| 018 | RBAC (Role-Based Access Control) | Tests if roles are properly enforced |
| 019 | User State Management | Validates session-based access control |
| 020 | Privilege Escalation | Tests if users can gain unauthorized privileges |
| 021 | API Authorization | Tests API endpoint access control |
| 022 | Path Traversal Authorization | Tests directory access restrictions |

### How It Works

1. **Discovery** - Identifies protected pages, admin areas, API endpoints
2. **Testing** - Attempts to access restricted resources without proper permissions
3. **Analysis** - Checks if unauthorized access attempts were blocked
4. **Reporting** - Reports access control effectiveness

### Usage

```bash
python run_module.py --module=3 --target https://example.com --debug
```

---

## Module 4: Sensitive Data Protection

### Overview

Validates encryption, data masking, and PCI DSS compliance for sensitive information handling.

### Security Controls (12)

| ID | Control | What It Tests |
|----|---------|---------------|
| 023 | HTTPS/TLS | Validates secure HTTPS connections |
| 024 | Sensitive Data Masking | Checks for unmasked sensitive data in UI |
| 025 | Password Encryption at Rest | Validates password hashing (bcrypt, etc.) |
| 026 | Data-at-Rest Encryption | Checks database encryption policies |
| 027 | Data-in-Transit Encryption | Validates HTTPS for all sensitive data |
| 028 | PCI PAN Masking | Checks credit card number masking |
| 029 | PCI SAD Not Stored | Ensures CVV/PIN are not stored |
| 030 | PCI Log Masking | Validates sensitive data is masked in logs |
| 031 | Local DB Security | Checks local database encryption |
| 032 | Clear-Text Detection | Scans for clear-text passwords/secrets |
| 033 | Local Device Storage | Validates secure storage (keychain/keystore) |
| 034 | UI Tampering Protection | Checks for code obfuscation |

### How It Works

1. **Discovery** - Crawls pages, loads documents, runs TLS scan
2. **Testing** - Scans for unmasked data, checks encryption policies
3. **Analysis** - Validates encryption standards, masking patterns
4. **Reporting** - Reports data protection compliance

### Tools Used

- **testssl.sh** (optional) - TLS/SSL security scanner
- **Document analysis** - Policy validation

### Usage

```bash
# Basic HTTPS check
python run_module.py --module=4 --target https://example.com --debug

# With TLS scanning
python run_module.py --module=4 --target https://example.com --enable-testssl

# With document analysis
python run_module.py --module=4 \
  --target https://example.com \
  --document-path evidence/policies/
```

---

## Module 5: Session Management

### Overview

Tests session handling mechanisms including timeout, cookie security, and session fixation prevention.

### Security Controls (7)

| ID | Control | What It Tests |
|----|---------|---------------|
| 035 | Session Timeout | Validates session expiration after inactivity |
| 036 | Session ID Randomness | Tests session ID strength and unpredictability |
| 037 | Session Not in URL | Ensures session IDs aren't exposed in URLs |
| 038 | Cookie Flags | Validates Secure, HttpOnly, SameSite flags |
| 039 | Server-Side Validation | Tests server-side session validation |
| 040 | Token Expiry | Checks JWT/bearer token expiration |
| 041 | Session Fixation Prevention | Tests session ID regeneration after login |

### How It Works

1. **Discovery** - Crawls pages, identifies login functionality
2. **Testing** - Analyzes cookies, tests session behavior
3. **Analysis** - Validates cookie security flags, session management
4. **Reporting** - Reports session security status

### Usage

```bash
python run_module.py --module=5 --target https://example.com --debug
```

---

## Module 6: Logging & Monitoring

### Overview

Validates logging practices, audit trail completeness, log integrity, and retention policies.

### Security Controls (8)

| ID | Control | What It Tests |
|----|---------|---------------|
| 042 | Authentication Logging | Checks if login/logout events are logged |
| 043 | Authorization Logging | Validates access decision logging |
| 044 | Access Logging | Tests HTTP access logging |
| 045 | Error Logging | Validates error and exception logging |
| 046 | Security Event Logging | Checks security event logging |
| 047 | Audit Trail Completeness | Validates complete audit trails (timestamp, user, action, result) |
| 048 | Log Integrity | Tests tamper protection mechanisms |
| 049 | Log Retention | Validates retention policies |

### How It Works

1. **Loading** - Loads log files and policy documents
2. **Analysis** - Scans logs for required events, checks policies
3. **Validation** - Validates completeness, integrity, retention
4. **Reporting** - Reports logging compliance

### Usage

```bash
# Analyze log files
python run_module.py --module=6 --log-path /var/log/app/ --debug

# With policy documents
python run_module.py --module=6 \
  --log-path /var/log/app/ \
  --document-path evidence/policies/
```

---

## Module 7: API Security

### Overview

Tests API-specific security controls including authentication, rate limiting, input validation, and CORS configuration.

### Security Controls (10)

| ID | Control | What It Tests |
|----|---------|---------------|
| 050 | API Method Security | Tests HTTP method restrictions (TRACE, DELETE, etc.) |
| 051 | API Rate Limiting | Validates rate limiting implementation |
| 052 | API Input Validation | Tests API input sanitization |
| 053 | API Authentication Validation | Validates API authentication requirements |
| 054 | API Sensitive Params | Checks for sensitive data in URL parameters |
| 055 | API Error Handling | Tests error message verbosity |
| 056 | CORS Configuration | Validates CORS security settings |
| 057 | API Versioning | Checks for API versioning implementation |
| 058 | Secure Coding Evidence | Validates secure coding practices documentation |
| 059 | Third-Party Components | Checks dependency security management |

### How It Works

1. **Discovery** - Finds API endpoints from URLs and JavaScript
2. **Testing** - Tests methods, rate limits, authentication, CORS
3. **Analysis** - Validates API security configurations
4. **Reporting** - Reports API security status

### Usage

```bash
# Basic API testing
python run_module.py --module=7 --target https://api.example.com --debug

# With documentation
python run_module.py --module=7 \
  --target https://api.example.com \
  --document-path evidence/api_docs/
```

---

## Module 8: Infrastructure & Containers

### Overview

Validates infrastructure security, container security, and patch management practices.

### Security Controls (6)

| ID | Control | What It Tests |
|----|---------|---------------|
| 060 | Host Hardening | Checks OS hardening evidence (CIS benchmarks, Lynis) |
| 061 | Container Security | Validates container image scanning (Trivy, Clair) |
| 062 | Container Runtime Security | Tests runtime security configuration (seccomp, AppArmor) |
| 063 | Least Privilege | Validates minimal permissions (RBAC, non-root) |
| 064 | DoS Protection | Checks infrastructure-level DoS protection (WAF, rate limiting) |
| 065 | Security Updates | Validates patch management policies |

### How It Works

1. **Loading** - Loads security policies, IaC files, documentation
2. **Analysis** - Scans for security practices and configurations
3. **Validation** - Validates hardening, scanning, patching evidence
4. **Reporting** - Reports infrastructure security status

### Tools Referenced

- **Lynis** - System hardening scanner
- **Trivy** - Container vulnerability scanner
- **OpenSCAP** - Security compliance scanner

### Usage

```bash
# Analyze infrastructure documentation
python run_module.py --module=8 --document-path evidence/infrastructure/ --debug
```

---

## Usage Guide

### Quick Start

```bash
# 1. Navigate to project
cd /home/n3wb0rn/GAP-ANALYSIS

# 2. Activate environment
source gavenv/bin/activate

# 3. Run a module
python run_module.py --module=1 --target https://example.com --debug

# 4. Run all modules
./run_all.sh

# 5. Check results
ls -la outputs/
cat outputs/module1.json | python -m json.tool
```

### Command-Line Arguments

| Argument | Description | Modules |
|----------|-------------|---------|
| `--module` | Module number (1-8) | All |
| `--target` | Target URL | 1-5, 7 |
| `--target-file` | File with multiple targets | 1-5, 7 |
| `--log-path` | Path to log files | 6 |
| `--document-path` | Path to policy documents | 4, 6, 7, 8 |
| `--depth` | Crawl depth (default: 2) | 1, 4, 5, 7 |
| `--max-pages` | Max pages to crawl (default: 40) | 1, 4, 5, 7 |
| `--enable-zap` | Enable OWASP ZAP | 1 |
| `--enable-nikto` | Enable Nikto | 1 |
| `--enable-testssl` | Enable testssl.sh | 4 |
| `--debug` | Verbose logging | All |

### Output Format

Each module generates a JSON file:

```json
{
  "module": "Module Name",
  "module_number": 1,
  "timestamp": "2025-11-25T10:00:00Z",
  "controls": {
    "Control_Name": "pass",
    "Another_Control": "fail",
    "Third_Control": "not_tested"
  },
  "evidence": {
    "findings": [...]
  },
  "summary": {
    "total": 10,
    "passed": 7,
    "failed": 2,
    "not_tested": 1
  }
}
```

**Status Values:**
- `pass` - Control is properly implemented
- `fail` - Security issue detected
- `not_tested` - Insufficient data to test

### Common Workflows

#### Pre-Production Security Check

```bash
# Run all modules before deployment
./run_all.sh

# Review failures
grep -r "fail" outputs/
```

#### Compliance Audit

```bash
# PCI DSS compliance
python run_module.py --module=4 --target https://app.com --enable-testssl

# Audit logging compliance
python run_module.py --module=6 --log-path /var/log/app/
```

#### API Security Assessment

```bash
python run_module.py --module=7 --target https://api.example.com --debug
```

#### Infrastructure Security Review

```bash
python run_module.py --module=8 --document-path evidence/infrastructure/
```

### Module Dependencies

| Module | Required | Optional |
|--------|----------|----------|
| 1 | Target URL | ZAP, Nikto |
| 2 | Target URL | Credentials |
| 3 | Target URL | Credentials |
| 4 | Target URL | Documents, testssl.sh |
| 5 | Target URL | Credentials |
| 6 | Log files OR Target | Documents |
| 7 | Target URL | Documents |
| 8 | Documents | - |

### Troubleshooting

**Issue: "not_tested" results**
- Provide missing data (logs, documents, credentials)
- Enable optional tools (ZAP, testssl.sh)

**Issue: Module fails to run**
- Check if running from project root
- Verify virtual environment is activated
- Use `--debug` flag for detailed error messages

**Issue: No findings**
- Increase crawl depth: `--depth 3`
- Increase page limit: `--max-pages 60`
- Check target is accessible

---

## Summary

### System Capabilities

- **65 Security Controls** across 8 modules
- **Automated Testing** with integrated tools
- **Flexible Execution** - individual or full scan
- **Structured Output** - JSON format
- **Evidence Collection** - detailed findings

### Module Selection Guide

| Use Case | Modules |
|----------|---------|
| Web application security | 1, 2, 3, 5 |
| Data protection compliance | 4, 6 |
| API security | 7 |
| Infrastructure hardening | 8 |
| Full security assessment | All (run_all.sh) |

---

**For detailed module-specific documentation, see each module's README.md file.**
