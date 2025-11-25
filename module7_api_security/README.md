# Module 7: API Security Analyzer

## Overview

Module 7 automates the assessment of **10 security controls** related to API security, including authentication, rate limiting, input validation, CORS configuration, and secure coding practices.

## Controls Covered

| Control ID | Control Name | Description | Severity |
|------------|--------------|-------------|----------|
| 050 | API_Method_Security | API HTTP method restrictions | High |
| 051 | API_Rate_Limiting | API rate limiting implementation | Medium |
| 052 | API_Input_Validation | API input validation | High |
| 053 | API_Authentication_Validation | API authentication validation | Critical |
| 054 | API_Sensitive_Params | Sensitive data in API parameters | High |
| 055 | API_Error_Handling | API error handling and responses | Medium |
| 056 | API_CORS_Configuration | CORS configuration security | Medium |
| 057 | API_Versioning | API versioning implementation | Low |
| 058 | Secure_Coding_Evidence | Secure coding practices evidence | Medium |
| 059 | Third_Party_Components | Third-party component security | High |

## Usage

### Basic Usage

```bash
# Run against single target
python run_module.py --module=7 --target https://api.example.com --debug

# Run with documents
python run_module.py --module=7 \
  --target https://api.example.com \
  --document-path evidence/ \
  --debug
```

## Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | Single target URL | From config |
| `--target-file` | File with URLs (one per line) | None |
| `--document-path` | Path to policy documents | None |
| `--depth` | Discovery crawl depth | 2 |
| `--max-pages` | Maximum pages to crawl | 40 |
| `--debug` | Enable verbose logging | False |

## Control Evaluation Logic

### API Method Security (050)
- Tests dangerous HTTP methods (TRACE, TRACK, DELETE, PUT)
- **Pass**: Dangerous methods properly restricted
- **Fail**: Dangerous methods allowed

### API Rate Limiting (051)
- Makes rapid requests to detect rate limiting
- Checks for rate limit headers and 429 responses
- **Pass**: Rate limiting detected
- **Fail**: No rate limiting

### API Input Validation (052)
- Tests with SQL injection, XSS, path traversal payloads
- **Pass**: Input properly validated/encoded
- **Fail**: Payloads reflected without encoding

### API Authentication Validation (053)
- Tests protected endpoints without authentication
- **Pass**: Protected endpoints require auth
- **Fail**: Protected endpoints accessible without auth

### API Sensitive Params (054)
- Scans for passwords, API keys, tokens in URLs
- **Pass**: No sensitive data in URLs
- **Fail**: Sensitive data exposed in URLs

### API Error Handling (055)
- Tests error responses for verbose information
- **Pass**: Generic error messages
- **Fail**: Stack traces or sensitive info in errors

### CORS Configuration (056)
- Tests for wildcard CORS and reflected origins
- **Pass**: Proper CORS configuration
- **Fail**: Insecure CORS (wildcard or reflected)

### API Versioning (057)
- Checks for version indicators (/v1/, /v2/)
- **Pass**: Versioning detected
- **Fail**: No versioning

### Secure Coding Evidence (058)
- Checks documents for secure coding practices
- **Pass**: Evidence found
- **Fail**: No evidence

### Third-Party Components (059)
- Checks for dependency scanning evidence
- **Pass**: Third-party security management found
- **Fail**: No evidence

## Examples

### Example 1: Basic API Test

```bash
python run_module.py --module=7 --target https://api.example.com --debug
```

### Example 2: With Documentation

```bash
python run_module.py --module=7 \
  --target https://api.example.com \
  --document-path evidence/api_docs/ \
  --debug
```

## Integration

### With run_all.sh

```bash
./run_all.sh
```

## License

Part of the Security Controls GAP Analysis System - Phase 1
