# Module 4: Sensitive Data Protection Analyzer

## Overview

Module 4 automates the assessment of **12 security controls** related to sensitive data protection, encryption, and PCI DSS compliance. This module tests data protection at rest and in transit, validates TLS/HTTPS configurations, and checks for clear-text sensitive data exposure.

## Controls Covered

| Control ID | Control Name | Description | Severity |
|------------|--------------|-------------|----------|
| 023 | HTTPS_TLS | HTTPS/TLS implementation and configuration | Critical |
| 024 | Sensitive_Data_Masking | Sensitive data masking in UI/logs | High |
| 025 | Password_Encryption_Rest | Password encryption at rest | Critical |
| 026 | Data_Rest_Encryption | Data-at-rest encryption | High |
| 027 | Data_Transit_Encryption | Data-in-transit encryption | Critical |
| 028 | PCI_PAN_Masking | PCI DSS PAN masking | Critical |
| 029 | PCI_SAD_Not_Stored | PCI DSS SAD not stored | Critical |
| 030 | PCI_Log_Masking | PCI DSS log masking | High |
| 031 | Local_DB_Security | Local database security | High |
| 032 | Clear_Text_Detection | Clear-text password/data detection | Critical |
| 033 | Local_Device_Storage | Local device storage security | Medium |
| 034 | UI_Tampering_Protection | UI tampering protection | Medium |

## Tools Used

- **testssl.sh** - TLS/SSL configuration testing
- **OpenSSL** - Certificate validation
- **Python requests** - HTTP/HTTPS testing
- **BeautifulSoup** - HTML parsing
- **PyPDF2** - PDF document analysis
- **python-docx** - DOCX document analysis

## Installation

### Prerequisites

```bash
# Install Python dependencies
pip install requests beautifulsoup4 PyPDF2 python-docx

# Install testssl.sh (optional but recommended)
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
chmod +x /opt/testssl.sh/testssl.sh
```

### Configuration

Update `config/tool_paths.yaml`:

```yaml
tools:
  testssl:
    path: "/opt/testssl.sh/testssl.sh"
```

## Usage

### Basic Usage

```bash
# Run against single target
python module4_sensitive_data/main.py --target https://example.com

# Run with document analysis
python module4_sensitive_data/main.py \
  --target https://example.com \
  --document-path evidence/security_docs/

# Enable TLS scanning
python module4_sensitive_data/main.py \
  --target https://example.com \
  --enable-testssl

# Run against multiple targets
python module4_sensitive_data/main.py --target-file targets.txt
```

### Advanced Options

```bash
python module4_sensitive_data/main.py \
  --target https://example.com \
  --document-path evidence/ \
  --enable-testssl \
  --depth 3 \
  --max-pages 100 \
  --debug
```

### Via run_module.py

```bash
python run_module.py --module=4 --target https://example.com
```

## Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | Single target URL | From config |
| `--target-file` | File with URLs (one per line) | None |
| `--document-path` | Path to documents/directory for analysis | None |
| `--depth` | Discovery crawl depth | 2 |
| `--max-pages` | Maximum pages to crawl | 50 |
| `--enable-testssl` | Enable testssl.sh TLS scanning | False |
| `--debug` | Enable verbose logging | False |
| `--config-dir` | Configuration directory | config |

## Output Format

The module generates a JSON file at `outputs/module4.json`:

```json
{
  "module": "Sensitive Data Protection Analyzer",
  "module_number": 4,
  "timestamp": "2025-11-25T09:00:00Z",
  "targets": [
    {
      "target": "https://example.com",
      "controls": {
        "HTTPS_TLS": "pass",
        "Sensitive_Data_Masking": "pass",
        "Password_Encryption_Rest": "not_tested",
        "Data_Rest_Encryption": "not_tested",
        "Data_Transit_Encryption": "pass",
        "PCI_PAN_Masking": "pass",
        "PCI_SAD_Not_Stored": "not_tested",
        "PCI_Log_Masking": "not_tested",
        "Local_DB_Security": "not_tested",
        "Clear_Text_Detection": "pass",
        "Local_Device_Storage": "not_tested",
        "UI_Tampering_Protection": "not_tested"
      },
      "evidence": {
        "pages": [...],
        "documents": [...],
        "tls_scan": {...},
        "findings": [...]
      },
      "summary": {
        "total": 12,
        "passed": 5,
        "failed": 0,
        "not_tested": 7
      }
    }
  ],
  "summary": {
    "total_controls": 12,
    "passed": 5,
    "failed": 0,
    "not_tested": 7
  }
}
```

## Control Evaluation Logic

### Automated Controls (HTTPS/TLS Testing)

- **HTTPS_TLS (023)**: Checks if target uses HTTPS, validates TLS version (1.2+), and certificate validity
- **Data_Transit_Encryption (027)**: Validates HTTPS usage and checks for mixed content
- **Clear_Text_Detection (032)**: Scans pages for clear-text passwords, API keys, and connection strings

### Pattern-Based Controls (Data Masking)

- **Sensitive_Data_Masking (024)**: Scans for unmasked credit cards, SSNs, API keys
- **PCI_PAN_Masking (028)**: Detects unmasked PANs (credit card numbers)
- **PCI_Log_Masking (030)**: Scans log files for unmasked sensitive data

### Document-Based Controls (Policies)

- **Password_Encryption_Rest (025)**: Looks for bcrypt, scrypt, PBKDF2, Argon2 in docs
- **Data_Rest_Encryption (026)**: Checks for AES-256, TDE, database encryption
- **PCI_SAD_Not_Stored (029)**: Validates CVV/PIN not stored policy
- **Local_DB_Security (031)**: Checks for SQLite encryption, file permissions
- **Local_Device_Storage (033)**: Validates keychain/keystore usage
- **UI_Tampering_Protection (034)**: Checks for obfuscation, anti-tampering measures

## Document Analysis

The module can analyze various document formats:

- **PDF** (.pdf) - Security policies, architecture docs
- **DOCX** (.docx) - Design documents, procedures
- **TXT/MD** (.txt, .md) - Configuration files, README files

### Document Structure

```
evidence/
├── security_policy.pdf
├── architecture/
│   ├── database_design.docx
│   └── encryption_standards.txt
└── pci_compliance/
    ├── pan_handling.pdf
    └── logging_policy.docx
```

## Execution Time

- **Without testssl.sh**: 2-5 minutes
- **With testssl.sh**: 8-15 minutes
- **With document analysis**: +1-3 minutes per 10 documents

## Troubleshooting

### testssl.sh Not Found

```
Error: testssl.sh not found at /opt/testssl.sh/testssl.sh
```

**Solution**: Install testssl.sh or disable TLS scanning:
```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
```

### Document Parsing Errors

```
Warning: Failed to extract PDF content from file.pdf
```

**Solution**: Ensure PyPDF2 and python-docx are installed:
```bash
pip install PyPDF2 python-docx
```

### No Documents Provided

```
Warning: No documents provided for analysis
```

**Solution**: Use `--document-path` to specify document location:
```bash
python module4_sensitive_data/main.py --target https://example.com --document-path evidence/
```

## Integration

### With run_all.sh

Module 4 is automatically included in the full system scan:

```bash
./run_all.sh
```

### With CI/CD

```yaml
- name: Run Module 4
  run: |
    python run_module.py --module=4 --target ${{ secrets.TARGET_URL }}
```

## Examples

### Example 1: Basic HTTPS Check

```bash
python module4_sensitive_data/main.py --target https://example.com
```

### Example 2: Full TLS Scan with Documents

```bash
python module4_sensitive_data/main.py \
  --target https://example.com \
  --enable-testssl \
  --document-path evidence/security_docs/
```

### Example 3: Multiple Targets

Create `targets.txt`:
```
https://app.example.com
https://api.example.com
https://admin.example.com
```

Run:
```bash
python module4_sensitive_data/main.py --target-file targets.txt --enable-testssl
```

## License

Part of the Security Controls GAP Analysis System - Phase 1
