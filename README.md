# Security Controls GAP Analysis System

A comprehensive automated security testing framework that validates 65 security controls across 8 modules, covering web applications, APIs, and infrastructure security.

## Overview

The Security Controls GAP Analysis System is designed to identify security gaps in modern applications by testing critical security controls across multiple domains including input validation, authentication, authorization, data protection, session management, logging, API security, and infrastructure hardening.

### Key Features

- **8 Security Modules** - Comprehensive coverage of security domains
- **65 Security Controls** - Individual security checks based on industry standards
- **Automated Testing** - Integration with OWASP ZAP, Nikto, testssl.sh, and more
- **Flexible Execution** - Run individual modules or complete system scan
- **Structured Output** - JSON format for easy integration
- **Evidence Collection** - Detailed findings and recommendations

## Quick Start

```bash
# 1. Navigate to project directory
cd GAP-ANALYSIS

# 2. Run automated setup
chmod +x setup.sh && ./setup.sh

# 3. Create and activate virtual environment
python3 -m venv gavenv
source gavenv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run a module
python run_module.py --module=1 --target https://example.com --debug

# 6. Run all modules
./run_all.sh
```

## System Architecture

### Modules Overview

| Module | Name | Controls | Description |
|--------|------|----------|-------------|
| **1** | Input & Data Validation | 10 | Tests input sanitization and injection prevention |
| **2** | Authentication | 7 | Validates authentication mechanisms and password policies |
| **3** | Authorization | 5 | Tests access control and privilege management |
| **4** | Sensitive Data Protection | 12 | Validates encryption and PCI DSS compliance |
| **5** | Session Management | 7 | Tests session handling and cookie security |
| **6** | Logging & Monitoring | 8 | Validates logging practices and audit trails |
| **7** | API Security | 10 | Tests API-specific security controls |
| **8** | Infrastructure & Containers | 6 | Validates infrastructure hardening and container security |

**Total: 65 Security Controls**

## Documentation

### Primary Documentation

- **[Installation Guide](docs/installation_guide.md)** - Complete setup instructions for Kali Linux and other systems
- **[Module Guide](docs/complete_module_guide.md)** - Detailed documentation for all 8 modules
- **[System Architecture](docs/system_architecture_full.md)** - Complete system design and architecture

### Module-Specific Documentation

Each module has its own README with detailed usage instructions:

- [Module 1: Input & Data Validation](module1_input_validation/README.md)
- [Module 2: Authentication](module2_authentication/README.md)
- [Module 3: Authorization](module3_authorization/README.md)
- [Module 4: Sensitive Data Protection](module4_sensitive_data/README.md)
- [Module 5: Session Management](module5_session_management/README.md)
- [Module 6: Logging & Monitoring](module6_logging_monitoring/README.md)
- [Module 7: API Security](module7_api_security/README.md)
- [Module 8: Infrastructure & Containers](module8_infrastructure/README.md)

## Usage

### Running Individual Modules

```bash
# Module 1: Input Validation
python run_module.py --module=1 --target https://example.com --debug

# Module 2: Authentication
python run_module.py --module=2 --target https://example.com --debug

# Module 4: Sensitive Data (with TLS scanning)
python run_module.py --module=4 --target https://example.com --enable-testssl

# Module 6: Logging (with log files)
python run_module.py --module=6 --log-path /var/log/app/ --debug

# Module 7: API Security
python run_module.py --module=7 --target https://api.example.com --debug

# Module 8: Infrastructure (with documentation)
python run_module.py --module=8 --document-path evidence/infrastructure/
```

### Running All Modules

```bash
./run_all.sh
```

### Command-Line Arguments

| Argument | Description | Applicable Modules |
|----------|-------------|-------------------|
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

## Requirements

### System Requirements

- **OS**: Kali Linux (recommended), Ubuntu 20.04+, Debian 11+
- **Python**: 3.8 or higher
- **Disk Space**: 2-5 GB
- **Network**: Internet connection for tool downloads and remote scanning

### Python Dependencies

```
requests
beautifulsoup4
pyyaml
colorama
rich
python-docx
pypdf2
pytest
pydantic
jsonschema
tabulate
tqdm
lxml
python-dotenv
```

### Optional Security Tools

- **OWASP ZAP** - Web application scanner (Module 1)
- **Nikto** - Web server scanner (Module 1)
- **testssl.sh** - TLS/SSL scanner (Module 4)
- **Lynis** - System hardening scanner (Module 8)
- **Trivy** - Container scanner (Module 8)
- **Newman** - Postman CLI for API testing (Module 7)

See [Installation Guide](docs/installation_guide.md) for detailed setup instructions.

## Configuration

### Basic Configuration

Edit `config/config.yaml`:

```yaml
# Target Configuration
target:
  url: "https://example.com"
  timeout: 30
  verify_ssl: false

# Module Configuration
modules:
  enabled: [1, 2, 3, 4, 5, 6, 7, 8]

# Credentials (for testing)
credentials:
  username: "test_user"
  password: "test_password"

# Output Configuration
output:
  directory: "outputs"
  format: "json"
```

### Tool Paths

Edit `config/tool_paths.yaml` to configure external tool locations:

```yaml
tools:
  zap:
    path: "/opt/zaproxy/zap.sh"
    enabled: false
  testssl:
    path: "/opt/testssl.sh/testssl.sh"
    enabled: false
```

## Output

### JSON Output Format

Each module generates a JSON file in the `outputs/` directory:

```json
{
  "module": "Module Name",
  "module_number": 1,
  "timestamp": "2025-11-25T10:00:00Z",
  "controls": {
    "Control_Name": "pass",
    "Another_Control": "fail"
  },
  "summary": {
    "total": 10,
    "passed": 7,
    "failed": 2,
    "not_tested": 1
  }
}
```

**Status Values**:
- `pass` - Control properly implemented
- `fail` - Security issue detected
- `not_tested` - Insufficient data to test

### Viewing Results

```bash
# List all outputs
ls -la outputs/

# View specific module result
cat outputs/module1.json | python -m json.tool

# Search for failures
grep -r "fail" outputs/
```

## Project Structure

```
GAP-ANALYSIS/
├── config/                      # Configuration files
│   ├── config.yaml
│   ├── tool_paths.yaml
│   └── control_mapping.yaml
├── common/                      # Shared utilities
│   ├── __init__.py
│   ├── base_module.py
│   ├── config.py
│   └── logger.py
├── docs/                        # Documentation
│   ├── installation_guide.md
│   ├── complete_module_guide.md
│   └── system_architecture_full.md
├── module1_input_validation/    # Module 1
├── module2_authentication/      # Module 2
├── module3_authorization/       # Module 3
├── module4_sensitive_data/      # Module 4
├── module5_session_management/  # Module 5
├── module6_logging_monitoring/  # Module 6
├── module7_api_security/        # Module 7
├── module8_infrastructure/      # Module 8
├── outputs/                     # Scan results
├── logs/                        # Application logs
├── evidence/                    # Evidence documents
├── run_module.py               # Module runner
├── run_all.sh                  # Full system scan
├── setup.sh                    # Installation script
└── requirements.txt            # Python dependencies
```

## Testing

### Unit Tests

```bash
# Run all tests
python -m pytest

# Run specific module tests
python -m pytest module1_input_validation/tests/ -v
python -m pytest module2_authentication/tests/ -v
```

### Integration Testing

```bash
# Test with example.com
python run_module.py --module=1 --target https://example.com --debug

# Test logging module
mkdir -p test_logs
echo "2025-11-25 10:00:00 [INFO] User logged in" > test_logs/app.log
python run_module.py --module=6 --log-path test_logs/ --debug
```

## Common Use Cases

### Pre-Production Security Check

```bash
# Run all modules before deployment
./run_all.sh

# Review critical failures
grep -r "fail" outputs/
```

### Compliance Audit

```bash
# PCI DSS compliance check
python run_module.py --module=4 --target https://app.com --enable-testssl

# Audit logging compliance
python run_module.py --module=6 --log-path /var/log/app/
```

### API Security Assessment

```bash
python run_module.py --module=7 --target https://api.example.com --debug
```

### Infrastructure Security Review

```bash
# Prepare documentation
mkdir -p evidence/infrastructure
cat > evidence/infrastructure/policy.txt << EOF
CIS benchmarks enforced
Trivy scanning enabled
Security updates automated
EOF

# Run assessment
python run_module.py --module=8 --document-path evidence/infrastructure/
```

## Troubleshooting

### Common Issues

**ModuleNotFoundError: No module named 'common'**
```bash
# Run from project root
cd /path/to/GAP-ANALYSIS
python run_module.py --module=1 --help
```

**Virtual environment not activated**
```bash
source gavenv/bin/activate
```

**Tool not found**
```bash
# Update tool paths in config/tool_paths.yaml
# Or install missing tools (see Installation Guide)
```

**SSL certificate errors**
```yaml
# In config/config.yaml
target:
  verify_ssl: false
```

For more troubleshooting, see [Installation Guide](docs/installation_guide.md).

## Contributing

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd GAP-ANALYSIS

# Create virtual environment
python3 -m venv gavenv
source gavenv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest
```

### Adding New Controls

1. Update `config/control_mapping.yaml`
2. Implement control in appropriate `module*/controls.py`
3. Add tests in `module*/tests/`
4. Update module README

## License

This project is part of the Security Controls GAP Analysis System - Phase 1.

## Support

- **Documentation**: See [docs/](docs/) directory
- **Module Help**: Check individual module READMEs
- **Installation**: See [Installation Guide](docs/installation_guide.md)
- **Module Details**: See [Module Guide](docs/complete_module_guide.md)

## Version

**Current Version**: 1.0.0  
**Modules**: 8/8 Complete  
**Controls**: 65/65 Implemented  
**Status**: Production Ready

---

**Quick Links**:
- [Installation Guide](docs/installation_guide.md)
- [Module Documentation](docs/complete_module_guide.md)
- [System Architecture](docs/system_architecture_full.md)
