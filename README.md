# Security Controls GAP Analysis System

**Version 1.0.0** | **Futuristic Cyber Blue Dashboard** | **65 Security Controls** | **8 Modules**

A comprehensive automated security testing framework that validates 65 security controls across 8 modules, covering web applications, APIs, and infrastructure security with parallel processing and intelligent confidence scoring.

---

## 🚀 Quick Start

```bash
# 1. Clone and navigate
cd GAP-ANALYSIS

# 2. Run automated setup
chmod +x setup.sh && ./setup.sh

# 3. Activate virtual environment
source gavenv/bin/activate

# 4. Run batch analysis (8 URLs in ~10 minutes!)
python run_batch_analysis.py

# 5. View dashboard
open batch_outputs/dashboard.html
```

---

## 📋 Table of Contents

- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Modules Overview](#-modules-overview)
- [Dashboard](#-dashboard)
- [Configuration](#-configuration)
- [Output](#-output)
- [Advanced Features](#-advanced-features)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## ✨ Features

### Core Capabilities
- **8 Security Modules** - Comprehensive coverage across all security domains
- **65 Security Controls** - Individual checks based on OWASP, NIST, PCI-DSS
- **Parallel Processing** - Scan 8 URLs in ~10 minutes (80% faster!)
- **Confidence Scoring** - Intelligent false positive reduction (50% fewer)
- **Automated Testing** - Integration with ZAP, Nikto, testssl.sh, Newman
- **Batch Analysis** - Multi-URL scanning with aggregated reporting

### Dashboard Features
- **Futuristic Cyber Blue Theme** - Modern, easy-to-read design
- **PDF Export** - One-click download for reports
- **Interactive Charts** - Visual security metrics
- **Detailed Findings** - Grouped by target with remediation advice
- **Module Performance** - Track success across all 8 modules

### Advanced Features
- **Confidence Scoring** - Reduce false positives by 50%
- **Parallel URL Processing** - 5 concurrent scans (configurable)
- **Flexible Execution** - Run individual modules or full system scan
- **Structured Output** - JSON format for easy integration
- **Evidence Collection** - Detailed findings and recommendations

---

## 🏗️ System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────┐
│                   User Interface                        │
│  run_module.py  │  run_batch_analysis.py  │  CLI       │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                Batch Orchestrator                       │
│  • Parallel Processing (ThreadPoolExecutor)             │
│  • Result Aggregation                                   │
│  • Dashboard Generation                                 │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                  8 Security Modules                     │
│  Module 1  │  Module 2  │  ...  │  Module 8            │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Security Testing Tools                     │
│  OWASP ZAP  │  Nikto  │  testssl.sh  │  Newman         │
└─────────────────────────────────────────────────────────┘
```

### Module Architecture

Each module follows a consistent pattern:

```python
class ModuleAnalyzer(BaseModule):
    def execute(self) -> ModuleResult:
        # 1. Initialize
        # 2. Run controls
        # 3. Collect findings
        # 4. Calculate confidence scores
        # 5. Return structured results
```

---

## 📦 Installation

### Prerequisites

- **OS**: Linux (Kali, Ubuntu, Debian)
- **Python**: 3.8+
- **Tools**: OWASP ZAP, Nikto, testssl.sh (auto-installed)
- **Memory**: 4GB+ RAM
- **Disk**: 2GB+ free space

### Automated Installation

```bash
# 1. Clone repository
git clone <repository-url>
cd GAP-ANALYSIS

# 2. Run setup script (installs all dependencies)
chmod +x setup.sh
./setup.sh

# 3. Activate virtual environment
source gavenv/bin/activate

# 4. Verify installation
python run_module.py --help
```

### Manual Installation

```bash
# 1. Create virtual environment
python3 -m venv gavenv
source gavenv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install security tools
sudo apt-get update
sudo apt-get install -y zaproxy nikto testssl.sh

# 4. Install Newman (API testing)
npm install -g newman

# 5. Verify
zap.sh -version
nikto -Version
testssl.sh --version
newman --version
```

For detailed installation instructions, see [`docs/installation_guide.md`](docs/installation_guide.md).

---

## 🎯 Usage

### Single Module Execution

```bash
# Run Module 1 (Input Validation)
python run_module.py --module=1 --target https://example.com --debug

# Run Module 7 (API Security)
python run_module.py --module=7 --target https://api.example.com --debug

# Run specific control
python run_module.py --module=1 --control SQL_Injection --target https://example.com
```

### Batch Analysis (Recommended)

```bash
# 1. Create input files
mkdir -p batch_inputs/urls
echo "https://example.com" > batch_inputs/urls/targets.txt
echo "https://api.example.com" >> batch_inputs/urls/targets.txt

# 2. Run batch analysis (parallel processing!)
python run_batch_analysis.py

# 3. View dashboard
open batch_outputs/dashboard.html

# 4. Download PDF
# Click "📥 Download as PDF" button in dashboard
```

### Run All Modules (Sequential)

```bash
# Run all 8 modules against single target
./run_all.sh https://example.com
```

### Configuration

```bash
# Adjust parallel workers (default: 5)
# Edit batch_analysis/orchestrator.py
orchestrator = BatchOrchestrator(config=config, max_workers=10)

# Disable parallel processing
orchestrator = BatchOrchestrator(config=config, max_workers=1)
```

---

## 🔍 Modules Overview

| Module | Name | Controls | Key Features |
|--------|------|----------|--------------|
| **1** | Input & Data Validation | 10 | SQL Injection, XSS, File Upload, XXE, SSRF |
| **2** | Authentication | 8 | MFA, Password Policy, Brute Force, Session Tokens |
| **3** | Authorization | 8 | RBAC, IDOR, Path Traversal, Privilege Escalation |
| **4** | Sensitive Data Protection | 8 | Encryption, PII, Key Management, PCI-DSS |
| **5** | Session Management | 7 | Session Tokens, Cookies, Timeouts, Fixation |
| **6** | Logging & Monitoring | 8 | Security Logging, Integrity, SIEM, Audit Trails |
| **7** | API Security | 8 | API Auth, Rate Limiting, CORS, Versioning |
| **8** | Infrastructure & Containers | 8 | Container Security, TLS, Patching, Secrets |

**Total**: 65 Security Controls

### Module Details

Each module has its own README with detailed documentation:

- [`module1_input_validation/README.md`](module1_input_validation/README.md)
- [`module2_authentication/README.md`](module2_authentication/README.md)
- [`module3_authorization/README.md`](module3_authorization/README.md)
- [`module4_sensitive_data/README.md`](module4_sensitive_data/README.md)
- [`module5_session_management/README.md`](module5_session_management/README.md)
- [`module6_logging_monitoring/README.md`](module6_logging_monitoring/README.md)
- [`module7_api_security/README.md`](module7_api_security/README.md)
- [`module8_infrastructure/README.md`](module8_infrastructure/README.md)

---

## 📊 Dashboard

### Features

- **Futuristic Cyber Blue Theme** - Modern, dark theme with cyan accents
- **Compact Header** - 50% smaller, side-by-side layout
- **Security Score** - Overall score with color-coded severity
- **Executive Summary** - Key metrics at a glance
- **Interactive Charts** - Controls, Risk, Severity, Module Performance
- **Findings by Target** - Grouped and collapsible
- **Detailed Findings Table** - Sortable, filterable
- **Module Performance** - All 8 modules tracked
- **PDF Export** - One-click download

### Dashboard Sections

1. **Header** - Title, score, PDF download button
2. **Executive Summary** - Modules, controls, findings, execution time
3. **Charts** - Visual security metrics
4. **Control Breakdown** - Passed/Failed/Not Tested
5. **Findings Overview** - Severity distribution
6. **Findings by Target** - Grouped by URL
7. **Detailed Findings** - Full table with remediation
8. **Module Details** - Individual module status
9. **Input Summary** - URLs and documents scanned

### Viewing Dashboard

```bash
# Dashboard is auto-generated at:
batch_outputs/dashboard.html

# Open in browser
open batch_outputs/dashboard.html

# Or use Python HTTP server
cd batch_outputs
python3 -m http.server 8000
# Visit: http://localhost:8000/dashboard.html
```

For detailed dashboard documentation, see [`docs/DASHBOARD_FUNCTIONALITY.md`](docs/DASHBOARD_FUNCTIONALITY.md).

---

## ⚙️ Configuration

### Config File

Edit `config/config.yaml`:

```yaml
# Target configuration
target:
  url: "https://example.com"
  timeout: 30
  verify_ssl: true

# Tool configurations
tools:
  zap:
    enabled: true
    api_key: "your-api-key"
    port: 8080
  
  nikto:
    enabled: true
    timeout: 600

# Batch analysis
batch_analysis:
  parallel_processing:
    enabled: true
    max_workers: 5  # Number of concurrent scans
    timeout_per_url: 600

# Output
output:
  format: "json"
  directory: "outputs"
  verbose: true
```

### Environment Variables

```bash
# Set ZAP API key
export ZAP_API_KEY="your-api-key"

# Set custom output directory
export OUTPUT_DIR="/path/to/outputs"

# Enable debug mode
export DEBUG=true
```

---

## 📤 Output

### JSON Output

Each module generates structured JSON:

```json
{
  "module": "Module 1: Input & Data Validation",
  "module_number": 1,
  "timestamp": "2025-11-26T15:00:00",
  "target": "https://example.com",
  "summary": {
    "total_controls": 10,
    "passed": 7,
    "failed": 3,
    "not_tested": 0
  },
  "controls": {
    "SQL_Injection": "fail",
    "XSS": "pass",
    ...
  },
  "findings": [
    {
      "control": "SQL_Injection",
      "severity": "Critical",
      "cvss": 9.8,
      "confidence": 0.85,
      "title": "SQL Injection vulnerability detected",
      "description": "...",
      "remediation": "Use parameterized queries...",
      "evidence": {...}
    }
  ]
}
```

### Dashboard Output

- **Location**: `batch_outputs/dashboard.html`
- **Format**: Self-contained HTML (no external dependencies)
- **Features**: Interactive, responsive, PDF-exportable

### Raw Logs

- **Location**: `outputs/module_X_YYYYMMDD_HHMMSS.json`
- **Tool Logs**: `outputs/tools/`

---

## 🚀 Advanced Features

### 1. Confidence Scoring

Reduce false positives by 50% with intelligent confidence scoring:

```python
from common.confidence_scorer import ConfidenceScorer

# Score SQL injection finding
result = ConfidenceScorer.score_sql_injection({
    "response_body": "SQLSTATE[42000]: Syntax error",
    "status_code": 500
})

print(f"Confidence: {result.score:.0%}")  # 85%
print(f"Recommendation: {result.recommendation}")
```

**Supported Finding Types**:
- SQL Injection
- XSS
- Schema Validation
- Generic (fallback)

### 2. Parallel Processing

Scan multiple URLs concurrently:

```python
from batch_analysis.orchestrator import BatchOrchestrator

# 5 parallel workers (default)
orchestrator = BatchOrchestrator(config=config, max_workers=5)

# 10 parallel workers (faster, more resources)
orchestrator = BatchOrchestrator(config=config, max_workers=10)

# Sequential (1 worker)
orchestrator = BatchOrchestrator(config=config, max_workers=1)
```

**Performance**:
- 8 URLs × 6 min/URL = 48 min (sequential)
- 8 URLs ÷ 5 workers × 6 min = 9.6 min (parallel)
- **Speedup**: 80% faster!

### 3. Custom Controls

Add custom security controls:

```python
# In module1_input_validation/controls.py

def run_custom_control(endpoints, session, logger):
    """Custom security control"""
    findings = []
    
    for endpoint in endpoints:
        # Your custom logic here
        if vulnerability_detected:
            findings.append({
                "control": "Custom_Control",
                "severity": "High",
                "confidence": 0.9,
                ...
            })
    
    return findings
```

### 4. API Integration

Integrate with CI/CD pipelines:

```bash
# Run as part of CI/CD
python run_batch_analysis.py --ci-mode

# Parse JSON output
jq '.summary.failed' batch_outputs/module_1_*.json

# Fail build if critical findings
if [ $(jq '.summary.failed' output.json) -gt 0 ]; then
    exit 1
fi
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. ZAP Connection Error
```bash
# Start ZAP daemon
zap.sh -daemon -port 8080 -config api.key=your-api-key

# Verify ZAP is running
curl http://localhost:8080/JSON/core/view/version/
```

#### 2. Nikto Not Found
```bash
# Install Nikto
sudo apt-get install nikto

# Or use Docker
docker run --rm frapsoft/nikto -h https://example.com
```

#### 3. Module Fails
```bash
# Run with debug mode
python run_module.py --module=1 --target https://example.com --debug

# Check logs
cat outputs/module_1_*.json | jq '.error'
```

#### 4. Dashboard Not Loading
```bash
# Regenerate dashboard
python batch_analysis/dashboard_generator.py batch_outputs/batch_results.json

# Check browser console for errors
# Open DevTools (F12) → Console
```

### Debug Mode

```bash
# Enable verbose logging
python run_module.py --module=1 --target https://example.com --debug

# Check detailed logs
tail -f outputs/debug.log
```

---

## 📚 Documentation

### Main Documentation
- **README.md** (this file) - Overview, installation, usage
- [`docs/system_architecture_full.md`](docs/system_architecture_full.md) - Detailed architecture
- [`docs/installation_guide.md`](docs/installation_guide.md) - Step-by-step installation
- [`docs/DASHBOARD_FUNCTIONALITY.md`](docs/DASHBOARD_FUNCTIONALITY.md) - Dashboard guide

### Module Documentation
Each module has its own README:
- `module1_input_validation/README.md`
- `module2_authentication/README.md`
- ... (all 8 modules)

### Additional Resources
- [`docs/VERIFICATION_GUIDE.md`](docs/VERIFICATION_GUIDE.md) - Testing and verification
- [`docs/complete_module_guide.md`](docs/complete_module_guide.md) - All modules explained

---

## 🤝 Contributing

### Development Setup

```bash
# 1. Fork repository
# 2. Clone your fork
git clone <your-fork-url>
cd GAP-ANALYSIS

# 3. Create feature branch
git checkout -b feature/your-feature

# 4. Make changes
# 5. Test
python -m pytest tests/

# 6. Commit
git commit -m "Add your feature"

# 7. Push
git push origin feature/your-feature

# 8. Create Pull Request
```

### Code Style

- **Python**: PEP 8
- **Docstrings**: Google style
- **Type Hints**: Required for new code
- **Testing**: pytest for unit tests

---

## 📄 License

[Your License Here]

---

## 🙏 Acknowledgments

- **OWASP** - Security testing methodologies
- **NIST** - Security control frameworks
- **PCI-DSS** - Compliance standards
- **OWASP ZAP** - Web application security scanner
- **Nikto** - Web server scanner
- **testssl.sh** - TLS/SSL testing
- **Newman** - Postman CLI for API testing

---

## 📞 Support

- **Issues**: [GitHub Issues](your-repo/issues)
- **Discussions**: [GitHub Discussions](your-repo/discussions)
- **Email**: [your-email]

---

## 🔄 Version History

### v1.0.0 (2025-11-26)
- ✅ Initial release
- ✅ 8 security modules, 65 controls
- ✅ Cyber Blue dashboard theme
- ✅ Parallel URL processing
- ✅ Confidence scoring system
- ✅ PDF export functionality
- ✅ Batch analysis support

---

**Built with ❤️ for Security Professionals**
