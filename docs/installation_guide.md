# Installation and Deployment Guide

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Detailed Installation Steps](#detailed-installation-steps)
4. [Tool Installation](#tool-installation)
5. [Configuration](#configuration)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Operating System

- **Primary**: Kali Linux (recommended)
- **Supported**: Ubuntu 20.04+, Debian 11+, macOS
- **Architecture**: x86_64

### Software Requirements

| Component | Version | Required |
|-----------|---------|----------|
| Python | 3.8+ | Yes |
| pip | Latest | Yes |
| Git | 2.0+ | Yes |
| Java | 11+ | Optional (for ZAP) |
| Node.js/npm | 14+ | Optional (for Newman) |

### Disk Space

- Minimum: 2 GB
- Recommended: 5 GB (with all tools)

### Network

- Internet connection required for:
  - Installing dependencies
  - Downloading security tools
  - Running scans against remote targets

---

## Quick Installation

### Automated Setup (Recommended)

```bash
# 1. Clone or navigate to project directory
cd /path/to/GAP-ANALYSIS

# 2. Make setup script executable
chmod +x setup.sh

# 3. Run setup script
./setup.sh

# 4. Create virtual environment
python3 -m venv gavenv
source gavenv/bin/activate

# 5. Install Python dependencies
pip install -r requirements.txt

# 6. Verify installation
python run_module.py --help
```

**Time Required**: 10-15 minutes

---

## Detailed Installation Steps

### Step 1: System Preparation

#### Update System Packages

```bash
# Kali Linux / Debian / Ubuntu
sudo apt update && sudo apt upgrade -y

# macOS
brew update
```

#### Install Base Dependencies

```bash
# Kali Linux / Debian / Ubuntu
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    build-essential \
    libssl-dev \
    libffi-dev

# macOS
brew install python3 git curl wget
```

### Step 2: Project Setup

#### Clone or Extract Project

```bash
# If using Git
git clone <repository-url> GAP-ANALYSIS
cd GAP-ANALYSIS

# If using archive
unzip GAP-ANALYSIS.zip
cd GAP-ANALYSIS
```

#### Create Directory Structure

The `setup.sh` script creates these directories automatically:

```
GAP-ANALYSIS/
├── config/              # Configuration files
├── common/              # Shared utilities
├── module1_input_validation/
├── module2_authentication/
├── module3_authorization/
├── module4_sensitive_data/
├── module5_session_management/
├── module6_logging_monitoring/
├── module7_api_security/
├── module8_infrastructure/
├── outputs/             # Scan results
├── logs/                # Application logs
├── evidence/            # Evidence documents
├── docs/                # Documentation
└── tests/               # Test files
```

### Step 3: Python Environment

#### Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv gavenv

# Activate virtual environment
source gavenv/bin/activate

# Verify activation (should show gavenv path)
which python
```

#### Install Python Dependencies

```bash
# Install from requirements.txt
pip install -r requirements.txt

# Verify installation
pip list
```

**Python Packages Installed**:
- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing
- `pyyaml` - YAML configuration
- `colorama` - Colored terminal output
- `rich` - Rich text formatting
- `python-docx` - DOCX file parsing
- `pypdf2` - PDF file parsing
- `pytest` - Testing framework
- `pydantic` - Data validation
- `jsonschema` - JSON validation
- `tabulate` - Table formatting
- `tqdm` - Progress bars
- `lxml` - XML parsing
- `python-dotenv` - Environment variables

### Step 4: Configuration Files

#### Create config/config.yaml

```bash
cat > config/config.yaml << 'EOF'
# Security GAP Analysis Configuration

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

# Logging Configuration
logging:
  level: "INFO"
  directory: "logs"
EOF
```

#### Create config/tool_paths.yaml

```bash
cat > config/tool_paths.yaml << 'EOF'
# External Tool Paths

tools:
  zap:
    path: "/opt/zaproxy/zap.sh"
    enabled: false
  
  nikto:
    path: "/usr/bin/nikto"
    enabled: false
  
  testssl:
    path: "/opt/testssl.sh/testssl.sh"
    enabled: false
  
  lynis:
    path: "/usr/bin/lynis"
    enabled: false
  
  trivy:
    path: "/usr/bin/trivy"
    enabled: false
  
  newman:
    path: "/usr/bin/newman"
    enabled: false
EOF
```

---

## Tool Installation

### Optional Security Tools

These tools enhance the system's capabilities but are not required for basic operation.

### OWASP ZAP (Web Application Scanner)

**Purpose**: Automated vulnerability scanning for Module 1

```bash
# Install Java (required)
sudo apt install -y openjdk-11-jdk

# Download ZAP
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz

# Extract
tar -xzf ZAP_2.14.0_Linux.tar.gz

# Move to /opt
sudo mv ZAP_2.14.0 /opt/zaproxy

# Verify
/opt/zaproxy/zap.sh -version
```

### Nikto (Web Server Scanner)

**Purpose**: Web server vulnerability scanning for Module 1

```bash
# Kali Linux (pre-installed)
nikto -Version

# Ubuntu/Debian
sudo apt install -y nikto

# Verify
nikto -Version
```

### testssl.sh (TLS/SSL Scanner)

**Purpose**: TLS/SSL security testing for Module 4

```bash
# Clone repository
sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh

# Make executable
sudo chmod +x /opt/testssl.sh/testssl.sh

# Verify
/opt/testssl.sh/testssl.sh --version
```

### Lynis (System Hardening Scanner)

**Purpose**: OS hardening validation for Module 8

```bash
# Kali Linux
sudo apt install -y lynis

# Ubuntu/Debian
sudo apt install -y lynis

# Verify
lynis version
```

### Trivy (Container Scanner)

**Purpose**: Container security scanning for Module 8

```bash
# Add repository
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list

# Install
sudo apt update
sudo apt install -y trivy

# Verify
trivy --version
```

### Newman (Postman CLI)

**Purpose**: API testing for Module 7

```bash
# Install Node.js and npm
sudo apt install -y nodejs npm

# Install Newman globally
sudo npm install -g newman

# Verify
newman --version
```

---

## Configuration

### Environment Variables (Optional)

Create `.env` file for sensitive configuration:

```bash
cat > .env << 'EOF'
# Target Configuration
TARGET_URL=https://example.com

# Credentials
TEST_USERNAME=test_user
TEST_PASSWORD=test_password

# API Keys
API_KEY=your_api_key_here

# Tool Paths
ZAP_PATH=/opt/zaproxy/zap.sh
TESTSSL_PATH=/opt/testssl.sh/testssl.sh
EOF

# Secure the file
chmod 600 .env
```

### Update Tool Paths

Edit `config/tool_paths.yaml` to match your installation:

```bash
# Find tool locations
which nikto
which lynis
which trivy
which newman

# Update config/tool_paths.yaml accordingly
```

---

## Verification

### Test Installation

#### 1. Verify Python Environment

```bash
# Check Python version
python --version

# Check installed packages
pip list | grep -E "requests|beautifulsoup4|pyyaml"
```

#### 2. Test Module Execution

```bash
# Test help command
python run_module.py --help

# List available modules
python run_module.py --list

# Run Module 1 in test mode
python run_module.py --module=1 --test
```

#### 3. Verify Tool Integration

```bash
# Check tool availability
./setup.sh  # Re-run to see tool status

# Test individual tools
nikto -Version
lynis version
trivy --version
```

#### 4. Run Sample Scan

```bash
# Create test target
mkdir -p test_logs
echo "2025-11-25 10:00:00 [INFO] User logged in" > test_logs/app.log

# Run Module 6 (Logging)
python run_module.py --module=6 --log-path test_logs/ --debug

# Check output
cat outputs/logging_monitoring_analyzer.json
```

### Expected Output

Successful installation should show:

```
[SUCCESS] Module 6 -> outputs/logging_monitoring_analyzer.json
```

---

## Troubleshooting

### Common Issues

#### Issue: ModuleNotFoundError: No module named 'common'

**Solution**: Run from project root directory

```bash
cd /path/to/GAP-ANALYSIS
python run_module.py --module=1 --help
```

#### Issue: Permission denied when running setup.sh

**Solution**: Make script executable

```bash
chmod +x setup.sh
./setup.sh
```

#### Issue: pip install fails

**Solution**: Upgrade pip and retry

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Issue: Virtual environment not activating

**Solution**: Recreate virtual environment

```bash
rm -rf gavenv
python3 -m venv gavenv
source gavenv/bin/activate
pip install -r requirements.txt
```

#### Issue: Tool not found (ZAP, testssl.sh, etc.)

**Solution**: Update tool paths in config/tool_paths.yaml

```bash
# Find tool location
which <tool_name>

# Update config/tool_paths.yaml with correct path
```

#### Issue: SSL certificate verification failed

**Solution**: Disable SSL verification in config

```yaml
# config/config.yaml
target:
  verify_ssl: false
```

### Getting Help

1. Check module README: `module*/README.md`
2. Review logs: `logs/*.log`
3. Run with debug flag: `--debug`
4. Check setup script output: `./setup.sh`

---

## Post-Installation

### Next Steps

1. **Configure Targets**
   ```bash
   # Edit config/config.yaml
   nano config/config.yaml
   ```

2. **Prepare Evidence**
   ```bash
   # Create evidence directory structure
   mkdir -p evidence/{policies,logs,infrastructure}
   ```

3. **Run Test Scan**
   ```bash
   # Test against example.com
   python run_module.py --module=1 --target https://example.com --debug
   ```

4. **Review Results**
   ```bash
   # Check outputs
   ls -la outputs/
   cat outputs/module1.json | python -m json.tool
   ```

### Deployment Checklist

- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] Python dependencies installed
- [ ] Configuration files created
- [ ] Optional tools installed (as needed)
- [ ] Tool paths configured
- [ ] Test scan completed successfully
- [ ] Output directory accessible
- [ ] Logs directory writable

---

## Quick Reference

### Daily Usage

```bash
# Activate environment
cd /path/to/GAP-ANALYSIS
source gavenv/bin/activate

# Run single module
python run_module.py --module=1 --target https://example.com

# Run all modules
./run_all.sh

# Deactivate environment
deactivate
```

### Update System

```bash
# Update Python dependencies
pip install -r requirements.txt --upgrade

# Update security tools
sudo apt update && sudo apt upgrade -y
```

---

## Summary

**Installation Time**: 10-15 minutes (basic) | 30-45 minutes (with all tools)

**Required Steps**:
1. Install Python 3.8+
2. Create virtual environment
3. Install Python dependencies
4. Configure system

**Optional Steps**:
1. Install security tools (ZAP, Nikto, testssl.sh, etc.)
2. Configure tool paths
3. Set up environment variables

**Verification**:
```bash
python run_module.py --list
python run_module.py --module=1 --test
```

The system is now ready for security assessments.
