#!/bin/bash

# ============================================================================
# Security GAP Analysis System - Setup Script
# ============================================================================
# This script sets up the complete Phase 1 environment
# Run with: chmod +x setup.sh && ./setup.sh
# ============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}============================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_command() {
    if command -v $1 &> /dev/null; then
        print_success "$1 is installed"
        return 0
    else
        print_warning "$1 is not installed"
        return 1
    fi
}

# Main script
print_header "Security GAP Analysis System - Setup"

# Check OS
print_info "Detecting operating system..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    print_success "Linux detected"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    print_success "macOS detected"
else
    print_error "Unsupported OS: $OSTYPE"
    exit 1
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_warning "Running as root. Some operations may require non-root user."
fi

# Create directory structure
print_header "Creating Directory Structure"
directories=(
    "config"
    "common"
    "module1_input_validation"
    "module2_authentication"
    "module3_authorization"
    "module4_sensitive_data"
    "module5_session_management"
    "module6_logging_monitoring"
    "module7_api_security"
    "module8_infrastructure"
    "outputs"
    "logs"
    "merge"
    "docs"
    "tests"
    "cache"
    "evidence"
)

for dir in "${directories[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        print_success "Created directory: $dir"
    else
        print_info "Directory exists: $dir"
    fi
done

# Check Python
print_header "Checking Python Environment"
if ! check_command python3; then
    print_error "Python 3 is required but not installed"
    print_info "Install: sudo apt install python3 python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_info "Python version: $PYTHON_VERSION"

# Check pip
if ! check_command pip3; then
    print_error "pip3 is required but not installed"
    print_info "Install: sudo apt install python3-pip"
    exit 1
fi

# Install Python dependencies
print_header "Installing Python Dependencies"
if [ -f "requirements.txt" ]; then
    print_info "Installing from requirements.txt..."
    pip3 install -r requirements.txt --upgrade
    print_success "Python dependencies installed"
else
    print_warning "requirements.txt not found. Please create it."
fi

# Check for security tools
print_header "Checking Security Tools"

# Check Git
check_command git || print_warning "Git not installed: sudo apt install git"

# Check curl
check_command curl || print_warning "curl not installed: sudo apt install curl"

# Check wget
check_command wget || print_warning "wget not installed: sudo apt install wget"

# Check Nikto
check_command nikto || print_warning "Nikto not installed: sudo apt install nikto"

# Check Lynis
check_command lynis || print_warning "Lynis not installed: sudo apt install lynis"

# Check OpenSSL
check_command openssl || print_warning "OpenSSL not installed (usually pre-installed)"

# Check Node/npm (for Newman)
if check_command npm; then
    # Check Newman
    if ! check_command newman; then
        print_info "Installing Newman (Postman CLI)..."
        sudo npm install -g newman
        print_success "Newman installed"
    fi
else
    print_warning "npm not installed. Newman requires Node.js/npm"
    print_info "Install: sudo apt install nodejs npm"
fi

# Check for Java (required for ZAP)
if ! check_command java; then
    print_warning "Java not installed. OWASP ZAP requires Java 11+"
    print_info "Install: sudo apt install openjdk-11-jdk"
fi

# Install OWASP ZAP
print_header "OWASP ZAP Installation"
if [ ! -d "/opt/zaproxy" ]; then
    print_info "OWASP ZAP not found. Install manually or run:"
    echo "  wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz"
    echo "  tar -xzf ZAP_2.14.0_Linux.tar.gz"
    echo "  sudo mv ZAP_2.14.0 /opt/zaproxy"
else
    print_success "OWASP ZAP found at /opt/zaproxy"
fi

# Install testssl.sh
print_header "testssl.sh Installation"
if [ ! -d "/opt/testssl.sh" ]; then
    print_info "Installing testssl.sh..."
    sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
    sudo chmod +x /opt/testssl.sh/testssl.sh
    print_success "testssl.sh installed"
else
    print_success "testssl.sh found at /opt/testssl.sh"
fi

# Install Trivy
print_header "Trivy Installation"
if ! check_command trivy; then
    print_info "Installing Trivy..."
    if [ "$OS" == "linux" ]; then
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt update && sudo apt install trivy -y
        print_success "Trivy installed"
    elif [ "$OS" == "macos" ]; then
        brew install trivy
        print_success "Trivy installed via Homebrew"
    fi
fi

# Create example config files
print_header "Creating Configuration Files"

# Check if config files exist
if [ ! -f "config/config.yaml" ]; then
    print_info "Create config/config.yaml with your settings"
else
    print_success "config/config.yaml exists"
fi

if [ ! -f "config/tool_paths.yaml" ]; then
    print_info "Create config/tool_paths.yaml with tool paths"
else
    print_success "config/tool_paths.yaml exists"
fi

if [ ! -f "config/control_mapping.yaml" ]; then
    print_info "Create config/control_mapping.yaml with control definitions"
else
    print_success "config/control_mapping.yaml exists"
fi

# Set permissions
print_header "Setting Permissions"
chmod +x setup.sh 2>/dev/null || true
chmod -R 755 outputs logs cache evidence 2>/dev/null || true
print_success "Permissions set"

# Create .gitignore
print_header "Creating .gitignore"
if [ ! -f ".gitignore" ]; then
    cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
.venv/

# Outputs
outputs/*.json
outputs/*.xml
outputs/*.html
logs/*.log
cache/*
evidence/*

# Sensitive data
config/config.yaml
*.key
*.pem
*.p12
credentials.txt

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Test coverage
.coverage
htmlcov/

# Backups
*.backup
*.bak
EOF
    print_success ".gitignore created"
else
    print_info ".gitignore exists"
fi

# Print summary
print_header "Setup Summary"
echo ""
print_success "Directory structure created"
print_success "Python dependencies installed"
print_info "Security tools status:"
echo "  - Nikto:      $(check_command nikto && echo 'Installed' || echo 'Not installed')"
echo "  - Lynis:      $(check_command lynis && echo 'Installed' || echo 'Not installed')"
echo "  - Trivy:      $(check_command trivy && echo 'Installed' || echo 'Not installed')"
echo "  - Newman:     $(check_command newman && echo 'Installed' || echo 'Not installed')"
echo "  - testssl.sh: $([ -f '/opt/testssl.sh/testssl.sh' ] && echo 'Installed' || echo 'Not installed')"
echo "  - OWASP ZAP:  $([ -d '/opt/zaproxy' ] && echo 'Installed' || echo 'Not installed')"

echo ""
print_header "Next Steps"
echo "1. Configure your settings in config/config.yaml"
echo "2. Update tool paths in config/tool_paths.yaml"
echo "3. Review control mappings in config/control_mapping.yaml"
echo "4. Run a test: python3 run_module.py --module=1 --test"
echo "5. Run all modules: ./run_all.sh"
echo ""
print_success "Setup complete!"
