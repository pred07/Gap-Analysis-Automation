# Module 8: Infrastructure & Container Analyzer

## Overview

Module 8 automates the assessment of **6 security controls** related to infrastructure and container security, including host hardening, container security, runtime configuration, and patch management.

## Controls Covered

| Control ID | Control Name | Description | Severity |
|------------|--------------|-------------|----------|
| 060 | Host_Hardening | Host/OS hardening implementation | High |
| 061 | Container_Security | Container image security | High |
| 062 | Container_Runtime_Security | Container runtime security configuration | High |
| 063 | Least_Privilege | Least privilege principle enforcement | High |
| 064 | DOS_Protection_Infrastructure | Infrastructure-level DoS protection | Medium |
| 065 | Security_Updates | Security updates and patch management | High |

## Tools Referenced

- **Lynis** - System hardening scanning
- **Trivy** - Container vulnerability scanning
- **OpenSCAP** - Security compliance scanning

## Usage

### Basic Usage

```bash
# Run with infrastructure documentation
python run_module.py --module=8 --document-path evidence/infrastructure/ --debug

# Or directly
python -m module8_infrastructure.main --document-path evidence/infrastructure/ --debug
```

## Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | Target URL (optional) | None |
| `--document-path` | Path to policy documents | None |
| `--debug` | Enable verbose logging | False |

## Control Evaluation Logic

### Host Hardening (060)
- Checks for OS hardening evidence
- Keywords: CIS benchmark, Lynis, security baseline, firewall
- **Pass**: Hardening evidence found
- **Fail**: No hardening evidence

### Container Security (061)
- Checks for container scanning evidence
- Keywords: Trivy, image scan, vulnerability scan
- **Pass**: Container security evidence found
- **Fail**: No evidence

### Container Runtime Security (062)
- Checks for runtime security configuration
- Keywords: seccomp, AppArmor, capabilities, security context
- **Pass**: Runtime security evidence found
- **Fail**: No evidence

### Least Privilege (063)
- Checks for least privilege enforcement
- Keywords: RBAC, minimal permissions, non-root
- **Pass**: Least privilege evidence found
- **Fail**: No evidence

### DoS Protection (064)
- Checks for DoS protection measures
- Keywords: DDoS protection, WAF, rate limiting, auto-scaling
- **Pass**: DoS protection evidence found
- **Fail**: No evidence

### Security Updates (065)
- Checks for patch management policy
- Keywords: patch management, security updates, CVE remediation
- **Pass**: Update policy found
- **Fail**: No policy

## Document Requirements

Module 8 analyzes infrastructure and security policy documents:

### Supported Formats
- Text files (.txt, .md)
- YAML files (.yaml, .yml) - Kubernetes manifests, IaC
- PDF (.pdf) - Security policies
- DOCX (.docx) - Documentation

### Sample Document Structure

```
evidence/infrastructure/
├── hardening_policy.md
├── container_security.pdf
├── kubernetes_manifests/
│   ├── deployment.yaml
│   └── security-context.yaml
└── patch_management.docx
```

## Examples

### Example 1: Basic Infrastructure Analysis

```bash
python run_module.py --module=8 --document-path evidence/infrastructure/ --debug
```

### Example 2: Create Test Documents

```bash
mkdir -p evidence/infrastructure
cat > evidence/infrastructure/security_policy.txt << 'EOF'
Infrastructure Security Policy

Host Hardening:
- All servers follow CIS benchmarks
- Lynis scans performed monthly
- Firewall rules enforced

Container Security:
- All images scanned with Trivy
- Base images updated weekly
- Non-root containers enforced

Patch Management:
- Security updates applied within 7 days
- Automated patching enabled
EOF

# Run analysis
python run_module.py --module=8 --document-path evidence/infrastructure/ --debug
```

## Integration

### With run_all.sh

```bash
./run_all.sh
```

## License

Part of the Security Controls GAP Analysis System - Phase 1
