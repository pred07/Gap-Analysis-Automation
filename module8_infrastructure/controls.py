"""
Control implementations for Module 8 infrastructure and container security checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ControlResult:
    name: str
    status: str
    findings: List[Dict]


def run_host_hardening(documents: List[Dict], logger) -> ControlResult:
    """Control 060: Host/OS hardening implementation."""
    findings = []
    
    if not documents:
        return ControlResult("Host_Hardening", "not_tested", findings)
    
    # Keywords indicating host hardening practices
    hardening_keywords = [
        "hardening", "cis benchmark", "security baseline", "lynis",
        "os hardening", "system hardening", "security configuration",
        "firewall", "selinux", "apparmor", "kernel hardening"
    ]
    
    evidence_found = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in hardening_keywords:
            if keyword in content:
                evidence_found = True
                logger.info(f"[Host Hardening] Found '{keyword}' in documentation")
                break
        if evidence_found:
            break
    
    if not evidence_found:
        findings.append({"indicator": "no_host_hardening_evidence"})
        logger.warning("[Host Hardening] No host hardening evidence found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Host_Hardening", status, findings)


def run_container_security(documents: List[Dict], logger) -> ControlResult:
    """Control 061: Container image security."""
    findings = []
    
    if not documents:
        return ControlResult("Container_Security", "not_tested", findings)
    
    # Keywords indicating container security practices
    container_keywords = [
        "container scan", "image scan", "trivy", "clair", "anchore",
        "vulnerability scan", "docker scan", "container security",
        "base image", "minimal image", "distroless"
    ]
    
    evidence_found = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in container_keywords:
            if keyword in content:
                evidence_found = True
                logger.info(f"[Container Security] Found '{keyword}' in documentation")
                break
        if evidence_found:
            break
    
    if not evidence_found:
        findings.append({"indicator": "no_container_security_evidence"})
        logger.warning("[Container Security] No container security evidence found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Container_Security", status, findings)


def run_container_runtime_security(documents: List[Dict], logger) -> ControlResult:
    """Control 062: Container runtime security configuration."""
    findings = []
    
    if not documents:
        return ControlResult("Container_Runtime_Security", "not_tested", findings)
    
    # Keywords indicating runtime security
    runtime_keywords = [
        "runtime security", "seccomp", "apparmor profile", "selinux context",
        "capabilities", "privileged container", "read-only filesystem",
        "security context", "pod security", "network policy"
    ]
    
    evidence_found = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in runtime_keywords:
            if keyword in content:
                evidence_found = True
                logger.info(f"[Runtime Security] Found '{keyword}' in documentation")
                break
        if evidence_found:
            break
    
    if not evidence_found:
        findings.append({"indicator": "no_runtime_security_evidence"})
        logger.warning("[Runtime Security] No runtime security evidence found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Container_Runtime_Security", status, findings)


def run_least_privilege(documents: List[Dict], logger) -> ControlResult:
    """Control 063: Least privilege principle enforcement."""
    findings = []
    
    if not documents:
        return ControlResult("Least_Privilege", "not_tested", findings)
    
    # Keywords indicating least privilege
    privilege_keywords = [
        "least privilege", "principle of least privilege", "minimal permissions",
        "rbac", "role-based access", "iam policy", "service account",
        "non-root", "unprivileged", "drop capabilities"
    ]
    
    evidence_found = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in privilege_keywords:
            if keyword in content:
                evidence_found = True
                logger.info(f"[Least Privilege] Found '{keyword}' in documentation")
                break
        if evidence_found:
            break
    
    if not evidence_found:
        findings.append({"indicator": "no_least_privilege_evidence"})
        logger.warning("[Least Privilege] No least privilege evidence found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Least_Privilege", status, findings)


def run_dos_protection_infrastructure(documents: List[Dict], logger) -> ControlResult:
    """Control 064: Infrastructure-level DoS protection."""
    findings = []
    
    if not documents:
        return ControlResult("DOS_Protection_Infrastructure", "not_tested", findings)
    
    # Keywords indicating DoS protection
    dos_keywords = [
        "ddos protection", "dos protection", "rate limiting", "cloudflare",
        "waf", "web application firewall", "load balancer", "auto-scaling",
        "resource limits", "throttling", "circuit breaker"
    ]
    
    evidence_found = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in dos_keywords:
            if keyword in content:
                evidence_found = True
                logger.info(f"[DoS Protection] Found '{keyword}' in documentation")
                break
        if evidence_found:
            break
    
    if not evidence_found:
        findings.append({"indicator": "no_dos_protection_evidence"})
        logger.warning("[DoS Protection] No DoS protection evidence found")
    
    status = "fail" if findings else "pass"
    return ControlResult("DOS_Protection_Infrastructure", status, findings)


def run_security_updates(documents: List[Dict], logger) -> ControlResult:
    """Control 065: Security updates and patch management."""
    findings = []
    
    if not documents:
        return ControlResult("Security_Updates", "not_tested", findings)
    
    # Keywords indicating patch management
    update_keywords = [
        "patch management", "security updates", "vulnerability patching",
        "update policy", "automated updates", "patch schedule",
        "security patches", "cve remediation", "update process"
    ]
    
    evidence_found = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in update_keywords:
            if keyword in content:
                evidence_found = True
                logger.info(f"[Security Updates] Found '{keyword}' in documentation")
                break
        if evidence_found:
            break
    
    if not evidence_found:
        findings.append({"indicator": "no_security_update_policy"})
        logger.warning("[Security Updates] No security update policy found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Security_Updates", status, findings)
