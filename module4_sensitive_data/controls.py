"""
Control implementations for Module 4 sensitive data protection checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests


@dataclass
class ControlResult:
    name: str
    status: str
    findings: List[Dict]


def run_https_tls(target: str, tls_results: Dict, logger) -> ControlResult:
    """Control 023: HTTPS/TLS implementation."""
    findings = []
    
    if not target.startswith("https://"):
        findings.append({"url": target, "indicator": "http_not_https"})
        logger.warning(f"[HTTPS/TLS] {target} does not use HTTPS")
        return ControlResult("HTTPS_TLS", "fail", findings)
    
    # Check TLS scan results if available
    if tls_results.get("success"):
        tls_version = tls_results.get("tls_version", "")
        if "TLS 1.2" not in tls_version and "TLS 1.3" not in tls_version:
            findings.append({"url": target, "indicator": "weak_tls_version", "version": tls_version})
            logger.warning(f"[HTTPS/TLS] {target} uses weak TLS version: {tls_version}")
            return ControlResult("HTTPS_TLS", "fail", findings)
        
        cert_valid = tls_results.get("cert_valid", False)
        if not cert_valid:
            findings.append({"url": target, "indicator": "invalid_certificate"})
            logger.warning(f"[HTTPS/TLS] {target} has invalid certificate")
            return ControlResult("HTTPS_TLS", "fail", findings)
        
        logger.info(f"[HTTPS/TLS] {target} has valid TLS configuration")
        return ControlResult("HTTPS_TLS", "pass", findings)
    
    # If no TLS scan results, mark as not_tested
    logger.warning("[HTTPS/TLS] No TLS scan results available")
    return ControlResult("HTTPS_TLS", "not_tested", findings)


def run_sensitive_data_masking(pages: List[Dict], logger) -> ControlResult:
    """Control 024: Sensitive data masking in UI/logs."""
    findings = []
    
    # Patterns for unmasked sensitive data
    patterns = {
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "api_key": r"(api[_-]?key|apikey)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})",
    }
    
    for page in pages[:10]:  # Check first 10 pages
        content = page.get("content", "")
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    "url": page["url"],
                    "indicator": f"unmasked_{pattern_name}",
                    "count": len(matches)
                })
                logger.warning(f"[Masking] Found unmasked {pattern_name} in {page['url']}")
    
    status = "fail" if findings else ("not_tested" if not pages else "pass")
    return ControlResult("Sensitive_Data_Masking", status, findings)


def run_password_encryption_rest(documents: List[Dict], logger) -> ControlResult:
    """Control 025: Password encryption at rest."""
    findings = []
    
    if not documents:
        logger.warning("[Password Encryption] No documents provided for analysis")
        return ControlResult("Password_Encryption_Rest", "not_tested", findings)
    
    # Keywords indicating strong password hashing
    strong_keywords = ["bcrypt", "scrypt", "pbkdf2", "argon2", "sha-256", "sha-512"]
    weak_keywords = ["md5", "sha1", "plaintext", "clear-text"]
    
    has_strong = False
    has_weak = False
    
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in strong_keywords:
            if keyword in content:
                has_strong = True
                logger.info(f"[Password Encryption] Found {keyword} in documentation")
                break
        for keyword in weak_keywords:
            if keyword in content:
                has_weak = True
                findings.append({"document": doc.get("name", "unknown"), "indicator": f"weak_hashing_{keyword}"})
                logger.warning(f"[Password Encryption] Found weak hashing: {keyword}")
    
    if has_weak:
        return ControlResult("Password_Encryption_Rest", "fail", findings)
    elif has_strong:
        return ControlResult("Password_Encryption_Rest", "pass", findings)
    else:
        return ControlResult("Password_Encryption_Rest", "not_tested", findings)


def run_data_rest_encryption(documents: List[Dict], logger) -> ControlResult:
    """Control 026: Data-at-rest encryption."""
    findings = []
    
    if not documents:
        return ControlResult("Data_Rest_Encryption", "not_tested", findings)
    
    encryption_keywords = ["aes-256", "aes-128", "encryption at rest", "tde", "transparent data encryption", "database encryption"]
    
    has_encryption = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in encryption_keywords:
            if keyword in content:
                has_encryption = True
                logger.info(f"[Data Encryption] Found '{keyword}' in documentation")
                break
    
    status = "pass" if has_encryption else "not_tested"
    return ControlResult("Data_Rest_Encryption", status, findings)


def run_data_transit_encryption(target: str, tls_results: Dict, logger) -> ControlResult:
    """Control 027: Data-in-transit encryption."""
    findings = []
    
    if not target.startswith("https://"):
        findings.append({"url": target, "indicator": "no_https"})
        logger.warning(f"[Data Transit] {target} does not use HTTPS")
        return ControlResult("Data_Transit_Encryption", "fail", findings)
    
    # Check for mixed content if TLS results available
    if tls_results.get("success"):
        mixed_content = tls_results.get("mixed_content", False)
        if mixed_content:
            findings.append({"url": target, "indicator": "mixed_content_detected"})
            logger.warning(f"[Data Transit] Mixed content detected in {target}")
            return ControlResult("Data_Transit_Encryption", "fail", findings)
        
        logger.info(f"[Data Transit] {target} properly encrypts data in transit")
        return ControlResult("Data_Transit_Encryption", "pass", findings)
    
    # Basic check passed (HTTPS), but no detailed scan
    logger.info(f"[Data Transit] {target} uses HTTPS (detailed scan not available)")
    return ControlResult("Data_Transit_Encryption", "pass", findings)


def run_pci_pan_masking(pages: List[Dict], documents: List[Dict], logger) -> ControlResult:
    """Control 028: PCI PAN masking."""
    findings = []
    
    # PAN pattern (credit card numbers)
    pan_pattern = r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
    masked_pan_pattern = r"\*{4,12}[-\s]?\d{4}"
    
    # Check pages
    for page in pages[:10]:
        content = page.get("content", "")
        pans = re.findall(pan_pattern, content)
        masked_pans = re.findall(masked_pan_pattern, content)
        
        # If we find unmasked PANs
        if pans and not masked_pans:
            findings.append({"url": page["url"], "indicator": "unmasked_pan", "count": len(pans)})
            logger.warning(f"[PCI PAN] Unmasked PANs found in {page['url']}")
    
    # Check documents
    for doc in documents:
        content = doc.get("content", "")
        pans = re.findall(pan_pattern, content)
        if pans:
            findings.append({"document": doc.get("name", "unknown"), "indicator": "pan_in_document"})
            logger.warning(f"[PCI PAN] PANs found in document {doc.get('name')}")
    
    status = "fail" if findings else ("not_tested" if not pages and not documents else "pass")
    return ControlResult("PCI_PAN_Masking", status, findings)


def run_pci_sad_not_stored(documents: List[Dict], logger) -> ControlResult:
    """Control 029: PCI SAD (Sensitive Authentication Data) not stored."""
    findings = []
    
    if not documents:
        return ControlResult("PCI_SAD_Not_Stored", "not_tested", findings)
    
    # SAD keywords (CVV, PIN, track data)
    sad_patterns = {
        "cvv": r"\b(cvv|cvc|cvv2|cvc2)[\s:=]+\d{3,4}\b",
        "pin": r"\bpin[\s:=]+\d{4,6}\b",
        "track": r"track[\s_-]?(1|2|data)",
    }
    
    for doc in documents:
        content = doc.get("content", "").lower()
        for sad_type, pattern in sad_patterns.items():
            if re.search(pattern, content):
                findings.append({"document": doc.get("name", "unknown"), "indicator": f"sad_stored_{sad_type}"})
                logger.warning(f"[PCI SAD] {sad_type.upper()} data found in {doc.get('name')}")
    
    # Check for policy documentation
    policy_keywords = ["cvv not stored", "pin not stored", "sad not stored", "sensitive authentication data"]
    has_policy = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in policy_keywords:
            if keyword in content:
                has_policy = True
                break
    
    if findings:
        return ControlResult("PCI_SAD_Not_Stored", "fail", findings)
    elif has_policy:
        return ControlResult("PCI_SAD_Not_Stored", "pass", findings)
    else:
        return ControlResult("PCI_SAD_Not_Stored", "not_tested", findings)


def run_pci_log_masking(log_files: List[Dict], logger) -> ControlResult:
    """Control 030: PCI log masking."""
    findings = []
    
    if not log_files:
        logger.warning("[PCI Log Masking] No log files provided")
        return ControlResult("PCI_Log_Masking", "not_tested", findings)
    
    # Patterns for sensitive data in logs
    sensitive_patterns = {
        "pan": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "cvv": r"\b(cvv|cvc)[\s:=]+\d{3,4}\b",
        "password": r"password[\s:=]+['\"]?[^'\"\s]{6,}",
    }
    
    for log_file in log_files:
        content = log_file.get("content", "")
        for pattern_name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    "file": log_file.get("name", "unknown"),
                    "indicator": f"unmasked_{pattern_name}_in_logs",
                    "count": len(matches)
                })
                logger.warning(f"[PCI Log] Unmasked {pattern_name} in {log_file.get('name')}")
    
    status = "fail" if findings else "pass"
    return ControlResult("PCI_Log_Masking", status, findings)


def run_local_db_security(documents: List[Dict], logger) -> ControlResult:
    """Control 031: Local database security."""
    findings = []
    
    if not documents:
        return ControlResult("Local_DB_Security", "not_tested", findings)
    
    security_keywords = ["sqlite encryption", "database encryption", "sqlcipher", "encrypted database", "file permissions"]
    
    has_security = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in security_keywords:
            if keyword in content:
                has_security = True
                logger.info(f"[Local DB] Found '{keyword}' in documentation")
                break
    
    status = "pass" if has_security else "not_tested"
    return ControlResult("Local_DB_Security", status, findings)


def run_clear_text_detection(pages: List[Dict], logger) -> ControlResult:
    """Control 032: Clear-text password/data detection."""
    findings = []
    
    # Patterns for clear-text sensitive data
    clear_text_patterns = {
        "password": r"password[\s:=]+['\"]?([^'\"\s]{6,})['\"]?",
        "api_key": r"(api[_-]?key|apikey)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})",
        "secret": r"(secret|token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})",
        "connection_string": r"(mysql|postgres|mongodb)://[^:]+:[^@]+@",
    }
    
    for page in pages[:15]:
        content = page.get("content", "")
        for pattern_name, pattern in clear_text_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    "url": page["url"],
                    "indicator": f"clear_text_{pattern_name}",
                    "count": len(matches)
                })
                logger.warning(f"[Clear-text] Found {pattern_name} in {page['url']}")
    
    status = "fail" if findings else ("not_tested" if not pages else "pass")
    return ControlResult("Clear_Text_Detection", status, findings)


def run_local_device_storage(documents: List[Dict], logger) -> ControlResult:
    """Control 033: Local device storage security."""
    findings = []
    
    if not documents:
        return ControlResult("Local_Device_Storage", "not_tested", findings)
    
    storage_keywords = ["keychain", "keystore", "secure storage", "encrypted storage", "secure enclave"]
    
    has_secure_storage = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in storage_keywords:
            if keyword in content:
                has_secure_storage = True
                logger.info(f"[Local Storage] Found '{keyword}' in documentation")
                break
    
    status = "pass" if has_secure_storage else "not_tested"
    return ControlResult("Local_Device_Storage", status, findings)


def run_ui_tampering_protection(documents: List[Dict], logger) -> ControlResult:
    """Control 034: UI tampering protection."""
    findings = []
    
    if not documents:
        return ControlResult("UI_Tampering_Protection", "not_tested", findings)
    
    protection_keywords = ["obfuscation", "code obfuscation", "anti-tampering", "integrity check", "jailbreak detection", "root detection"]
    
    has_protection = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in protection_keywords:
            if keyword in content:
                has_protection = True
                logger.info(f"[UI Tampering] Found '{keyword}' in documentation")
                break
    
    status = "pass" if has_protection else "not_tested"
    return ControlResult("UI_Tampering_Protection", status, findings)
