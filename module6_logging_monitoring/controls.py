"""
Control implementations for Module 6 logging and monitoring checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional


@dataclass
class ControlResult:
    name: str
    status: str
    findings: List[Dict]


def run_authentication_logging(log_files: List[Dict], logger) -> ControlResult:
    """Control 042: Authentication events logging."""
    findings = []
    
    if not log_files:
        logger.warning("[Auth Logging] No log files provided")
        return ControlResult("Authentication_Logging", "not_tested", findings)
    
    # Keywords indicating authentication events
    auth_keywords = [
        "login", "logout", "signin", "signout", "authenticate", "authentication",
        "logged in", "logged out", "sign in", "sign out", "auth success", "auth fail"
    ]
    
    auth_events_found = False
    for log_file in log_files:
        content = log_file.get("content", "").lower()
        for keyword in auth_keywords:
            if keyword in content:
                auth_events_found = True
                logger.info(f"[Auth Logging] Found '{keyword}' in {log_file.get('name')}")
                break
        if auth_events_found:
            break
    
    if not auth_events_found:
        findings.append({"indicator": "no_authentication_logging_detected"})
        logger.warning("[Auth Logging] No authentication events found in logs")
    
    status = "fail" if findings else "pass"
    return ControlResult("Authentication_Logging", status, findings)


def run_authorization_logging(log_files: List[Dict], logger) -> ControlResult:
    """Control 043: Authorization events logging."""
    findings = []
    
    if not log_files:
        return ControlResult("Authorization_Logging", "not_tested", findings)
    
    # Keywords indicating authorization events
    authz_keywords = [
        "access denied", "permission denied", "unauthorized", "forbidden",
        "access granted", "permission granted", "authorized", "role", "privilege"
    ]
    
    authz_events_found = False
    for log_file in log_files:
        content = log_file.get("content", "").lower()
        for keyword in authz_keywords:
            if keyword in content:
                authz_events_found = True
                logger.info(f"[Authz Logging] Found '{keyword}' in {log_file.get('name')}")
                break
        if authz_events_found:
            break
    
    if not authz_events_found:
        findings.append({"indicator": "no_authorization_logging_detected"})
        logger.warning("[Authz Logging] No authorization events found in logs")
    
    status = "fail" if findings else "pass"
    return ControlResult("Authorization_Logging", status, findings)


def run_access_logging(log_files: List[Dict], logger) -> ControlResult:
    """Control 044: System access logging."""
    findings = []
    
    if not log_files:
        return ControlResult("Access_Logging", "not_tested", findings)
    
    # Look for access log patterns (IP addresses, HTTP methods, status codes)
    access_patterns = [
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address
        r"(GET|POST|PUT|DELETE|PATCH)\s+/",  # HTTP methods
        r"\s(200|201|204|301|302|400|401|403|404|500)\s",  # HTTP status codes
    ]
    
    access_logs_found = False
    for log_file in log_files:
        content = log_file.get("content", "")
        for pattern in access_patterns:
            if re.search(pattern, content):
                access_logs_found = True
                logger.info(f"[Access Logging] Found access log pattern in {log_file.get('name')}")
                break
        if access_logs_found:
            break
    
    if not access_logs_found:
        findings.append({"indicator": "no_access_logging_detected"})
        logger.warning("[Access Logging] No access logs found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Access_Logging", status, findings)


def run_error_logging(log_files: List[Dict], logger) -> ControlResult:
    """Control 045: Error and exception logging."""
    findings = []
    
    if not log_files:
        return ControlResult("Error_Logging", "not_tested", findings)
    
    # Keywords indicating error logging
    error_keywords = [
        "error", "exception", "fatal", "critical", "warning", "traceback",
        "stack trace", "failed", "failure"
    ]
    
    error_logs_found = False
    for log_file in log_files:
        content = log_file.get("content", "").lower()
        for keyword in error_keywords:
            if keyword in content:
                error_logs_found = True
                logger.info(f"[Error Logging] Found '{keyword}' in {log_file.get('name')}")
                break
        if error_logs_found:
            break
    
    if not error_logs_found:
        findings.append({"indicator": "no_error_logging_detected"})
        logger.warning("[Error Logging] No error logs found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Error_Logging", status, findings)


def run_security_event_logging(log_files: List[Dict], logger) -> ControlResult:
    """Control 046: Security events logging."""
    findings = []
    
    if not log_files:
        return ControlResult("Security_Event_Logging", "not_tested", findings)
    
    # Keywords indicating security events
    security_keywords = [
        "security", "attack", "intrusion", "breach", "vulnerability",
        "malicious", "suspicious", "blocked", "firewall", "ids", "ips",
        "sql injection", "xss", "csrf", "brute force"
    ]
    
    security_events_found = False
    for log_file in log_files:
        content = log_file.get("content", "").lower()
        for keyword in security_keywords:
            if keyword in content:
                security_events_found = True
                logger.info(f"[Security Logging] Found '{keyword}' in {log_file.get('name')}")
                break
        if security_events_found:
            break
    
    if not security_events_found:
        findings.append({"indicator": "no_security_event_logging_detected"})
        logger.warning("[Security Logging] No security events found in logs")
    
    status = "fail" if findings else "pass"
    return ControlResult("Security_Event_Logging", status, findings)


def run_audit_trail_completeness(log_files: List[Dict], logger) -> ControlResult:
    """Control 047: Complete audit trail maintenance."""
    findings = []
    
    if not log_files:
        return ControlResult("Audit_Trail_Completeness", "not_tested", findings)
    
    # Check for essential audit trail components
    required_components = {
        "timestamp": [r"\d{4}-\d{2}-\d{2}", r"\d{2}/\d{2}/\d{4}", r"\[\d{2}:\d{2}:\d{2}\]"],
        "user": ["user", "username", "userid", "uid"],
        "action": ["action", "event", "operation", "method"],
        "result": ["success", "fail", "error", "status"],
    }
    
    components_found = {key: False for key in required_components}
    
    for log_file in log_files:
        content = log_file.get("content", "").lower()
        
        # Check for timestamps
        for pattern in required_components["timestamp"]:
            if re.search(pattern, content):
                components_found["timestamp"] = True
                break
        
        # Check for other components
        for component, keywords in required_components.items():
            if component == "timestamp":
                continue
            for keyword in keywords:
                if keyword in content:
                    components_found[component] = True
                    break
    
    missing_components = [comp for comp, found in components_found.items() if not found]
    
    if missing_components:
        findings.append({
            "indicator": "incomplete_audit_trail",
            "missing_components": missing_components
        })
        logger.warning(f"[Audit Trail] Missing components: {', '.join(missing_components)}")
    
    status = "fail" if findings else "pass"
    return ControlResult("Audit_Trail_Completeness", status, findings)


def run_log_integrity(log_files: List[Dict], documents: List[Dict], logger) -> ControlResult:
    """Control 048: Log integrity and tamper protection."""
    findings = []
    
    if not log_files and not documents:
        return ControlResult("Log_Integrity", "not_tested", findings)
    
    # Check documents for log integrity policies
    integrity_keywords = [
        "log integrity", "tamper-proof", "immutable", "hash", "checksum",
        "digital signature", "write-once", "append-only", "syslog", "centralized logging"
    ]
    
    integrity_measures_found = False
    
    # Check documents
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in integrity_keywords:
            if keyword in content:
                integrity_measures_found = True
                logger.info(f"[Log Integrity] Found '{keyword}' in documentation")
                break
        if integrity_measures_found:
            break
    
    # Check log files for integrity indicators
    if not integrity_measures_found:
        for log_file in log_files:
            content = log_file.get("content", "").lower()
            # Look for hash/checksum patterns
            if re.search(r"(hash|checksum|signature):\s*[a-f0-9]{32,}", content):
                integrity_measures_found = True
                logger.info(f"[Log Integrity] Found integrity hash in {log_file.get('name')}")
                break
    
    if not integrity_measures_found:
        findings.append({"indicator": "no_log_integrity_measures_detected"})
        logger.warning("[Log Integrity] No integrity protection measures found")
    
    status = "fail" if findings else ("not_tested" if not log_files and not documents else "pass")
    return ControlResult("Log_Integrity", status, findings)


def run_log_retention(log_files: List[Dict], documents: List[Dict], logger) -> ControlResult:
    """Control 049: Log retention and archival."""
    findings = []
    
    if not log_files and not documents:
        return ControlResult("Log_Retention", "not_tested", findings)
    
    # Check documents for retention policies
    retention_keywords = [
        "retention", "archival", "archive", "retention period", "retention policy",
        "90 days", "180 days", "1 year", "2 years", "backup", "log rotation"
    ]
    
    retention_policy_found = False
    
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in retention_keywords:
            if keyword in content:
                retention_policy_found = True
                logger.info(f"[Log Retention] Found '{keyword}' in documentation")
                break
        if retention_policy_found:
            break
    
    # Check log files for rotation indicators
    if not retention_policy_found:
        for log_file in log_files:
            name = log_file.get("name", "").lower()
            # Look for dated log files or rotation patterns
            if re.search(r"\d{4}-\d{2}-\d{2}|\d{8}|\.log\.\d+|\.gz$|\.zip$", name):
                retention_policy_found = True
                logger.info(f"[Log Retention] Found log rotation pattern in {name}")
                break
    
    if not retention_policy_found:
        findings.append({"indicator": "no_log_retention_policy_detected"})
        logger.warning("[Log Retention] No retention policy or rotation found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Log_Retention", status, findings)
