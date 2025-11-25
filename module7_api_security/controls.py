"""
Control implementations for Module 7 API security checks.
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


def run_api_method_security(api_endpoints: List[str], session_factory, logger) -> ControlResult:
    """Control 050: API HTTP method restrictions."""
    findings = []
    
    if not api_endpoints:
        return ControlResult("API_Method_Security", "not_tested", findings)
    
    session = session_factory()
    
    # Test for improper HTTP method handling
    for endpoint in api_endpoints[:10]:
        try:
            # Test if OPTIONS is properly handled
            resp_options = session.options(endpoint, timeout=5)
            allowed_methods = resp_options.headers.get("Allow", "")
            
            # Test if dangerous methods are allowed
            dangerous_methods = ["TRACE", "TRACK", "DELETE", "PUT"]
            for method in dangerous_methods:
                try:
                    resp = session.request(method, endpoint, timeout=5)
                    if resp.status_code < 400:
                        findings.append({
                            "endpoint": endpoint,
                            "method": method,
                            "status_code": resp.status_code,
                            "indicator": f"dangerous_method_{method.lower()}_allowed"
                        })
                        logger.warning(f"[API Method] {method} allowed on {endpoint}")
                except:
                    pass
        except Exception as e:
            logger.debug(f"[API Method] Error testing {endpoint}: {e}")
    
    status = "fail" if findings else ("not_tested" if not api_endpoints else "pass")
    return ControlResult("API_Method_Security", status, findings)


def run_api_rate_limiting(api_endpoints: List[str], session_factory, logger) -> ControlResult:
    """Control 051: API rate limiting implementation."""
    findings = []
    
    if not api_endpoints:
        return ControlResult("API_Rate_Limiting", "not_tested", findings)
    
    session = session_factory()
    
    # Test rate limiting by making multiple rapid requests
    for endpoint in api_endpoints[:3]:
        try:
            rate_limit_detected = False
            
            # Make 20 rapid requests
            for i in range(20):
                resp = session.get(endpoint, timeout=5)
                
                # Check for rate limit headers
                if "X-RateLimit-Limit" in resp.headers or "X-Rate-Limit" in resp.headers:
                    rate_limit_detected = True
                    logger.info(f"[Rate Limiting] Rate limit headers found on {endpoint}")
                    break
                
                # Check for 429 Too Many Requests
                if resp.status_code == 429:
                    rate_limit_detected = True
                    logger.info(f"[Rate Limiting] Rate limit enforced (429) on {endpoint}")
                    break
            
            if not rate_limit_detected:
                findings.append({
                    "endpoint": endpoint,
                    "indicator": "no_rate_limiting_detected"
                })
                logger.warning(f"[Rate Limiting] No rate limiting on {endpoint}")
                
        except Exception as e:
            logger.debug(f"[Rate Limiting] Error testing {endpoint}: {e}")
    
    status = "fail" if findings else "pass"
    return ControlResult("API_Rate_Limiting", status, findings)


def run_api_input_validation(api_endpoints: List[str], session_factory, logger) -> ControlResult:
    """Control 052: API input validation."""
    findings = []
    
    if not api_endpoints:
        return ControlResult("API_Input_Validation", "not_tested", findings)
    
    session = session_factory()
    
    # Test with malicious payloads
    test_payloads = [
        "' OR '1'='1",  # SQL injection
        "<script>alert(1)</script>",  # XSS
        "../../../etc/passwd",  # Path traversal
        "999999999999999999999",  # Integer overflow
    ]
    
    for endpoint in api_endpoints[:5]:
        try:
            for payload in test_payloads:
                # Test in query parameters
                resp = session.get(f"{endpoint}?test={payload}", timeout=5)
                
                # Check if payload is reflected without encoding
                if payload in resp.text:
                    findings.append({
                        "endpoint": endpoint,
                        "payload": payload[:30],
                        "indicator": "input_not_validated_or_encoded"
                    })
                    logger.warning(f"[API Input] Payload reflected in {endpoint}")
                    break
        except Exception as e:
            logger.debug(f"[API Input] Error testing {endpoint}: {e}")
    
    status = "fail" if findings else "pass"
    return ControlResult("API_Input_Validation", status, findings)


def run_api_authentication_validation(api_endpoints: List[str], session_factory, credentials: Dict, logger) -> ControlResult:
    """Control 053: API authentication validation."""
    findings = []
    
    if not api_endpoints:
        return ControlResult("API_Authentication_Validation", "not_tested", findings)
    
    session = session_factory()
    
    # Test endpoints without authentication
    for endpoint in api_endpoints[:10]:
        try:
            resp = session.get(endpoint, timeout=5)
            
            # If endpoint returns 200 without auth, it might be unprotected
            if resp.status_code == 200:
                # Check if it looks like it should be protected
                if any(keyword in endpoint.lower() for keyword in ["admin", "user", "account", "profile", "private"]):
                    findings.append({
                        "endpoint": endpoint,
                        "status_code": resp.status_code,
                        "indicator": "protected_endpoint_accessible_without_auth"
                    })
                    logger.warning(f"[API Auth] Protected endpoint accessible: {endpoint}")
        except Exception as e:
            logger.debug(f"[API Auth] Error testing {endpoint}: {e}")
    
    status = "fail" if findings else "pass"
    return ControlResult("API_Authentication_Validation", status, findings)


def run_api_sensitive_params(api_endpoints: List[str], session_factory, logger) -> ControlResult:
    """Control 054: Sensitive data in API parameters."""
    findings = []
    
    if not api_endpoints:
        return ControlResult("API_Sensitive_Params", "not_tested", findings)
    
    # Check for sensitive data in URLs
    sensitive_patterns = {
        "password": r"(password|pwd|pass)=",
        "api_key": r"(api[_-]?key|apikey)=",
        "token": r"(token|auth)=",
        "credit_card": r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}",
    }
    
    for endpoint in api_endpoints:
        for param_type, pattern in sensitive_patterns.items():
            if re.search(pattern, endpoint, re.IGNORECASE):
                findings.append({
                    "endpoint": endpoint,
                    "indicator": f"sensitive_{param_type}_in_url"
                })
                logger.warning(f"[API Sensitive] {param_type} found in URL: {endpoint}")
    
    status = "fail" if findings else ("not_tested" if not api_endpoints else "pass")
    return ControlResult("API_Sensitive_Params", status, findings)


def run_api_error_handling(api_endpoints: List[str], session_factory, logger) -> ControlResult:
    """Control 055: API error handling and responses."""
    findings = []
    
    if not api_endpoints:
        return ControlResult("API_Error_Handling", "not_tested", findings)
    
    session = session_factory()
    
    # Test error responses
    for endpoint in api_endpoints[:5]:
        try:
            # Test with invalid endpoint
            resp = session.get(f"{endpoint}/nonexistent", timeout=5)
            
            # Check if error reveals sensitive information
            error_indicators = [
                "stack trace", "traceback", "exception", "sql", "database",
                "file not found", "path", "directory"
            ]
            
            response_text = resp.text.lower()
            for indicator in error_indicators:
                if indicator in response_text:
                    findings.append({
                        "endpoint": endpoint,
                        "indicator": f"verbose_error_{indicator.replace(' ', '_')}"
                    })
                    logger.warning(f"[API Error] Verbose error in {endpoint}: {indicator}")
                    break
        except Exception as e:
            logger.debug(f"[API Error] Error testing {endpoint}: {e}")
    
    status = "fail" if findings else "pass"
    return ControlResult("API_Error_Handling", status, findings)


def run_api_cors_configuration(api_endpoints: List[str], session_factory, logger) -> ControlResult:
    """Control 056: CORS configuration security."""
    findings = []
    
    if not api_endpoints:
        return ControlResult("API_CORS_Configuration", "not_tested", findings)
    
    session = session_factory()
    
    # Test CORS configuration
    for endpoint in api_endpoints[:5]:
        try:
            headers = {"Origin": "https://evil.com"}
            resp = session.get(endpoint, headers=headers, timeout=5)
            
            # Check CORS headers
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            
            # Wildcard CORS is dangerous
            if acao == "*":
                findings.append({
                    "endpoint": endpoint,
                    "indicator": "cors_wildcard_allowed"
                })
                logger.warning(f"[CORS] Wildcard CORS on {endpoint}")
            
            # Reflected origin is dangerous
            elif acao == "https://evil.com":
                findings.append({
                    "endpoint": endpoint,
                    "indicator": "cors_reflected_origin"
                })
                logger.warning(f"[CORS] Reflected origin on {endpoint}")
        except Exception as e:
            logger.debug(f"[CORS] Error testing {endpoint}: {e}")
    
    status = "fail" if findings else ("not_tested" if not api_endpoints else "pass")
    return ControlResult("API_CORS_Configuration", status, findings)


def run_api_versioning(api_endpoints: List[str], logger) -> ControlResult:
    """Control 057: API versioning implementation."""
    findings = []
    
    if not api_endpoints:
        return ControlResult("API_Versioning", "not_tested", findings)
    
    # Check for version indicators in URLs
    version_patterns = [
        r"/v\d+/",  # /v1/, /v2/
        r"/api/\d+/",  # /api/1/
        r"version=\d+",  # version=1
    ]
    
    has_versioning = False
    for endpoint in api_endpoints:
        for pattern in version_patterns:
            if re.search(pattern, endpoint, re.IGNORECASE):
                has_versioning = True
                logger.info(f"[API Versioning] Version found in {endpoint}")
                break
        if has_versioning:
            break
    
    if not has_versioning:
        findings.append({"indicator": "no_api_versioning_detected"})
        logger.warning("[API Versioning] No versioning detected in API endpoints")
    
    status = "fail" if findings else "pass"
    return ControlResult("API_Versioning", status, findings)


def run_secure_coding_evidence(documents: List[Dict], logger) -> ControlResult:
    """Control 058: Secure coding practices evidence."""
    findings = []
    
    if not documents:
        return ControlResult("Secure_Coding_Evidence", "not_tested", findings)
    
    # Keywords indicating secure coding practices
    secure_coding_keywords = [
        "secure coding", "code review", "static analysis", "sast", "dast",
        "security testing", "penetration test", "vulnerability scan",
        "owasp", "security guidelines", "coding standards"
    ]
    
    evidence_found = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in secure_coding_keywords:
            if keyword in content:
                evidence_found = True
                logger.info(f"[Secure Coding] Found '{keyword}' in documentation")
                break
        if evidence_found:
            break
    
    if not evidence_found:
        findings.append({"indicator": "no_secure_coding_evidence"})
        logger.warning("[Secure Coding] No secure coding evidence found")
    
    status = "fail" if findings else "pass"
    return ControlResult("Secure_Coding_Evidence", status, findings)


def run_third_party_components(documents: List[Dict], logger) -> ControlResult:
    """Control 059: Third-party component security."""
    findings = []
    
    if not documents:
        return ControlResult("Third_Party_Components", "not_tested", findings)
    
    # Keywords indicating third-party security management
    third_party_keywords = [
        "dependency scan", "sca", "software composition analysis",
        "vulnerability management", "cve", "npm audit", "pip audit",
        "dependency check", "snyk", "dependabot", "renovate"
    ]
    
    evidence_found = False
    for doc in documents:
        content = doc.get("content", "").lower()
        for keyword in third_party_keywords:
            if keyword in content:
                evidence_found = True
                logger.info(f"[Third-Party] Found '{keyword}' in documentation")
                break
        if evidence_found:
            break
    
    if not evidence_found:
        findings.append({"indicator": "no_third_party_security_evidence"})
        logger.warning("[Third-Party] No third-party security management evidence")
    
    status = "fail" if findings else "pass"
    return ControlResult("Third_Party_Components", status, findings)
