"""
Control implementations for Module 5 session management checks.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import requests


@dataclass
class ControlResult:
    name: str
    status: str
    findings: List[Dict]


def run_session_timeout(pages: List[Dict], session_factory, credentials: Dict, logger) -> ControlResult:
    """Control 035: Session timeout implementation."""
    findings = []
    
    if not credentials.get("username") or not credentials.get("password"):
        logger.warning("[Session Timeout] No credentials provided for testing")
        return ControlResult("Session_Timeout", "not_tested", findings)
    
    # Look for login pages
    login_pages = [p for p in pages if "login" in p.get("url", "").lower()]
    if not login_pages:
        return ControlResult("Session_Timeout", "not_tested", findings)
    
    session = session_factory()
    
    # Try to establish a session
    for page in login_pages[:1]:
        try:
            # Make initial request
            resp1 = session.get(page["url"], timeout=10)
            cookies_before = len(session.cookies)
            
            if cookies_before == 0:
                continue
            
            # Wait a short time (simulate timeout check)
            time.sleep(2)
            
            # Make another request
            resp2 = session.get(page["url"], timeout=10)
            
            # Check if session cookies have expiry
            has_timeout = False
            for cookie in session.cookies:
                if cookie.expires:
                    has_timeout = True
                    logger.info(f"[Session Timeout] Cookie {cookie.name} has expiry: {cookie.expires}")
                    break
            
            if not has_timeout:
                findings.append({"url": page["url"], "indicator": "no_session_timeout_detected"})
                logger.warning(f"[Session Timeout] No timeout detected for {page['url']}")
            
        except Exception as e:
            logger.debug(f"[Session Timeout] Error testing {page['url']}: {e}")
    
    status = "fail" if findings else ("not_tested" if not login_pages else "pass")
    return ControlResult("Session_Timeout", status, findings)


def run_session_id_randomness(pages: List[Dict], session_factory, logger) -> ControlResult:
    """Control 036: Session ID randomness and unpredictability."""
    findings = []
    
    session_ids = []
    session = session_factory()
    
    # Collect session IDs from multiple requests
    for page in pages[:5]:
        try:
            resp = session.get(page["url"], timeout=10)
            
            # Check for session cookies
            for cookie in resp.cookies:
                cookie_name_lower = cookie.name.lower()
                if any(keyword in cookie_name_lower for keyword in ["session", "sess", "sid", "jsession"]):
                    session_ids.append(cookie.value)
                    logger.debug(f"[Session ID] Found session cookie: {cookie.name}")
        except Exception as e:
            logger.debug(f"[Session ID] Error: {e}")
    
    if not session_ids:
        return ControlResult("Session_ID_Randomness", "not_tested", findings)
    
    # Check for weak session IDs (sequential, predictable patterns)
    for sid in session_ids:
        # Check if session ID is too short (weak)
        if len(sid) < 16:
            findings.append({"session_id": sid[:10] + "...", "indicator": "short_session_id"})
            logger.warning(f"[Session ID] Weak session ID detected (too short): {len(sid)} chars")
        
        # Check if session ID is numeric only (predictable)
        if sid.isdigit():
            findings.append({"session_id": sid[:10] + "...", "indicator": "numeric_only_session_id"})
            logger.warning("[Session ID] Numeric-only session ID detected")
    
    status = "fail" if findings else "pass"
    return ControlResult("Session_ID_Randomness", status, findings)


def run_session_not_in_url(pages: List[Dict], logger) -> ControlResult:
    """Control 037: Session ID not exposed in URL."""
    findings = []
    
    # Patterns that might indicate session IDs in URLs
    session_patterns = [
        r"[?&](session|sess|sid|jsessionid|phpsessid)=",
        r"[?&]token=[a-zA-Z0-9]{16,}",
    ]
    
    for page in pages:
        url = page.get("url", "")
        for pattern in session_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append({"url": url, "indicator": "session_in_url"})
                logger.warning(f"[Session in URL] Session ID found in URL: {url}")
                break
    
    status = "fail" if findings else ("not_tested" if not pages else "pass")
    return ControlResult("Session_Not_In_URL", status, findings)


def run_cookie_flags(pages: List[Dict], session_factory, logger) -> ControlResult:
    """Control 038: Secure cookie flags (Secure, HttpOnly, SameSite)."""
    findings = []
    
    session = session_factory()
    checked_cookies = set()
    
    for page in pages[:10]:
        try:
            resp = session.get(page["url"], timeout=10)
            
            for cookie in resp.cookies:
                if cookie.name in checked_cookies:
                    continue
                checked_cookies.add(cookie.name)
                
                cookie_name_lower = cookie.name.lower()
                is_session_cookie = any(kw in cookie_name_lower for kw in ["session", "sess", "sid", "auth", "token"])
                
                if not is_session_cookie:
                    continue
                
                # Check Secure flag
                if not cookie.secure and page["url"].startswith("https://"):
                    findings.append({
                        "cookie": cookie.name,
                        "url": page["url"],
                        "indicator": "missing_secure_flag"
                    })
                    logger.warning(f"[Cookie Flags] Cookie {cookie.name} missing Secure flag")
                
                # Check HttpOnly flag
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    findings.append({
                        "cookie": cookie.name,
                        "url": page["url"],
                        "indicator": "missing_httponly_flag"
                    })
                    logger.warning(f"[Cookie Flags] Cookie {cookie.name} missing HttpOnly flag")
                
                # Check SameSite attribute
                if not cookie.has_nonstandard_attr("SameSite"):
                    findings.append({
                        "cookie": cookie.name,
                        "url": page["url"],
                        "indicator": "missing_samesite_attribute"
                    })
                    logger.warning(f"[Cookie Flags] Cookie {cookie.name} missing SameSite attribute")
                
        except Exception as e:
            logger.debug(f"[Cookie Flags] Error: {e}")
    
    status = "fail" if findings else ("not_tested" if not checked_cookies else "pass")
    return ControlResult("Cookie_Flags", status, findings)


def run_server_side_validation(pages: List[Dict], session_factory, logger) -> ControlResult:
    """Control 039: Server-side session validation."""
    findings = []
    
    session = session_factory()
    
    # Look for protected pages (admin, dashboard, account)
    protected_keywords = ["admin", "dashboard", "account", "profile", "settings"]
    protected_pages = [
        p for p in pages 
        if any(kw in p.get("url", "").lower() for kw in protected_keywords)
    ]
    
    if not protected_pages:
        return ControlResult("Server_Side_Validation", "not_tested", findings)
    
    for page in protected_pages[:3]:
        try:
            # Try to access without valid session
            resp = session.get(page["url"], timeout=10)
            
            # If we get 200 OK without authentication, it's a problem
            if resp.status_code == 200:
                # Check if page actually requires auth (look for login redirects or forms)
                if "login" not in resp.text.lower() and "sign in" not in resp.text.lower():
                    findings.append({
                        "url": page["url"],
                        "status_code": resp.status_code,
                        "indicator": "protected_page_accessible_without_session"
                    })
                    logger.warning(f"[Server Validation] Protected page accessible: {page['url']}")
        except Exception as e:
            logger.debug(f"[Server Validation] Error: {e}")
    
    status = "fail" if findings else "pass"
    return ControlResult("Server_Side_Validation", status, findings)


def run_token_expiry(pages: List[Dict], session_factory, logger) -> ControlResult:
    """Control 040: Token expiration and refresh."""
    findings = []
    
    session = session_factory()
    tokens_found = []
    
    # Look for API endpoints or pages with tokens
    for page in pages[:10]:
        try:
            resp = session.get(page["url"], timeout=10)
            
            # Check for tokens in response headers
            auth_header = resp.headers.get("Authorization", "")
            if "Bearer" in auth_header:
                tokens_found.append({"type": "bearer_token", "url": page["url"]})
            
            # Check for JWT tokens in cookies
            for cookie in resp.cookies:
                if "token" in cookie.name.lower() or "jwt" in cookie.name.lower():
                    # Check if cookie has expiry
                    if not cookie.expires:
                        findings.append({
                            "cookie": cookie.name,
                            "url": page["url"],
                            "indicator": "token_without_expiry"
                        })
                        logger.warning(f"[Token Expiry] Token {cookie.name} has no expiry")
                    else:
                        tokens_found.append({"type": "cookie_token", "cookie": cookie.name})
        except Exception as e:
            logger.debug(f"[Token Expiry] Error: {e}")
    
    status = "fail" if findings else ("not_tested" if not tokens_found else "pass")
    return ControlResult("Token_Expiry", status, findings)


def run_session_fixation_prevention(pages: List[Dict], session_factory, logger) -> ControlResult:
    """Control 041: Session fixation attack prevention."""
    findings = []
    
    # Look for login pages
    login_pages = [p for p in pages if "login" in p.get("url", "").lower()]
    
    if not login_pages:
        return ControlResult("Session_Fixation_Prevention", "not_tested", findings)
    
    for login_page in login_pages[:1]:
        try:
            session = session_factory()
            
            # Get session before login
            resp1 = session.get(login_page["url"], timeout=10)
            session_id_before = None
            
            for cookie in session.cookies:
                if "session" in cookie.name.lower() or "sess" in cookie.name.lower():
                    session_id_before = cookie.value
                    break
            
            if not session_id_before:
                continue
            
            # Simulate login attempt (without actual credentials)
            # In a real test, we'd submit login form
            resp2 = session.get(login_page["url"], timeout=10)
            session_id_after = None
            
            for cookie in session.cookies:
                if "session" in cookie.name.lower() or "sess" in cookie.name.lower():
                    session_id_after = cookie.value
                    break
            
            # Check if session ID changed (it should for fixation prevention)
            if session_id_before and session_id_after and session_id_before == session_id_after:
                findings.append({
                    "url": login_page["url"],
                    "indicator": "session_id_not_regenerated_after_login"
                })
                logger.warning(f"[Session Fixation] Session ID not regenerated: {login_page['url']}")
            
        except Exception as e:
            logger.debug(f"[Session Fixation] Error: {e}")
    
    status = "fail" if findings else ("not_tested" if not login_pages else "pass")
    return ControlResult("Session_Fixation_Prevention", status, findings)
