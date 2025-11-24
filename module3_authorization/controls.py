"""
Control implementations for Module 3 authorization checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import requests


@dataclass
class ControlResult:
    name: str
    status: str
    findings: List[Dict]


def run_rbac(pages: List[Dict], session_factory, logger) -> ControlResult:
    findings = []
    session = session_factory()
    for page in pages:
        if not page["admin_hint"]:
            continue
        resp = session.get(page["url"], timeout=10)
        if resp.status_code < 400:
            findings.append({"url": page["url"], "indicator": "admin_page_accessible_without_auth"})
            logger.warning(f"[RBAC] {page['url']} accessible without auth")
            break
    status = "fail" if findings else ("not_tested" if not any(p["admin_hint"] for p in pages) else "pass")
    return ControlResult("Role_Based_Access_Control", status, findings)


def run_user_state_management(protected_pages: List[Dict], session_factory, logger) -> ControlResult:
    findings = []
    if not protected_pages:
        return ControlResult("User_State_Management", "not_tested", findings)

    session = session_factory()
    for page in protected_pages[:3]:
        resp = session.get(page["url"], timeout=10)
        if resp.status_code in (200, 302):
            findings.append({"url": page["url"], "indicator": "sessionless_access"})
            logger.warning(f"[State] {page['url']} accessible without session")
            break
    status = "fail" if findings else "pass"
    return ControlResult("User_State_Management", status, findings)


def run_database_permission_controls(pages: List[Dict], session_factory, logger) -> ControlResult:
    findings = []
    candidates = [page for page in pages if _has_numeric_id(page["url"])]
    session = session_factory()
    for page in candidates[:5]:
        mutated = _increment_id(page["url"])
        resp = session.get(mutated, timeout=10)
        if resp.status_code < 400:
            findings.append({"url": mutated, "indicator": "idor_possible"})
            logger.warning(f"[IDOR] {mutated} accessible sequentially")
            break
    status = "fail" if findings else ("not_tested" if not candidates else "pass")
    return ControlResult("Database_Permission_Controls", status, findings)


def run_os_access_restrictions(pages: List[Dict], session_factory, logger) -> ControlResult:
    findings = []
    session = session_factory()
    for page in pages:
        if "../" in page["url"]:
            findings.append({"url": page["url"], "indicator": "directory_traversal_in_url"})
            break
    if not findings:
        sensitive_paths = ["/etc/passwd", "/var/log", "/admin", "/config"]
        base = pages[0]["url"] if pages else ""
        parsed = urlparse(base)
        for path in sensitive_paths:
            target = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
            resp = session.get(target, timeout=5)
            if resp.status_code < 400:
                findings.append({"url": target, "indicator": "restricted_file_accessible"})
                logger.warning(f"[OS Access] {target} accessible")
                break
    status = "fail" if findings else ("not_tested" if not pages else "pass")
    return ControlResult("OS_Level_Access_Restrictions", status, findings)


def run_api_authorization(api_endpoints: List[str], session_factory, creds: Dict, logger) -> ControlResult:
    findings = []
    if not api_endpoints:
        return ControlResult("API_Authorization", "not_tested", findings)

    session = session_factory()
    token = creds.get("api_key") or creds.get("bearer_token")
    for endpoint in api_endpoints[:5]:
        no_token_resp = session.get(endpoint, timeout=10)
        if no_token_resp.status_code < 400:
            findings.append({"url": endpoint, "indicator": "api_accessible_without_token"})
            logger.warning(f"[API Auth] {endpoint} accessible without token")
            break
        if token:
            headers = {"Authorization": f"Bearer {token}"}
            with_token = session.get(endpoint, headers=headers, timeout=10)
            if with_token.status_code >= 400:
                findings.append({"url": endpoint, "indicator": "valid_token_rejected"})
                break
    status = "fail" if findings else "pass"
    return ControlResult("API_Authorization", status, findings)


# --------------------------------------------------------------------------- #
# Helpers


def _has_numeric_id(url: str) -> bool:
    import re

    return bool(re.search(r"\d+", url))


def _increment_id(url: str) -> str:
    import re

    match = re.search(r"(\d+)", url)
    if not match:
        return url
    start, end = match.span()
    original = match.group(0)
    incremented = str(int(original) + 1)
    return url[:start] + incremented + url[end:]

