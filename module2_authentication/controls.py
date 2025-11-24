"""
Control implementations for Module 2 authentication checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests


@dataclass
class ControlResult:
    name: str
    status: str
    findings: List[Dict]


def run_password_policy(forms: List[Dict]) -> ControlResult:
    findings = []
    for form in forms:
        if "login" not in form["category"] and "password_change" not in form["category"]:
            continue
        hints = []
        for field in form["inputs"]:
            placeholder = (field.get("placeholder") or "").lower()
            label = (field.get("label") or "").lower()
            if any(word in (placeholder + label) for word in ["min", "length", "uppercase", "special"]):
                hints.append({"field": field["name"], "hint": placeholder or label})
        if not hints:
            findings.append({"control": "Password_Policy", "url": form["url"], "issue": "no_policy_hint"})
    status = "fail" if findings else ("not_tested" if not forms else "pass")
    return ControlResult("Password_Policy", status, findings)


def run_login_error_messages(login_forms: List[Dict], session: requests.Session, creds: Dict, logger) -> ControlResult:
    findings = []
    if not login_forms:
        return ControlResult("Login_Error_Messages", "not_tested", findings)

    username = creds.get("username") or "testuser"
    wrong_password = "badpassword123!"
    for form in login_forms[:3]:
        payload = build_form_payload(form, username, wrong_password)
        resp = submit_form(session, form, payload)
        if resp is None:
            continue
        text = resp.text.lower()
        if "user does not exist" in text or "invalid username" in text:
            findings.append({"url": form["url"], "indicator": "verbose_username_error"})
            logger.warning(f"[LoginError] Verbose username error at {form['url']}")
            break
    status = "fail" if findings else "pass"
    return ControlResult("Login_Error_Messages", status, findings)


def run_last_login_message(session: requests.Session, success_context: Dict, logger) -> ControlResult:
    findings = []
    resp = success_context.get("response")
    if resp is None:
        return ControlResult("Last_Login_Message", "not_tested", findings)
    if "last login" in resp.text.lower() or "last sign-in" in resp.text.lower():
        status = "pass"
    else:
        status = "fail"
        findings.append({"url": success_context["url"], "indicator": "missing_last_login_message"})
    return ControlResult("Last_Login_Message", status, findings)


def run_password_encryption_transit(login_forms: List[Dict]) -> ControlResult:
    findings = []
    for form in login_forms:
        if not form["url"].startswith("https://"):
            findings.append({"url": form["url"], "issue": "login_form_not_https"})
    status = "fail" if findings else ("not_tested" if not login_forms else "pass")
    return ControlResult("Password_Encryption_Transit", status, findings)


def run_password_change_process(change_forms: List[Dict], session: requests.Session, creds: Dict, logger) -> ControlResult:
    findings = []
    if not change_forms:
        return ControlResult("Password_Change_Process", "not_tested", findings)

    for form in change_forms[:2]:
        payload = {}
        for field in form["inputs"]:
            name = field["name"]
            if not name:
                continue
            if "current" in (field["label"] or "").lower():
                payload[name] = creds.get("password", "WrongPass123!")
            elif "confirm" in (field["label"] or "").lower():
                payload[name] = "short"
            else:
                payload[name] = "short"
        resp = submit_form(session, form, payload)
        if resp is None:
            continue
        if resp.status_code < 400 and "error" not in resp.text.lower():
            findings.append({"url": form["url"], "indicator": "weak_password_accepted"})
            logger.warning(f"[PasswordChange] Weak password accepted at {form['url']}")
            break
    status = "fail" if findings else "pass"
    return ControlResult("Password_Change_Process", status, findings)


def run_mfa_detection(pages: List[Dict]) -> ControlResult:
    findings = []
    for page in pages:
        if page["mfa_signals"]:
            findings.append({"url": page["url"], "signals": page["mfa_signals"]})
    status = "pass" if findings else "fail"
    return ControlResult("Multi_Factor_Authentication", status, findings)


def run_api_authentication(pages: List[Dict], session: requests.Session, creds: Dict, logger) -> ControlResult:
    api_pages = [p for p in pages if p.get("api_candidate")]
    if not api_pages:
        return ControlResult("API_Authentication", "not_tested", [])

    findings = []
    for page in api_pages[:3]:
        url = page["url"]
        resp_no_token = session.get(url, timeout=10)
        token = creds.get("api_key") or creds.get("bearer_token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        resp_with_token = session.get(url, headers=headers, timeout=10)
        if resp_no_token.status_code < 400:
            findings.append({"url": url, "indicator": "endpoint_accessible_without_token"})
            logger.warning(f"[APIAuth] {url} accessible without auth")
            break
        if token and resp_with_token.status_code >= 400:
            findings.append({"url": url, "indicator": "token_not_accepted"})
            break
    status = "fail" if findings else "pass"
    return ControlResult("API_Authentication", status, findings)


# --------------------------------------------------------------------------- #
# Helpers


def build_form_payload(form: Dict, username: str, password: str) -> Dict:
    payload = {}
    for field in form["inputs"]:
        name = field.get("name")
        if not name:
            continue
        input_type = field.get("type", "text")
        if input_type == "password":
            payload[name] = password
        elif input_type in ("text", "email", "username"):
            payload[name] = username
        else:
            payload[name] = "test"
    return payload


def submit_form(session: requests.Session, form: Dict, payload: Dict) -> Optional[requests.Response]:
    url = form["url"]
    method = form.get("method", "GET").upper()
    try:
        if method == "GET":
            return session.get(url, params=payload, timeout=10)
        return session.post(url, data=payload, timeout=10)
    except requests.RequestException:
        return None

