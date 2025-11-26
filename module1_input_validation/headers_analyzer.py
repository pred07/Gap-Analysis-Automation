"""
HTTP security headers analyzer.
"""

from __future__ import annotations

from typing import Dict, List

import requests

REQUIRED_HEADERS = {
    "Content-Security-Policy": "Medium",  # Medium unless XSS is present
    "X-Content-Type-Options": "Medium",
    "X-Frame-Options": "Medium",
    "Strict-Transport-Security": "High",  # High for HTTPS sites
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low",
    "X-XSS-Protection": "Low",  # Deprecated, browsers ignore it
}


class HeadersAnalyzer:
    def __init__(self, logger):
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Module1-Headers"})

    def analyze(self, url: str) -> Dict:
        try:
            response = self.session.get(url, timeout=10)
            headers = {k: v for k, v in response.headers.items()}
        except requests.RequestException as exc:
            self.logger.warning(f"Header analysis failed for {url}: {exc}")
            headers = {}

        missing: List[Dict] = []
        for header, severity in REQUIRED_HEADERS.items():
            if header not in headers:
                missing.append({"header": header, "severity": severity})

        return {
            "url": url,
            "status": "ok" if not missing else "missing_headers",
            "headers": headers,
            "missing_headers": missing,
        }


