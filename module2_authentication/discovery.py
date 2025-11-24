"""
Authentication-specific discovery utilities.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

LOGIN_KEYWORDS = ["login", "signin", "auth"]
PASSWORD_CHANGE_KEYWORDS = ["password", "change", "reset"]
MFA_KEYWORDS = ["otp", "token", "mfa", "2fa", "one-time"]
API_HINTS = ["/api/", "/auth", "/token"]


class AuthDiscovery:
    def __init__(self, logger, max_depth: int = 2, max_pages: int = 40):
        self.logger = logger
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Module2-Discovery"})

    def crawl(self, base_url: str) -> Dict:
        queue = deque([(base_url, 0)])
        visited: Set[str] = set()
        pages: List[Dict] = []

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)

            try:
                resp = self.session.get(url, timeout=10)
            except requests.RequestException:
                continue

            entry = self._capture_page(url, resp)
            pages.append(entry)

            if "text/html" in resp.headers.get("Content-Type", ""):
                for link in self._extract_links(resp.text, url, base_url):
                    if link not in visited:
                        queue.append((link, depth + 1))

        return {"base_url": base_url, "pages": pages}

    def _capture_page(self, url: str, response: requests.Response) -> Dict:
        forms = []
        mfa_signals = []
        api_candidate = any(keyword in url for keyword in API_HINTS)

        content_type = response.headers.get("Content-Type", "")
        html = response.text if "text/html" in content_type else ""
        if html:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                form_meta = self._parse_form(url, form)
                forms.append(form_meta)
                if form_meta["category"] == "login":
                    mfa_signals.extend(self._scan_for_keywords(form, MFA_KEYWORDS))
            if not api_candidate:
                api_candidate = any(keyword in html.lower() for keyword in ["api token", "bearer "])

        return {
            "url": url,
            "status": response.status_code,
            "content_type": content_type,
            "forms": forms,
            "mfa_signals": mfa_signals,
            "api_candidate": api_candidate,
        }

    def _parse_form(self, current_url: str, form) -> Dict:
        action = form.get("action") or current_url
        method = (form.get("method") or "GET").upper()
        target = urljoin(current_url, action)
        inputs = []
        has_password = False
        has_confirm = False
        categories = set()

        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            input_type = (field.get("type") or "text").lower()
            required = field.has_attr("required")
            placeholder = field.get("placeholder", "")
            label = field.parent.string if field.parent else ""

            inputs.append(
                {
                    "name": name,
                    "type": input_type,
                    "required": required,
                    "placeholder": placeholder,
                    "label": label,
                }
            )
            if input_type == "password":
                if has_password:
                    has_confirm = True
                has_password = True

        if any(keyword in target.lower() for keyword in LOGIN_KEYWORDS) or has_password:
            categories.add("login")
        if any(keyword in target.lower() for keyword in PASSWORD_CHANGE_KEYWORDS) or has_confirm:
            categories.add("password_change")
        if any(keyword in target.lower() for keyword in MFA_KEYWORDS):
            categories.add("mfa")

        return {
            "url": target,
            "method": method,
            "inputs": inputs,
            "category": ",".join(sorted(categories)) if categories else "general",
        }

    def _extract_links(self, html: str, current: str, base: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all(["a", "form"], href=True):
            href = tag.get("href")
            if not href:
                continue
            url = urljoin(current, href)
            if self._same_host(url, base):
                links.append(url.split("#")[0])
        for tag in soup.find_all("form", action=True):
            action = tag.get("action")
            if not action:
                continue
            url = urljoin(current, action)
            if self._same_host(url, base):
                links.append(url.split("#")[0])
        return links

    def _scan_for_keywords(self, element, keywords: List[str]) -> List[str]:
        text = element.get_text(" ").lower()
        return [kw for kw in keywords if kw in text]

    def _same_host(self, url: str, base: str) -> bool:
        return urlparse(url).netloc == urlparse(base).netloc

