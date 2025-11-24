"""
Authorization-focused discovery utilities.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

ADMIN_HINTS = ["admin", "dashboard", "manage", "internal"]
API_HINTS = ["/api/", "/v1/", "/v2/", ".json"]
TRAVERSAL_STRINGS = ["../", "..\\", "%2e%2e%2f"]


class AuthzDiscovery:
    def __init__(self, logger, max_depth: int = 2, max_pages: int = 60):
        self.logger = logger
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Module3-Discovery"})

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

        protected_pages = [
            page for page in pages if page["admin_hint"] or page["requires_auth"]
        ]
        api_endpoints = [page["url"] for page in pages if page["api_candidate"]]

        return {
            "base_url": base_url,
            "pages": pages,
            "protected_pages": protected_pages,
            "api_endpoints": api_endpoints,
        }

    def _capture_page(self, url: str, response: requests.Response) -> Dict:
        content_type = response.headers.get("Content-Type", "")
        html = response.text if "text/html" in content_type else ""
        admin_hint = any(keyword in url.lower() for keyword in ADMIN_HINTS)
        requires_auth = response.status_code in (401, 403)
        api_candidate = any(keyword in url.lower() for keyword in API_HINTS)

        traversal_sensitive = any(pattern in url.lower() for pattern in TRAVERSAL_STRINGS)

        forms = []
        if html:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                forms.append(
                    {
                        "url": urljoin(url, form.get("action") or url),
                        "method": (form.get("method") or "GET").upper(),
                        "inputs": [field.get("name") for field in form.find_all("input")],
                    }
                )
            if not api_candidate:
                api_candidate = any(hint in html.lower() for hint in ["api key", "bearer "])

        return {
            "url": url,
            "status": response.status_code,
            "content_type": content_type,
            "forms": forms,
            "admin_hint": admin_hint,
            "requires_auth": requires_auth,
            "api_candidate": api_candidate,
            "traversal_sensitive": traversal_sensitive,
        }

    def _extract_links(self, html: str, current: str, base: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all(["a", "link"], href=True):
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
        for tag in soup.find_all(["script"], src=True):
            src = tag.get("src")
            if not src:
                continue
            url = urljoin(current, src)
            if self._same_host(url, base):
                links.append(url.split("#")[0])
        return links

    def _same_host(self, url: str, base: str) -> bool:
        return urlparse(url).netloc == urlparse(base).netloc

