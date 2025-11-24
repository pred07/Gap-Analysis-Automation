"""
Recursive directory and endpoint discovery for Module 1.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

DEFAULT_WORDLIST = [
    "admin",
    "api",
    "backup",
    "config",
    "login",
    "portal",
    "robots.txt",
    "sitemap.xml",
    "static",
    "uploads",
]

SENSITIVE_PATTERNS = [
    re.compile(r"\.env", re.I),
    re.compile(r"\.git", re.I),
    re.compile(r"backup", re.I),
    re.compile(r"db\.sql", re.I),
    re.compile(r"config", re.I),
]


class DirectoryScanner:
    def __init__(
        self,
        logger,
        max_depth: int = 2,
        max_endpoints: int = 50,
        wordlist_enabled: bool = True,
    ):
        self.logger = logger
        self.max_depth = max_depth
        self.max_endpoints = max_endpoints
        self.wordlist_enabled = wordlist_enabled
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Module1-Discovery"})

    # ------------------------------------------------------------------ #
    def scan(self, base_url: str) -> Dict:
        queue = deque([(base_url, 0)])
        visited: Set[str] = set()
        endpoints: List[Dict] = []
        sensitive_files: List[Dict] = []
        classifications = {
            "html": 0,
            "upload": 0,
            "json": 0,
            "xml": 0,
            "param": 0,
            "api": 0,
        }

        while queue and len(endpoints) < self.max_endpoints:
            current_url, depth = queue.popleft()
            if current_url in visited or depth > self.max_depth:
                continue
            visited.add(current_url)

            try:
                response = self.session.get(current_url, timeout=10)
            except requests.RequestException:
                continue

            entry = self._build_endpoint_entry(current_url, depth, response)
            endpoints.append(entry)

            if entry["sensitive"]:
                sensitive_files.append(entry)

            if "text/html" in entry["content_type"]:
                self._enqueue_links(queue, visited, response.text, current_url, base_url, depth + 1)
                form_endpoints = self._extract_forms(response.text, current_url, depth)
                for form_entry in form_endpoints:
                    endpoints.append(form_entry)
                    if form_entry["sensitive"]:
                        sensitive_files.append(form_entry)

            self._update_classifications(classifications, entry)
            if len(endpoints) >= self.max_endpoints:
                break

        if self.wordlist_enabled and len(endpoints) < self.max_endpoints:
            self._smart_wordlist_scan(base_url, visited, endpoints, sensitive_files, classifications)

        return {
            "base_url": base_url,
            "endpoints": endpoints[: self.max_endpoints],
            "sensitive_files": sensitive_files,
            "classifications": classifications,
        }

    # ------------------------------------------------------------------ #
    def _build_endpoint_entry(self, url: str, depth: int, response: requests.Response) -> Dict:
        content_type = response.headers.get("Content-Type", "")
        query_params = list(parse_qs(urlparse(url).query).keys())
        tags = set()
        if query_params:
            tags.add("param")
        if "application/json" in content_type or "/json" in content_type or "/api/" in urlparse(url).path:
            tags.add("json")
        if "xml" in content_type or urlparse(url).path.endswith(".xml"):
            tags.add("xml")
        if "/api/" in urlparse(url).path:
            tags.add("api")
        snippet = ""
        if "text/html" in content_type or content_type == "":
            tags.add("html")
            snippet = response.text[:200]

        sensitive = any(pattern.search(url) for pattern in SENSITIVE_PATTERNS)

        return {
            "url": url,
            "method": "GET",
            "depth": depth,
            "status": response.status_code,
            "content_type": content_type,
            "params": query_params,
            "tags": sorted(tags),
            "has_file_input": False,
            "form": None,
            "sensitive": sensitive,
            "snippet": snippet,
        }

    def _enqueue_links(self, queue, visited, html: str, current: str, base: str, next_depth: int) -> None:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "link"], href=True):
            href = tag.get("href")
            if not href:
                continue
            url = urljoin(current, href)
            if self._same_host(url, base) and url not in visited:
                queue.append((url, next_depth))
        for tag in soup.find_all("form", action=True):
            action = tag.get("action")
            if not action:
                continue
            url = urljoin(current, action)
            if self._same_host(url, base) and url not in visited:
                queue.append((url, next_depth))
        for tag in soup.find_all(["script", "img"], src=True):
            src = tag.get("src")
            if not src:
                continue
            url = urljoin(current, src)
            if self._same_host(url, base) and url not in visited:
                queue.append((url, next_depth))

    def _extract_forms(self, html: str, current: str, depth: int) -> List[Dict]:
        soup = BeautifulSoup(html, "html.parser")
        endpoints: List[Dict] = []
        for form in soup.find_all("form"):
            action = form.get("action") or current
            method = (form.get("method") or "GET").upper()
            target_url = urljoin(current, action)
            inputs = []
            has_file = False
            params = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                input_type = (input_tag.get("type") or "text").lower()
                required = input_tag.has_attr("required")
                if input_type == "file":
                    has_file = True
                if name:
                    params.append(name)
                inputs.append({"name": name, "type": input_type, "required": required})
            entry = {
                "url": target_url,
                "method": method,
                "depth": depth,
                "status": 200,
                "content_type": "",
                "params": params,
                "tags": ["html", "param"] if params else ["html"],
                "has_file_input": has_file,
                "form": {"inputs": inputs},
                "sensitive": any(pattern.search(target_url) for pattern in SENSITIVE_PATTERNS),
            }
            endpoints.append(entry)
        return endpoints

    def _smart_wordlist_scan(self, base_url: str, visited: Set[str], endpoints: List[Dict], sensitive_files: List[Dict], classifications: Dict[str, int]) -> None:
        for word in DEFAULT_WORDLIST:
            candidate = urljoin(base_url.rstrip("/") + "/", word)
            if candidate in visited:
                continue
            try:
                response = self.session.head(candidate, timeout=5, allow_redirects=True)
            except requests.RequestException:
                continue
            if response.status_code < 400:
                entry = {
                    "url": candidate,
                    "method": "HEAD",
                    "depth": 1,
                    "status": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "params": [],
                    "tags": [],
                    "has_file_input": False,
                    "form": None,
                    "sensitive": any(pattern.search(candidate) for pattern in SENSITIVE_PATTERNS),
                }
                endpoints.append(entry)
                self._update_classifications(classifications, entry)
                if entry["sensitive"]:
                    sensitive_files.append(entry)
            if len(endpoints) >= self.max_endpoints:
                break

    def _update_classifications(self, classifications: Dict[str, int], entry: Dict) -> None:
        for tag in entry["tags"]:
            if tag in classifications:
                classifications[tag] += 1
        if entry.get("has_file_input"):
            classifications["upload"] += 1

    def _same_host(self, url: str, base: str) -> bool:
        return urlparse(url).netloc == urlparse(base).netloc

    def _same_host(self, url: str, base: str) -> bool:
        return urlparse(url).netloc == urlparse(base).netloc


