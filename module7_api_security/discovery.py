"""
Discovery component for Module 7 - API endpoint discovery.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class APIDiscovery:
    """Discover API endpoints from target application."""

    def __init__(self, logger, max_depth: int = 2, max_pages: int = 40):
        self.logger = logger
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.api_endpoints: Set[str] = set()

    def discover(self, base_url: str) -> Dict:
        """Discover API endpoints from target."""
        self.logger.info(f"Starting API endpoint discovery for {base_url}")
        
        # Crawl to find API endpoints
        self._crawl_recursive(base_url, depth=0)
        
        # Add common API paths
        self._check_common_api_paths(base_url)
        
        api_list = list(self.api_endpoints)
        self.logger.info(f"API discovery complete: {len(api_list)} endpoints found")
        
        return {
            "api_endpoints": api_list,
        }

    def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl pages to find API endpoints."""
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        
        if url in self.visited:
            return
        
        self.visited.add(url)
        
        try:
            session = requests.Session()
            session.verify = False
            session.headers.update({"User-Agent": "Module7-Discovery"})
            
            response = session.get(url, timeout=10)
            if response.status_code >= 400:
                return
            
            # Check if this URL is an API endpoint
            if self._is_api_endpoint(url, response):
                self.api_endpoints.add(url)
                self.logger.debug(f"[API Discovery] Found API endpoint: {url}")
            
            # Parse and follow links
            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type:
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Look for API endpoints in JavaScript
                scripts = soup.find_all("script")
                for script in scripts:
                    if script.string:
                        api_urls = self._extract_api_urls_from_js(script.string, url)
                        self.api_endpoints.update(api_urls)
                
                # Follow links
                links = soup.find_all("a", href=True)
                for link in links:
                    href = link["href"]
                    absolute_url = urljoin(url, href)
                    
                    if self._is_same_domain(url, absolute_url):
                        self._crawl_recursive(absolute_url, depth + 1)
                        
        except requests.RequestException as e:
            self.logger.debug(f"Request failed for {url}: {e}")
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {e}")

    def _is_api_endpoint(self, url: str, response: requests.Response) -> bool:
        """Check if URL is an API endpoint."""
        # Check URL patterns
        api_patterns = [
            r"/api/",
            r"/v\d+/",
            r"/rest/",
            r"/graphql",
            r"/swagger",
            r"/openapi",
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        # Check response content type
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type or "application/xml" in content_type:
            return True
        
        return False

    def _extract_api_urls_from_js(self, js_content: str, base_url: str) -> Set[str]:
        """Extract API URLs from JavaScript code."""
        api_urls = set()
        
        # Look for API URL patterns in JavaScript
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match.startswith("/"):
                    api_url = urljoin(base_url, match)
                    if self._is_same_domain(base_url, api_url):
                        api_urls.add(api_url)
        
        return api_urls

    def _check_common_api_paths(self, base_url: str):
        """Check common API paths."""
        common_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/rest",
            "/graphql",
            "/api/users",
            "/api/auth",
            "/api/login",
        ]
        
        session = requests.Session()
        session.verify = False
        
        for path in common_paths:
            try:
                url = urljoin(base_url, path)
                resp = session.get(url, timeout=5)
                
                if resp.status_code < 400:
                    self.api_endpoints.add(url)
                    self.logger.debug(f"[API Discovery] Found common API path: {url}")
            except:
                pass

    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain."""
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2
