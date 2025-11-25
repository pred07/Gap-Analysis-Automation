"""
Discovery component for Module 5 - session-focused page crawling.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class SessionDiscovery:
    """Crawl target and collect pages for session analysis."""

    def __init__(self, logger, max_depth: int = 2, max_pages: int = 40):
        self.logger = logger
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.pages = []

    def crawl(self, base_url: str) -> Dict:
        """Crawl the target and collect pages."""
        self.logger.info(f"Starting session discovery crawl for {base_url}")
        self._crawl_recursive(base_url, depth=0)
        
        # Identify login pages
        login_pages = [
            p for p in self.pages
            if "login" in p.get("url", "").lower() or "signin" in p.get("url", "").lower()
        ]
        
        self.logger.info(f"Discovery complete: {len(self.pages)} pages, {len(login_pages)} login pages")
        return {
            "pages": self.pages,
            "login_pages": login_pages,
        }

    def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl pages."""
        if depth > self.max_depth or len(self.pages) >= self.max_pages:
            return
        
        if url in self.visited:
            return
        
        self.visited.add(url)
        
        try:
            session = requests.Session()
            session.verify = False
            session.headers.update({"User-Agent": "Module5-Discovery"})
            
            response = session.get(url, timeout=10)
            if response.status_code >= 400:
                return
            
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                return
            
            # Store page data
            page_data = {
                "url": url,
                "status_code": response.status_code,
                "content": response.text,
                "headers": dict(response.headers),
                "cookies": [
                    {
                        "name": cookie.name,
                        "value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
                        "secure": cookie.secure,
                        "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                        "samesite": cookie.get_nonstandard_attr("SameSite", ""),
                    }
                    for cookie in response.cookies
                ],
            }
            self.pages.append(page_data)
            
            # Parse and follow links
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all("a", href=True)
            
            for link in links:
                href = link["href"]
                absolute_url = urljoin(url, href)
                
                # Only follow same-domain links
                if self._is_same_domain(url, absolute_url):
                    self._crawl_recursive(absolute_url, depth + 1)
                    
        except requests.RequestException as e:
            self.logger.debug(f"Request failed for {url}: {e}")
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {e}")

    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain."""
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2
