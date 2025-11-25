"""
Discovery component for Module 4 - crawls pages and collects content.
"""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class SensitiveDataDiscovery:
    """Crawl target and collect pages for sensitive data analysis."""

    def __init__(self, logger, max_depth: int = 2, max_pages: int = 50):
        self.logger = logger
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.pages = []

    def crawl(self, base_url: str) -> Dict:
        """Crawl the target and collect pages."""
        self.logger.info(f"Starting discovery crawl for {base_url}")
        self._crawl_recursive(base_url, depth=0)
        
        log_files = self._detect_log_files()
        
        self.logger.info(f"Discovery complete: {len(self.pages)} pages, {len(log_files)} log files")
        return {
            "pages": self.pages,
            "log_files": log_files,
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
            session.headers.update({"User-Agent": "Module4-Analyzer"})
            
            response = session.get(url, timeout=10)
            if response.status_code >= 400:
                return
            
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                return
            
            # Store page content
            page_data = {
                "url": url,
                "status_code": response.status_code,
                "content": response.text,
                "headers": dict(response.headers),
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

    def _detect_log_files(self) -> List[Dict]:
        """Detect potential log files from crawled pages."""
        log_files = []
        log_patterns = [r"\.log$", r"/logs?/", r"error", r"access", r"debug"]
        
        for page in self.pages:
            url = page["url"]
            for pattern in log_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    # Try to fetch log content
                    try:
                        session = requests.Session()
                        session.verify = False
                        resp = session.get(url, timeout=5)
                        if resp.status_code == 200:
                            log_files.append({
                                "name": url.split("/")[-1] or "log",
                                "url": url,
                                "content": resp.text[:10000],  # Limit to first 10KB
                            })
                    except:
                        pass
                    break
        
        return log_files
