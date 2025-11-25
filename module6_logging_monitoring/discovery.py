"""
Discovery component for Module 6 - log file discovery from target.
"""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import requests


class LogDiscovery:
    """Discover log files from target application."""

    def __init__(self, logger):
        self.logger = logger

    def discover(self, base_url: str) -> Dict:
        """Attempt to discover log files from target."""
        self.logger.info(f"Attempting log file discovery for {base_url}")
        
        log_files = []
        
        # Common log file paths to check
        common_log_paths = [
            "/logs/",
            "/log/",
            "/var/log/",
            "/admin/logs/",
            "/debug/logs/",
            "/logs/access.log",
            "/logs/error.log",
            "/logs/application.log",
            "/logs/security.log",
            "/log/app.log",
        ]
        
        session = requests.Session()
        session.verify = False
        session.headers.update({"User-Agent": "Module6-Discovery"})
        
        for log_path in common_log_paths:
            try:
                url = urljoin(base_url, log_path)
                resp = session.get(url, timeout=5)
                
                if resp.status_code == 200:
                    # Check if response looks like a log file
                    if self._looks_like_log(resp.text):
                        log_files.append({
                            "name": log_path.split("/")[-1] or "log",
                            "url": url,
                            "content": resp.text[:10000],  # First 10KB
                        })
                        self.logger.info(f"[Log Discovery] Found log file: {url}")
            except requests.RequestException:
                pass
        
        self.logger.info(f"Log discovery complete: {len(log_files)} log files found")
        return {
            "log_files": log_files,
        }

    def _looks_like_log(self, content: str) -> bool:
        """Check if content looks like a log file."""
        # Look for common log patterns
        log_patterns = [
            r"\d{4}-\d{2}-\d{2}",  # Date
            r"\d{2}:\d{2}:\d{2}",  # Time
            r"\[(INFO|ERROR|WARN|DEBUG)\]",  # Log levels
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
        ]
        
        for pattern in log_patterns:
            if re.search(pattern, content):
                return True
        
        return False
