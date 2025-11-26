#!/usr/bin/env python3
"""
URL Parser for Batch Analysis

Parses and validates URLs/endpoints from text files.
Categorizes URLs as web apps, APIs, or infrastructure.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
import logging


logger = logging.getLogger(__name__)


class URLParser:
    """Parse and validate URLs from text files."""
    
    def __init__(self, debug: bool = False):
        """
        Initialize URL parser.
        
        Args:
            debug: Enable debug logging
        """
        self.debug = debug
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # URL validation pattern
        self.url_pattern = re.compile(
            r'^https?://[^\s<>"{}|\\^`\[\]]+$',
            re.IGNORECASE
        )
        
        # API endpoint indicators
        self.api_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
            'api.', 'rest.', 'graphql.'
        ]
        
        # Infrastructure indicators
        self.infra_indicators = [
            'admin.', 'console.', 'dashboard.', 'jenkins.', 'gitlab.',
            'monitor.', 'grafana.', 'prometheus.', 'kibana.'
        ]
    
    def parse_directory(self, directory: Path) -> Dict[str, List[str]]:
        """
        Parse all text files in directory for URLs.
        
        Args:
            directory: Path to directory containing URL files
            
        Returns:
            Dictionary with categorized URLs
        """
        if not directory.exists():
            logger.warning(f"Directory not found: {directory}")
            return {"web": [], "api": [], "infrastructure": [], "all": []}
        
        all_urls: Set[str] = set()
        
        # Parse all .txt files
        for file_path in directory.glob("*.txt"):
            try:
                logger.info(f"Parsing {file_path.name}...")
                urls = self.parse_file(file_path)
                all_urls.update(urls)
            except Exception as e:
                logger.error(f"Error parsing {file_path.name}: {e}")
        
        # Categorize URLs
        categorized = self.categorize_urls(list(all_urls))
        
        logger.info(f"Found {len(all_urls)} unique URLs")
        logger.info(f"  - Web: {len(categorized['web'])}")
        logger.info(f"  - API: {len(categorized['api'])}")
        logger.info(f"  - Infrastructure: {len(categorized['infrastructure'])}")
        
        return categorized
    
    def parse_file(self, file_path: Path) -> List[str]:
        """
        Parse a single text file for URLs.
        
        Args:
            file_path: Path to text file
            
        Returns:
            List of valid URLs
        """
        urls = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Validate URL
                if self.validate_url(line):
                    urls.append(line)
                else:
                    logger.warning(f"Invalid URL at {file_path.name}:{line_num}: {line}")
        
        return urls
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL string to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not self.url_pattern.match(url):
            return False
        
        try:
            parsed = urlparse(url)
            # Must have scheme and netloc
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False
    
    def categorize_urls(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        Categorize URLs by type.
        
        Args:
            urls: List of URLs to categorize
            
        Returns:
            Dictionary with categorized URLs
        """
        categorized = {
            "web": [],
            "api": [],
            "infrastructure": [],
            "all": urls
        }
        
        for url in urls:
            category = self.categorize_url(url)
            categorized[category].append(url)
        
        return categorized
    
    def categorize_url(self, url: str) -> str:
        """
        Determine URL category.
        
        Args:
            url: URL to categorize
            
        Returns:
            Category: 'api', 'infrastructure', or 'web'
        """
        url_lower = url.lower()
        
        # Check for API indicators
        if any(indicator in url_lower for indicator in self.api_indicators):
            return "api"
        
        # Check for infrastructure indicators
        if any(indicator in url_lower for indicator in self.infra_indicators):
            return "infrastructure"
        
        # Default to web application
        return "web"
    
    def extract_base_urls(self, urls: List[str]) -> List[str]:
        """
        Extract base URLs (scheme + netloc) from full URLs.
        
        Args:
            urls: List of full URLs
            
        Returns:
            List of base URLs
        """
        base_urls = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                base_urls.add(base_url)
            except Exception as e:
                logger.warning(f"Error parsing URL {url}: {e}")
        
        return list(base_urls)
    
    def get_unique_domains(self, urls: List[str]) -> List[str]:
        """
        Extract unique domains from URLs.
        
        Args:
            urls: List of URLs
            
        Returns:
            List of unique domains
        """
        domains = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domains.add(parsed.netloc)
            except Exception:
                continue
        
        return sorted(list(domains))


if __name__ == "__main__":
    # Test the parser
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1:
        test_path = Path(sys.argv[1])
    else:
        test_path = Path("batch_inputs/urls")
    
    parser = URLParser(debug=True)
    results = parser.parse_directory(test_path)
    
    print("\n=== URL Parsing Results ===")
    print(f"Total URLs: {len(results['all'])}")
    print(f"Web Applications: {len(results['web'])}")
    print(f"API Endpoints: {len(results['api'])}")
    print(f"Infrastructure: {len(results['infrastructure'])}")
    
    if results['web']:
        print("\nSample Web URLs:")
        for url in results['web'][:3]:
            print(f"  - {url}")
    
    if results['api']:
        print("\nSample API URLs:")
        for url in results['api'][:3]:
            print(f"  - {url}")
    
    if results['infrastructure']:
        print("\nSample Infrastructure URLs:")
        for url in results['infrastructure'][:3]:
            print(f"  - {url}")
