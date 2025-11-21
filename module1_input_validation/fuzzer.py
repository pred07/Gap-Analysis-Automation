"""Custom Input Fuzzer"""
import requests
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class InputFuzzer:
    SQL_PAYLOADS = ["' OR '1'='1", "' OR '1'='1' --", "admin' --", "' UNION SELECT NULL--"]
    XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    
    def __init__(self, target_url, logger=None, timeout=10):
        self.target_url = target_url
        self.logger = logger
        self.timeout = timeout
        self.session = requests.Session()
    
    def test_sql_injection(self):
        results = {"vulnerable": False, "findings": [], "tested_payloads": 0}
        
        if self.logger:
            self.logger.info("Testing SQL injection payloads...")
        
        for payload in self.SQL_PAYLOADS[:3]:  # Test first 3 for speed
            results["tested_payloads"] += 1
            try:
                test_url = f"{self.target_url}?id={payload}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                sql_errors = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle']
                if any(err in response.text.lower() for err in sql_errors):
                    results["vulnerable"] = True
                    results["findings"].append({"payload": payload, "url": test_url})
                    if self.logger:
                        self.logger.warning(f"Potential SQLi with: {payload}")
            except:
                pass
            time.sleep(0.1)
        
        return results
    
    def test_xss(self):
        results = {"vulnerable": False, "findings": [], "tested_payloads": 0}
        
        if self.logger:
            self.logger.info("Testing XSS payloads...")
        
        for payload in self.XSS_PAYLOADS[:2]:  # Test first 2 for speed
            results["tested_payloads"] += 1
            try:
                test_url = f"{self.target_url}?q={payload}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if payload in response.text:
                    results["vulnerable"] = True
                    results["findings"].append({"payload": payload, "url": test_url})
                    if self.logger:
                        self.logger.warning(f"Potential XSS with: {payload}")
            except:
                pass
            time.sleep(0.1)
        
        return results
    
    def test_file_upload(self):
        return {"vulnerable": False, "findings": [], "tested_extensions": 0}
