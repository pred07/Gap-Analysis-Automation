"""Nikto Scanner Integration"""
import os
import subprocess
from urllib.parse import urlparse

class NiktoScanner:
    def __init__(self, nikto_path="nikto", logger=None):
        self.nikto_path = nikto_path
        self.logger = logger
    
    def scan(self, target, output_file, ssl=None):
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            parsed = urlparse(target)
            host = parsed.netloc or parsed.path
            
            if ssl is None:
                ssl = parsed.scheme == 'https'
            
            command = [self.nikto_path, "-h", host, "-o", output_file, "-Format", "txt"]
            if ssl:
                command.append("-ssl")
            
            if self.logger:
                self.logger.info(f"Running Nikto scan on {host}")
            
            process = subprocess.run(command, capture_output=True, text=True, timeout=900)
            
            return {
                "success": os.path.exists(output_file),
                "output_file": output_file,
                "error": None if os.path.exists(output_file) else "Scan failed"
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Nikto scan timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def parse_results(self, output_file):
        findings = {"input_validation_issues": [], "other": []}
        try:
            if not os.path.exists(output_file):
                return findings
            
            with open(output_file, 'r', errors='ignore') as f:
                for line in f:
                    line_lower = line.lower()
                    if any(k in line_lower for k in ['script', 'injection', 'xss']):
                        findings["input_validation_issues"].append(line.strip())
                    elif '+' in line or 'OSVDB' in line:
                        findings["other"].append(line.strip())
        except:
            pass
        
        return findings
