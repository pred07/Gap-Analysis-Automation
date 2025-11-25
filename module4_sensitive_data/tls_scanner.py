"""
TLS Scanner wrapper for testssl.sh integration.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Dict, Optional


class TLSScanner:
    """Wrapper for testssl.sh tool."""

    def __init__(self, tool_path: str, logger):
        self.tool_path = tool_path
        self.logger = logger

    def quick_scan(self, target: str) -> Dict:
        """
        Run a quick TLS scan on the target.
        Returns a dictionary with scan results.
        """
        self.logger.info(f"Running TLS quick scan on {target}")
        
        # Check if testssl.sh exists
        if not Path(self.tool_path).exists():
            self.logger.warning(f"testssl.sh not found at {self.tool_path}")
            return {"success": False, "error": "tool_not_found"}
        
        try:
            # Run testssl.sh with basic checks
            cmd = [self.tool_path, "--fast", "--quiet", target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
            )
            
            if result.returncode != 0:
                self.logger.warning(f"testssl.sh returned non-zero exit code: {result.returncode}")
                return {"success": False, "error": "scan_failed", "stderr": result.stderr}
            
            # Parse output
            output = result.stdout
            scan_results = self._parse_output(output)
            scan_results["success"] = True
            
            self.logger.info(f"TLS scan completed for {target}")
            return scan_results
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"TLS scan timed out for {target}")
            return {"success": False, "error": "timeout"}
        except Exception as e:
            self.logger.error(f"TLS scan failed: {e}")
            return {"success": False, "error": str(e)}

    def full_scan(self, target: str, output_file: Optional[str] = None) -> Dict:
        """
        Run a full TLS scan with detailed analysis.
        """
        self.logger.info(f"Running full TLS scan on {target}")
        
        if not Path(self.tool_path).exists():
            self.logger.warning(f"testssl.sh not found at {self.tool_path}")
            return {"success": False, "error": "tool_not_found"}
        
        try:
            cmd = [self.tool_path, "--quiet", target]
            
            if output_file:
                cmd.extend(["--jsonfile", output_file])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for full scan
            )
            
            scan_results = {"success": True, "output_file": output_file}
            
            if output_file and Path(output_file).exists():
                # Parse JSON output
                try:
                    with open(output_file, "r") as f:
                        json_data = json.load(f)
                        scan_results["json_data"] = json_data
                except Exception as e:
                    self.logger.warning(f"Failed to parse JSON output: {e}")
            
            return scan_results
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Full TLS scan timed out for {target}")
            return {"success": False, "error": "timeout"}
        except Exception as e:
            self.logger.error(f"Full TLS scan failed: {e}")
            return {"success": False, "error": str(e)}

    def _parse_output(self, output: str) -> Dict:
        """
        Parse testssl.sh text output and extract key information.
        """
        results = {
            "tls_version": "unknown",
            "cert_valid": False,
            "mixed_content": False,
            "vulnerabilities": [],
        }
        
        # Parse TLS version
        if "TLS 1.3" in output:
            results["tls_version"] = "TLS 1.3"
        elif "TLS 1.2" in output:
            results["tls_version"] = "TLS 1.2"
        elif "TLS 1.1" in output:
            results["tls_version"] = "TLS 1.1"
        elif "TLS 1.0" in output:
            results["tls_version"] = "TLS 1.0"
        
        # Check certificate validity
        if "certificate valid" in output.lower() or "ok" in output.lower():
            results["cert_valid"] = True
        
        # Check for common vulnerabilities
        vuln_keywords = ["VULNERABLE", "CRITICAL", "HIGH", "heartbleed", "poodle", "beast"]
        for keyword in vuln_keywords:
            if keyword.lower() in output.lower():
                results["vulnerabilities"].append(keyword)
        
        return results

    def check_certificate(self, target: str) -> Dict:
        """
        Check SSL/TLS certificate validity.
        """
        self.logger.info(f"Checking certificate for {target}")
        
        try:
            # Use openssl to check certificate
            cmd = ["openssl", "s_client", "-connect", f"{target}:443", "-servername", target]
            
            result = subprocess.run(
                cmd,
                input=b"",
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            output = result.stdout
            
            cert_info = {
                "valid": False,
                "issuer": "unknown",
                "subject": "unknown",
                "expiry": "unknown",
            }
            
            # Parse certificate info
            if "Verify return code: 0 (ok)" in output:
                cert_info["valid"] = True
            
            # Extract issuer
            issuer_match = re.search(r"issuer=(.+)", output)
            if issuer_match:
                cert_info["issuer"] = issuer_match.group(1).strip()
            
            # Extract subject
            subject_match = re.search(r"subject=(.+)", output)
            if subject_match:
                cert_info["subject"] = subject_match.group(1).strip()
            
            return cert_info
            
        except Exception as e:
            self.logger.error(f"Certificate check failed: {e}")
            return {"valid": False, "error": str(e)}


# Import re for certificate parsing
import re
