"""OWASP ZAP Scanner Integration - Fixed Version"""
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

class ZAPScanner:
    def __init__(self, zap_path, logger=None):
        self.zap_path = zap_path
        self.logger = logger
    
    def quick_scan(self, target_url, output_file):
        try:
            # Ensure absolute path for output
            output_file = os.path.abspath(output_file)
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Remove old report if exists
            if os.path.exists(output_file):
                os.remove(output_file)
            
            command = [
                self.zap_path,
                "-cmd",
                "-quickurl", target_url,
                "-quickout", output_file,
                "-quickprogress"
            ]
            
            if self.logger:
                self.logger.info(f"Running ZAP: {' '.join(command)}")
                self.logger.info(f"Output file: {output_file}")
            
            # Run ZAP with proper working directory
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=os.getcwd()
            )
            
            # Check if file was created
            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                if self.logger:
                    self.logger.info(f"✓ ZAP report created: {output_file} ({file_size} bytes)")
                
                return {
                    "success": True,
                    "output_file": output_file,
                    "error": None
                }
            else:
                # ZAP might have created it in a different location
                # Check common locations
                possible_locations = [
                    output_file,
                    os.path.basename(output_file),
                    f"~/.ZAP/{os.path.basename(output_file)}",
                    f"/tmp/{os.path.basename(output_file)}"
                ]
                
                for loc in possible_locations:
                    expanded = os.path.expanduser(loc)
                    if os.path.exists(expanded):
                        if self.logger:
                            self.logger.info(f"Found ZAP report at: {expanded}")
                        # Copy to expected location
                        import shutil
                        shutil.copy(expanded, output_file)
                        return {
                            "success": True,
                            "output_file": output_file,
                            "error": None
                        }
                
                # File not found anywhere
                if self.logger:
                    self.logger.error(f"ZAP report not created. stderr: {process.stderr}")
                
                return {
                    "success": False,
                    "error": f"Report file not created. Return code: {process.returncode}"
                }
                
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "ZAP scan timed out after 10 minutes"}
        except Exception as e:
            if self.logger:
                self.logger.exception(f"ZAP scan error: {e}")
            return {"success": False, "error": str(e)}
    
    def parse_results(self, xml_file):
        findings = {
            "sql_injection": [],
            "xss": [],
            "http_smuggling": [],
            "other": []
        }
        
        try:
            if not os.path.exists(xml_file):
                if self.logger:
                    self.logger.warning(f"ZAP XML file not found: {xml_file}")
                return findings
            
            # Check if file is empty
            if os.path.getsize(xml_file) == 0:
                if self.logger:
                    self.logger.warning(f"ZAP XML file is empty: {xml_file}")
                return findings
            
            # Parse XML
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Find all alert items
            alerts_found = 0
            for alert in root.findall(".//alertitem"):
                alerts_found += 1
                
                name_elem = alert.find("name")
                risk_elem = alert.find("riskdesc")
                uri_elem = alert.find("uri")
                desc_elem = alert.find("desc")
                
                alert_name = name_elem.text if name_elem is not None else "Unknown"
                risk = risk_elem.text if risk_elem is not None else "Unknown"
                uri = uri_elem.text if uri_elem is not None else ""
                desc = desc_elem.text if desc_elem is not None else ""
                
                alert_data = {
                    "name": alert_name,
                    "risk": risk,
                    "uri": uri,
                    "description": desc[:200]  # Truncate
                }
                
                # Categorize by vulnerability type
                alert_lower = alert_name.lower()
                
                if "sql" in alert_lower or "injection" in alert_lower:
                    findings["sql_injection"].append(alert_data)
                elif "xss" in alert_lower or "cross" in alert_lower or "script" in alert_lower:
                    findings["xss"].append(alert_data)
                elif "smuggling" in alert_lower:
                    findings["http_smuggling"].append(alert_data)
                else:
                    findings["other"].append(alert_data)
            
            if self.logger:
                self.logger.info(f"ZAP: Parsed {alerts_found} alerts from report")
                self.logger.info(f"  SQLi: {len(findings['sql_injection'])}, "
                               f"XSS: {len(findings['xss'])}, "
                               f"Smuggling: {len(findings['http_smuggling'])}, "
                               f"Other: {len(findings['other'])}")
        
        except ET.ParseError as e:
            if self.logger:
                self.logger.error(f"Failed to parse ZAP XML: {e}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error parsing ZAP results: {e}")
        
        return findings
