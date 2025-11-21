"""OWASP ZAP Scanner Integration"""
import os
import subprocess
import xml.etree.ElementTree as ET

class ZAPScanner:
    def __init__(self, zap_path, logger=None):
        self.zap_path = zap_path
        self.logger = logger
    
    def quick_scan(self, target_url, output_file):
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            command = [self.zap_path, "-cmd", "-quickurl", target_url, "-quickout", output_file]
            
            if self.logger:
                self.logger.info(f"Running ZAP scan on {target_url}")
            
            process = subprocess.run(command, capture_output=True, text=True, timeout=600)
            
            return {
                "success": process.returncode == 0,
                "output_file": output_file,
                "error": None if process.returncode == 0 else process.stderr
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "ZAP scan timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def parse_results(self, xml_file):
        findings = {"sql_injection": [], "xss": [], "other": []}
        try:
            if not os.path.exists(xml_file):
                return findings
            
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for alert in root.findall(".//alertitem"):
                name = alert.find("name")
                alert_name = name.text if name is not None else ""
                alert_lower = alert_name.lower()
                
                if "sql" in alert_lower or "injection" in alert_lower:
                    findings["sql_injection"].append(alert_name)
                elif "xss" in alert_lower or "script" in alert_lower:
                    findings["xss"].append(alert_name)
                else:
                    findings["other"].append(alert_name)
        except:
            pass
        
        return findings
