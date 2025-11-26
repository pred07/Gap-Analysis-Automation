#!/usr/bin/env python3
"""
Enhanced Dashboard Generator for Batch Analysis

Generates interactive HTML dashboard with detailed security findings,
severity levels, CVSS scores, and professional UI design.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging


logger = logging.getLogger(__name__)


class DashboardGenerator:
    """Generate enhanced HTML dashboard from batch analysis results."""
    
    # Severity to CVSS score mapping
    SEVERITY_CVSS = {
        "Critical": (9.0, 10.0),
        "High": (7.0, 8.9),
        "Medium": (4.0, 6.9),
        "Low": (0.1, 3.9),
        "Info": (0.0, 0.0)
    }
    
    # Control status to severity mapping
    STATUS_SEVERITY = {
        "fail": "High",
        "not_tested": "Medium",
        "pass": "Info"
    }
    
    def __init__(self, template_dir: Optional[Path] = None, debug: bool = False):
        """
        Initialize dashboard generator.
        
        Args:
            template_dir: Directory containing HTML templates
            debug: Enable debug logging
        """
        self.debug = debug
        if debug:
            logger.setLevel(logging.DEBUG)
        
        self.template_dir = template_dir or Path(__file__).parent / "report_templates"
        self.template_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_dashboard(
        self,
        results: Dict[str, Any],
        output_path: Optional[Path] = None
    ) -> Path:
        """
        Generate complete HTML dashboard with detailed findings.
        
        Args:
            results: Batch analysis results
            output_path: Path for output HTML file
            
        Returns:
            Path to generated dashboard
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(f"batch_outputs/reports/dashboard_{timestamp}.html")
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Generating enhanced dashboard at {output_path}...")
        
        # Load detailed findings from module outputs
        detailed_results = self._load_detailed_findings(results)
        
        # Build HTML content
        html = self._build_html(detailed_results)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Dashboard generated successfully: {output_path}")
        return output_path
    
    def _load_detailed_findings(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Load detailed findings from module output files."""
        module_results = results.get("module_results", {})
        detailed = {
            "summary": results.get("summary", {}),
            "timestamp": results.get("timestamp", ""),
            "execution_time": results.get("execution_time", 0),
            "modules": {},
            "all_findings": [],
            "controls_summary": {
                "total": 65,
                "passed": 0,
                "failed": 0,
                "not_tested": 0
            },
            "input_summary": {
                "documents": [],
                "url_files": [],
                "total_urls": 0,
                "web_urls": 0,
                "api_urls": 0,
                "infrastructure_urls": 0,
                "policies_found": 0,
                "controls_found": 0,
                "missing_inputs": []
            }
        }
        
        # Load input summary from batch_inputs directories
        try:
            # Check for documents
            docs_dir = Path("batch_inputs/documents")
            if docs_dir.exists():
                doc_files = [f.name for f in docs_dir.iterdir() if f.is_file() and not f.name.startswith('.')]
                detailed["input_summary"]["documents"] = doc_files
            
            # Check for URL files
            urls_dir = Path("batch_inputs/urls")
            if urls_dir.exists():
                url_files = [f.name for f in urls_dir.iterdir() if f.is_file() and f.suffix == '.txt' and not f.name.startswith('.')]
                detailed["input_summary"]["url_files"] = url_files
            
            # Check for missing inputs
            if not detailed["input_summary"]["documents"]:
                detailed["input_summary"]["missing_inputs"].append("No documents found in batch_inputs/documents/")
            if not detailed["input_summary"]["url_files"]:
                detailed["input_summary"]["missing_inputs"].append("No URL files found in batch_inputs/urls/")
                
        except Exception as e:
            logger.warning(f"Error loading input summary: {e}")
        
        for module_num, module_data in module_results.items():
            output_file = module_data.get("output_file")
            if not output_file:
                continue
            
            output_path = Path(output_file)
            if not output_path.exists():
                logger.warning(f"Output file not found: {output_file}")
                continue
            
            try:
                with open(output_path, 'r') as f:
                    module_output = json.load(f)
                
                # Extract findings
                findings = self._extract_findings(module_num, module_output)
                detailed["modules"][module_num] = {
                    "name": module_data.get("module", f"Module {module_num}"),
                    "success": module_data.get("success", False),
                    "findings": findings,
                    "controls": self._extract_controls(module_output)
                }
                
                # Aggregate findings
                detailed["all_findings"].extend(findings)
                
                # Count control statuses
                controls = self._extract_controls(module_output)
                for control_name, status in controls.items():
                    if status == "pass":
                        detailed["controls_summary"]["passed"] += 1
                        if "passed_controls" not in detailed["controls_summary"]:
                            detailed["controls_summary"]["passed_controls"] = []
                        detailed["controls_summary"]["passed_controls"].append({
                            "name": control_name,
                            "module": module_num
                        })
                    elif status == "fail":
                        detailed["controls_summary"]["failed"] += 1
                        if "failed_controls" not in detailed["controls_summary"]:
                            detailed["controls_summary"]["failed_controls"] = []
                        detailed["controls_summary"]["failed_controls"].append({
                            "name": control_name,
                            "module": module_num
                        })
                    elif status == "not_tested":
                        detailed["controls_summary"]["not_tested"] += 1
                        if "not_tested_controls" not in detailed["controls_summary"]:
                            detailed["controls_summary"]["not_tested_controls"] = []
                        detailed["controls_summary"]["not_tested_controls"].append({
                            "name": control_name,
                            "module": module_num
                        })
                
            except Exception as e:
                logger.error(f"Error loading {output_file}: {e}")
        
        # Update summary with actual counts
        detailed["summary"]["controls_passed"] = detailed["controls_summary"]["passed"]
        detailed["summary"]["controls_failed"] = detailed["controls_summary"]["failed"]
        detailed["summary"]["controls_not_tested"] = detailed["controls_summary"]["not_tested"]
        
        return detailed
    
    def _extract_findings(self, module_num: str, module_output: Dict) -> List[Dict]:
        """Extract security findings from module output."""
        findings = []
        
        # Check for targets array
        targets = module_output.get("targets", [])
        if not targets and "controls" in module_output:
            # Old format - single target
            targets = [module_output]
        
        for target_data in targets:
            target_url = target_data.get("target", "Unknown")
            controls = target_data.get("controls", {})
            evidence = target_data.get("evidence", {})
            
            # Extract from controls
            for control_name, status in controls.items():
                if status == "fail":
                    findings.append({
                        "module": module_num,
                        "control": control_name,
                        "severity": "High",
                        "cvss": 7.5,
                        "title": self._format_control_name(control_name),
                        "description": f"{control_name} control failed for {target_url}",
                        "target": target_url,
                        "remediation": self._get_remediation(control_name)
                    })
            
            # Extract from evidence
            findings.extend(self._extract_evidence_findings(module_num, target_url, evidence))
        
        return findings
    
    def _extract_evidence_findings(self, module_num: str, target: str, evidence: Dict) -> List[Dict]:
        """Extract findings from evidence section."""
        findings = []
        
        # Missing headers
        if "header_analysis" in evidence:
            missing_headers = evidence["header_analysis"].get("missing_headers", [])
            for header in missing_headers:
                findings.append({
                    "module": module_num,
                    "control": "Security Headers",
                    "severity": header.get("severity", "Medium"),
                    "cvss": self._severity_to_cvss(header.get("severity", "Medium")),
                    "title": f"Missing Security Header: {header.get('header', 'Unknown')}",
                    "description": f"The security header '{header.get('header')}' is missing from {target}",
                    "target": target,
                    "remediation": f"Add the '{header.get('header')}' header to your server configuration"
                })
        
        return findings
    
    def _extract_controls(self, module_output: Dict) -> Dict[str, str]:
        """Extract control statuses from module output."""
        controls = {}
        
        targets = module_output.get("targets", [])
        if not targets and "controls" in module_output:
            targets = [module_output]
        
        for target_data in targets:
            target_controls = target_data.get("controls", {})
            controls.update(target_controls)
        
        return controls
    
    def _format_control_name(self, control_name: str) -> str:
        """Format control name for display."""
        return control_name.replace("_", " ").title()
    
    def _get_remediation(self, control_name: str) -> str:
        """Get remediation advice for a control."""
        remediations = {
            "SQL_Injection": "Implement parameterized queries and input validation",
            "XSS": "Implement output encoding and Content Security Policy",
            "Schema_Validation": "Implement strict JSON schema validation",
            "CORS": "Configure CORS to allow only trusted origins",
            "API_Auth": "Implement proper authentication for all API endpoints",
            "Rate_Limiting": "Implement rate limiting to prevent abuse",
        }
        return remediations.get(control_name, "Review and implement security best practices")
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to CVSS score."""
        ranges = self.SEVERITY_CVSS.get(severity, (5.0, 5.0))
        return (ranges[0] + ranges[1]) / 2
    
    def _build_html(self, results: Dict[str, Any]) -> str:
        """Build complete HTML document."""
        summary = results.get("summary", {})
        modules = results.get("modules", {})
        all_findings = results.get("all_findings", [])
        controls_summary = results.get("controls_summary", {})
        input_summary = results.get("input_summary", {})
        
        # Calculate security score
        total = controls_summary.get("total", 65)
        passed = controls_summary.get("passed", 0)
        security_score = int((passed / total) * 100) if total > 0 else 0
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security GAP Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    {self._get_enhanced_styles()}
</head>
<body>
    <div class="container">
        {self._create_enhanced_header(summary, security_score)}
        {self._create_enhanced_executive_summary(summary, security_score, controls_summary)}
        {self._create_charts_section(controls_summary, all_findings, modules)}
        {self._create_control_breakdown(controls_summary)}
        {self._create_findings_overview(all_findings)}
        {self._create_findings_by_target(all_findings)}
        {self._create_detailed_findings_table(all_findings)}
        {self._create_module_details(modules)}
        {self._create_input_summary_section(input_summary)}
        {self._create_enhanced_footer(results)}
    </div>
    {self._get_enhanced_scripts(controls_summary, all_findings, modules)}
</body>
</html>"""
        return html
    
    def _get_enhanced_styles(self) -> str:
        """Get enhanced CSS styles with premium design."""
        return """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #1e293b;
            border-radius: 20px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            overflow: hidden;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #d946ef 100%);
            padding: 60px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }
        
        .header-content {
            position: relative;
            z-index: 1;
        }
        
        .header h1 {
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 10px;
            color: white;
            text-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }
        
        .header .subtitle {
            font-size: 1.3em;
            opacity: 0.95;
            font-weight: 300;
        }
        
        .header .timestamp {
            margin-top: 15px;
            font-size: 0.95em;
            opacity: 0.8;
        }
        
        /* Sections */
        .section {
            padding: 50px 40px;
            border-bottom: 1px solid #334155;
        }
        
        .section:last-child {
            border-bottom: none;
        }
        
        .section-title {
            font-size: 2.2em;
            margin-bottom: 30px;
            color: #f1f5f9;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .section-title::before {
            content: '';
            width: 5px;
            height: 40px;
            background: linear-gradient(180deg, #6366f1, #8b5cf6);
            border-radius: 10px;
        }
        
        /* Executive Summary */
        .executive-summary {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #334155 0%, #475569 100%);
            padding: 30px;
            border-radius: 15px;
            border: 1px solid #475569;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #6366f1, #8b5cf6);
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(99, 102, 241, 0.2);
            border-color: #6366f1;
        }
        
        .summary-card .label {
            font-size: 0.9em;
            color: #94a3b8;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }
        
        .summary-card .value {
            font-size: 3.5em;
            font-weight: 700;
            margin: 15px 0;
            background: linear-gradient(135deg, #f1f5f9, #cbd5e1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .value.critical { background: linear-gradient(135deg, #ef4444, #dc2626); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .value.high { background: linear-gradient(135deg, #f59e0b, #d97706); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .value.medium { background: linear-gradient(135deg, #3b82f6, #2563eb); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .value.success { background: linear-gradient(135deg, #10b981, #059669); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        
        .summary-card .detail {
            font-size: 0.85em;
            color: #94a3b8;
            margin-top: 10px;
        }
        
        /* Security Score Gauge */
        .score-gauge {
            position: relative;
            width: 200px;
            height: 200px;
            margin: 0 auto;
        }
        
        .score-circle {
            transform: rotate(-90deg);
        }
        
        .score-value {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 3em;
            font-weight: 700;
        }
        
        /* Findings Table */
        .findings-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0 10px;
            margin-top: 20px;
        }
        
        .findings-table thead th {
            background: #334155;
            padding: 15px 20px;
            text-align: left;
            font-weight: 600;
            color: #f1f5f9;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: none;
        }
        
        .findings-table thead th:first-child {
            border-radius: 10px 0 0 10px;
        }
        
        .findings-table thead th:last-child {
            border-radius: 0 10px 10px 0;
        }
        
        .findings-table tbody tr {
            background: #334155;
            transition: all 0.2s ease;
        }
        
        .findings-table tbody tr:hover {
            background: #3f4d63;
            transform: scale(1.01);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        }
        
        .findings-table tbody td {
            padding: 20px;
            border: none;
        }
        
        .findings-table tbody tr td:first-child {
            border-radius: 10px 0 0 10px;
        }
        
        .findings-table tbody tr td:last-child {
            border-radius: 0 10px 10px 0;
        }
        
        /* Severity Badges */
        .severity-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .severity-badge::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .severity-critical {
            background: linear-gradient(135deg, #7f1d1d, #991b1b);
            color: #fecaca;
            border: 1px solid #dc2626;
        }
        
        .severity-critical::before {
            background: #fecaca;
        }
        
        .severity-high {
            background: linear-gradient(135deg, #92400e, #b45309);
            color: #fed7aa;
            border: 1px solid #f59e0b;
        }
        
        .severity-high::before {
            background: #fed7aa;
        }
        
        .severity-medium {
            background: linear-gradient(135deg, #1e3a8a, #1e40af);
            color: #bfdbfe;
            border: 1px solid #3b82f6;
        }
        
        .severity-medium::before {
            background: #bfdbfe;
        }
        
        .severity-low {
            background: linear-gradient(135deg, #065f46, #047857);
            color: #a7f3d0;
            border: 1px solid #10b981;
        }
        
        .severity-low::before {
            background: #a7f3d0;
        }
        
        .severity-info {
            background: linear-gradient(135deg, #334155, #475569);
            color: #cbd5e1;
            border: 1px solid #64748b;
        }
        
        .severity-info::before {
            background: #cbd5e1;
        }
        
        /* CVSS Score */
        .cvss-score {
            display: inline-block;
            padding: 6px 12px;
            background: #1e293b;
            border-radius: 8px;
            font-weight: 600;
            font-family: 'Courier New', monospace;
        }
        
        /* Control Breakdown */
        .control-breakdown-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }
        
        .control-breakdown-card {
            background: #334155;
            border: 2px solid #475569;
            border-radius: 15px;
            padding: 25px;
            position: relative;
            overflow: hidden;
        }
        
        .passed-card {
            border-color: #10b981;
        }
        
        .passed-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #10b981, #059669);
        }
        
        .failed-card {
            border-color: #ef4444;
        }
        
        .failed-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #ef4444, #dc2626);
        }
        
        .not-tested-card {
            border-color: #f59e0b;
        }
        
        .not-tested-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #f59e0b, #d97706);
        }
        
        .control-breakdown-title {
            font-size: 1.2em;
            font-weight: 600;
            color: #f1f5f9;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .control-icon {
            font-size: 1.3em;
        }
        
        .control-list {
            list-style: none;
            padding: 0;
            margin: 0;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .control-list::-webkit-scrollbar {
            width: 8px;
        }
        
        .control-list::-webkit-scrollbar-track {
            background: #1e293b;
            border-radius: 4px;
        }
        
        .control-list::-webkit-scrollbar-thumb {
            background: #475569;
            border-radius: 4px;
        }
        
        .control-list::-webkit-scrollbar-thumb:hover {
            background: #64748b;
        }
        
        .control-list li {
            padding: 10px 12px;
            margin-bottom: 8px;
            background: #1e293b;
            border-radius: 8px;
            border-left: 3px solid transparent;
            color: #e2e8f0;
            font-size: 0.9em;
            transition: all 0.2s ease;
        }
        
        .passed-card .control-list li {
            border-left-color: #10b981;
        }
        
        .failed-card .control-list li {
            border-left-color: #ef4444;
        }
        
        .not-tested-card .control-list li {
            border-left-color: #f59e0b;
        }
        
        .control-list li:hover {
            background: #334155;
            transform: translateX(5px);
        }
        
        /* Module Cards */
        .module-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }
        
        /* Charts Section */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        
        /* Input Summary Section */
        .input-summary-section {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        }
        
        .section-subtitle {
            color: #94a3b8;
            font-size: 1.1em;
            margin-top: -15px;
            margin-bottom: 25px;
        }
        
        .input-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }
        
        .input-card {
            background: #334155;
            border: 1px solid #475569;
            border-radius: 15px;
            padding: 25px;
            position: relative;
            overflow: hidden;
        }
        
        .input-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #6366f1, #8b5cf6);
        }
        
        .input-card-title {
            font-size: 1.2em;
            font-weight: 600;
            color: #f1f5f9;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .title-icon {
            font-size: 1.3em;
        }
        
        .input-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .input-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 15px;
            background: #1e293b;
            border-radius: 8px;
            border: 1px solid #475569;
            transition: all 0.2s ease;
        }
        
        .input-item:hover {
            border-color: #6366f1;
            transform: translateX(5px);
        }
        
        .input-item.missing {
            background: linear-gradient(135deg, #7f1d1d, #991b1b);
            border-color: #dc2626;
        }
        
        .input-icon {
            font-size: 1.5em;
        }
        
        .input-name {
            flex: 1;
            color: #e2e8f0;
            font-size: 0.95em;
            font-weight: 500;
        }
        
        .input-status {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-used {
            background: linear-gradient(135deg, #065f46, #047857);
            color: #a7f3d0;
            border: 1px solid #10b981;
        }
        
        .status-missing {
            background: linear-gradient(135deg, #7f1d1d, #991b1b);
            color: #fecaca;
            border: 1px solid #dc2626;
        }
        
        .input-card-footer {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #475569;
            color: #94a3b8;
            font-size: 0.9em;
            font-weight: 500;
        }
        
        .missing-inputs-alert {
            margin-top: 30px;
            background: linear-gradient(135deg, #92400e, #b45309);
            border: 2px solid #f59e0b;
            border-radius: 12px;
            padding: 20px;
            color: #fed7aa;
        }
        
        .alert-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .alert-icon {
            font-size: 1.5em;
        }
        
        .alert-title {
            font-size: 1.1em;
            font-weight: 600;
        }
        
        .alert-list {
            margin: 15px 0;
            padding-left: 30px;
            list-style-type: disc;
        }
        
        .alert-list li {
            margin: 8px 0;
            font-size: 0.95em;
        }
        
        .alert-footer {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(255, 255, 255, 0.2);
            font-size: 0.9em;
        }
        
        .alert-footer code {
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #fef3c7;
        }
        
        /* Expanded Input Items */
        .input-item-expanded {
            background: #1e293b;
            border-radius: 8px;
            border: 1px solid #475569;
            margin-bottom: 10px;
            overflow: hidden;
        }
        
        .input-item-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 15px;
            cursor: pointer;
            transition: background 0.2s ease;
        }
        
        .input-item-header:hover {
            background: #334155;
        }
        
        .input-item-content {
            padding: 15px;
            background: #0f172a;
            border-top: 1px solid #475569;
            font-size: 0.9em;
            line-height: 1.8;
        }
        
        .url-code {
            background: #1e293b;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #60a5fa;
            font-size: 0.85em;
            border: 1px solid #334155;
            display: inline-block;
            margin: 2px 0;
        }
        
        /* Target Cards */
        .targets-container {
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin-top: 30px;
        }
        
        .target-card {
            background: #334155;
            border: 1px solid #475569;
            border-radius: 15px;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .target-card:hover {
            border-color: #6366f1;
            box-shadow: 0 10px 30px rgba(99, 102, 241, 0.2);
        }
        
        .target-header {
            background: linear-gradient(135deg, #1e293b, #334155);
            padding: 20px 25px;
            border-bottom: 2px solid #475569;
        }
        
        .target-url {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
        }
        
        .url-icon {
            font-size: 1.5em;
        }
        
        .target-url-text {
            background: #0f172a;
            padding: 8px 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            color: #60a5fa;
            font-size: 1em;
            border: 1px solid #334155;
            flex: 1;
        }
        
        .target-summary {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .target-count {
            background: #1e293b;
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.9em;
            color: #cbd5e1;
            font-weight: 600;
        }
        
        .mini-badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .badge-critical {
            background: linear-gradient(135deg, #7f1d1d, #991b1b);
            color: #fecaca;
            border: 1px solid #dc2626;
        }
        
        .badge-high {
            background: linear-gradient(135deg, #92400e, #b45309);
            color: #fed7aa;
            border: 1px solid #f59e0b;
        }
        
        .badge-medium {
            background: linear-gradient(135deg, #1e3a8a, #1e40af);
            color: #bfdbfe;
            border: 1px solid #3b82f6;
        }
        
        .badge-low {
            background: linear-gradient(135deg, #065f46, #047857);
            color: #a7f3d0;
            border: 1px solid #10b981;
        }
        
        .target-findings {
            padding: 0;
        }
        
        .target-findings-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .target-findings-table thead th {
            background: #1e293b;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            color: #f1f5f9;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #475569;
        }
        
        .target-findings-table tbody tr {
            border-bottom: 1px solid #475569;
            transition: background 0.2s ease;
        }
        
        .target-findings-table tbody tr:hover {
            background: #3f4d63;
        }
        
        .target-findings-table tbody tr:last-child {
            border-bottom: none;
        }
        
        .target-findings-table tbody td {
            padding: 15px;
            color: #e2e8f0;
        }
        
        /* Charts Section */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        
        .chart-card {
            background: #334155;
            border: 1px solid #475569;
            border-radius: 15px;
            padding: 30px;
            position: relative;
            overflow: hidden;
        }
        
        .chart-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #6366f1, #8b5cf6);
        }
        
        .chart-card h3 {
            font-size: 1.3em;
            font-weight: 600;
            color: #f1f5f9;
            margin-bottom: 20px;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
        }
        
        .chart-legend {
            margin-top: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            justify-content: center;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9em;
            color: #cbd5e1;
        }
        
        .legend-color {
            width: 16px;
            height: 16px;
            border-radius: 4px;
        }
        
        .module-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }
        
        .module-card {
            background: #334155;
            border: 1px solid #475569;
            border-radius: 15px;
            padding: 30px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .module-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #6366f1, #8b5cf6);
        }
        
        .module-card:hover {
            border-color: #6366f1;
            box-shadow: 0 15px 30px rgba(99, 102, 241, 0.2);
            transform: translateY(-3px);
        }
        
        .module-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .module-number {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5em;
            font-weight: 700;
            color: white;
            box-shadow: 0 5px 15px rgba(99, 102, 241, 0.3);
        }
        
        .module-name {
            font-size: 1.3em;
            font-weight: 600;
            color: #f1f5f9;
        }
        
        .module-status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
            margin-top: 15px;
        }
        
        .status-success {
            background: linear-gradient(135deg, #065f46, #047857);
            color: #a7f3d0;
            border: 1px solid #10b981;
        }
        
        .status-failed {
            background: linear-gradient(135deg, #7f1d1d, #991b1b);
            color: #fecaca;
            border: 1px solid #dc2626;
        }
        
        /* Footer */
        .footer {
            background: #0f172a;
            padding: 40px;
            text-align: center;
            color: #94a3b8;
            border-top: 1px solid #334155;
        }
        
        .footer-logo {
            font-size: 1.5em;
            font-weight: 700;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header h1 { font-size: 2em; }
            .section { padding: 30px 20px; }
            .summary-grid { grid-template-columns: 1fr; }
            .module-grid { grid-template-columns: 1fr; }
        }
        
        @media print {
            body { background: white; color: black; }
            .container { box-shadow: none; }
        }
    </style>
"""
    
    def _create_enhanced_header(self, summary: Dict[str, Any], security_score: int) -> str:
        """Create enhanced header with security score."""
        timestamp = summary.get("timestamp", datetime.now().isoformat())
        
        # Determine score color
        if security_score >= 80:
            score_class = "success"
        elif security_score >= 60:
            score_class = "medium"
        elif security_score >= 40:
            score_class = "high"
        else:
            score_class = "critical"
        
        return f"""
    <div class="header">
        <div class="header-content">
            <h1>Security GAP Analysis Report</h1>
            <p class="subtitle">Comprehensive Security Assessment Across 65 Controls</p>
            <p class="timestamp">Generated: {timestamp}</p>
            <div style="margin-top: 30px;">
                <div class="value {score_class}" style="font-size: 4em;">{security_score}%</div>
                <div class="subtitle">Overall Security Score</div>
            </div>
        </div>
    </div>
"""
    
    def _create_enhanced_executive_summary(
        self,
        summary: Dict[str, Any],
        security_score: int,
        controls_summary: Dict[str, int]
    ) -> str:
        """Create enhanced executive summary."""
        total_modules = summary.get("total_modules", 0)
        successful = summary.get("successful_modules", 0)
        failed = summary.get("failed_modules", 0)
        passed = controls_summary.get("passed", 0)
        failed_controls = controls_summary.get("failed", 0)
        not_tested = controls_summary.get("not_tested", 0)
        exec_time = summary.get("execution_time", 0)
        
        return f"""
    <div class="section executive-summary">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="label">Modules Executed</div>
                <div class="value medium">{total_modules}</div>
                <div class="detail">{successful} Successful • {failed} Failed</div>
            </div>
            <div class="summary-card">
                <div class="label">Controls Passed</div>
                <div class="value success">{passed}</div>
                <div class="detail">Out of 65 total controls</div>
            </div>
            <div class="summary-card">
                <div class="label">Controls Failed</div>
                <div class="value critical">{failed_controls}</div>
                <div class="detail">Require immediate attention</div>
            </div>
            <div class="summary-card">
                <div class="label">Not Tested</div>
                <div class="value high">{not_tested}</div>
                <div class="detail">Insufficient data</div>
            </div>
            <div class="summary-card">
                <div class="label">Execution Time</div>
                <div class="value medium">{exec_time/60:.1f}</div>
                <div class="detail">minutes</div>
            </div>
        </div>
        {f'''
        <div style="background: rgba(245, 158, 11, 0.1); border: 2px solid #f59e0b; border-radius: 12px; padding: 20px; margin-top: 25px;">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                <span style="font-size: 1.5em; color: #f59e0b;">⚠</span>
                <strong style="color: #fbbf24; font-size: 1.1em;">Incomplete Scan Detected</strong>
            </div>
            <div style="color: #fcd34d; line-height: 1.6;">
                <strong>{65 - (passed + failed_controls + not_tested)} controls</strong> were not executed. Only <strong>{passed + failed_controls + not_tested} out of 65</strong> controls were tested.
                <br><strong>Possible reasons:</strong> Missing input files (logs, infrastructure configs, documents) or modules failed to execute.
                <br><strong>Action:</strong> Check batch_inputs/ directory and ensure all required files are present.
            </div>
        </div>''' if (passed + failed_controls + not_tested) < 65 else ''}
    </div>
"""
    
    def _create_input_summary_section(self, input_summary: Dict[str, Any]) -> str:
        """Create input summary section showing what inputs were used."""
        documents = input_summary.get("documents", [])
        url_files = input_summary.get("url_files", [])
        missing_inputs = input_summary.get("missing_inputs", [])
        
        # Build documents list HTML
        docs_html = ""
        if documents:
            for doc in documents:
                docs_html += f"""
                <div class="input-item">

                    <span class="input-name">{doc}</span>
                    <span class="input-status status-used">Analyzed</span>
                </div>
"""
        else:
            docs_html = """
                <div class="input-item missing">

                    <span class="input-name">No documents provided</span>
                    <span class="input-status status-missing">Missing</span>
                </div>
"""
        
        # Build URL files list HTML with actual URLs
        urls_html = ""
        if url_files:
            for url_file in url_files:
                # Read actual URLs from the file
                urls_from_file = []
                try:
                    file_path = Path(f"batch_inputs/urls/{url_file}")
                    if file_path.exists():
                        with open(file_path, 'r') as f:
                            urls_from_file = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                except Exception as e:
                    logger.warning(f"Error reading {url_file}: {e}")
                
                urls_list = "<br>".join([f"<code class='url-code'>{url}</code>" for url in urls_from_file[:10]])  # Show first 10
                if len(urls_from_file) > 10:
                    urls_list += f"<br><em>... and {len(urls_from_file) - 10} more</em>"
                
                urls_html += f"""
                <div class="input-item-expanded">
                    <div class="input-item-header">

                        <span class="input-name">{url_file}</span>
                        <span class="input-status status-used">{len(urls_from_file)} URLs</span>
                    </div>
                    <div class="input-item-content">
                        {urls_list if urls_list else '<em>No URLs found</em>'}
                    </div>
                </div>
"""
        else:
            urls_html = """
                <div class="input-item missing">

                    <span class="input-name">No URL files provided</span>
                    <span class="input-status status-missing">Missing</span>
                </div>
"""
        
        # Build missing inputs alert
        missing_html = ""
        if missing_inputs:
            missing_items = "".join([f"<li>{item}</li>" for item in missing_inputs])
            missing_html = f"""
            <div class="missing-inputs-alert">
                <div class="alert-header">

                    <span class="alert-title">Missing Inputs Detected</span>
                </div>
                <ul class="alert-list">
                    {missing_items}
                </ul>
                <div class="alert-footer">
                    Add files to <code>batch_inputs/documents/</code> or <code>batch_inputs/urls/</code> for more comprehensive analysis
                </div>
            </div>
"""
        
        return f"""
    <div class="section input-summary-section">
        <h2 class="section-title">Input Reference</h2>
        <p class="section-subtitle">Complete list of all inputs analyzed in this scan</p>
        
        <div class="input-grid">
            <div class="input-card">
                <h3 class="input-card-title">

                    Documents Analyzed
                </h3>
                <div class="input-list">
                    {docs_html}
                </div>
                <div class="input-card-footer">
                    Total: {len(documents)} document(s)
                </div>
            </div>
            
            <div class="input-card">
                <h3 class="input-card-title">

                    URL Files & Endpoints
                </h3>
                <div class="input-list">
                    {urls_html}
                </div>
                <div class="input-card-footer">
                    Total: {len(url_files)} file(s)
                </div>
            </div>
        </div>
        
        {missing_html}
    </div>
"""
    
    
    
    def _create_control_breakdown(self, controls_summary: Dict[str, Any]) -> str:
        """Create detailed control breakdown showing which controls passed/failed."""
        passed_controls = controls_summary.get("passed_controls", [])
        failed_controls = controls_summary.get("failed_controls", [])
        not_tested_controls = controls_summary.get("not_tested_controls", [])
        
        # Helper function to format control name
        def format_control(ctrl):
            name = ctrl.get("name", "Unknown")
            module = ctrl.get("module", "?")
            # Make control name more readable
            readable_name = name.replace("_", " ").title()
            return f"{readable_name} <span style='color: #64748b;'>(M{module})</span>"
        
        # Build passed controls HTML
        passed_html = ""
        if passed_controls:
            for ctrl in passed_controls[:20]:  # Show first 20
                passed_html += f"<li>{format_control(ctrl)}</li>"
            if len(passed_controls) > 20:
                passed_html += f"<li><em>... and {len(passed_controls) - 20} more</em></li>"
        else:
            passed_html = "<li><em>No controls passed</em></li>"
        
        # Build failed controls HTML
        failed_html = ""
        if failed_controls:
            for ctrl in failed_controls:
                failed_html += f"<li>{format_control(ctrl)}</li>"
        else:
            failed_html = "<li><em>No controls failed</em></li>"
        
        # Build not tested controls HTML
        not_tested_html = ""
        if not_tested_controls:
            for ctrl in not_tested_controls:  # Show ALL
                not_tested_html += f"<li>{format_control(ctrl)}</li>"
        else:
            not_tested_html = "<li><em>All controls tested</em></li>"
        
        return f"""
    <div class="section">
        <h2 class="section-title">Control Status Breakdown</h2>
        <p class="section-subtitle">Detailed list of all 65 security controls and their test results</p>
        
        <div class="control-breakdown-grid">
            <div class="control-breakdown-card passed-card">
                <h3 class="control-breakdown-title">
                    <span class="control-icon">✓</span>
                    Passed Controls ({len(passed_controls)})
                </h3>
                <ul class="control-list">
                    {passed_html}
                </ul>
            </div>
            
            <div class="control-breakdown-card failed-card">
                <h3 class="control-breakdown-title">
                    <span class="control-icon">✗</span>
                    Failed Controls ({len(failed_controls)})
                </h3>
                <ul class="control-list">
                    {failed_html}
                </ul>
            </div>
            
            <div class="control-breakdown-card not-tested-card">
                <h3 class="control-breakdown-title">
                    <span class="control-icon">⊘</span>
                    Not Tested ({len(not_tested_controls)})
                </h3>
                <ul class="control-list">
                    {not_tested_html}
                </ul>
            </div>
        </div>
    </div>
"""
    
    def _create_charts_section(
        self,
        controls_summary: Dict[str, int],
        findings: List[Dict],
        modules: Dict[str, Any]
    ) -> str:
        """Create interactive charts section."""
        return f"""
    <div class="section">
        <h2 class="section-title">Visual Analytics</h2>
        <div class="charts-grid">
            <div class="chart-card">
                <h3>Control Status Distribution</h3>
                <div class="chart-container">
                    <canvas id="controlsChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Risk Distribution by Severity</h3>
                <div class="chart-container">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Findings by Severity</h3>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Module Performance</h3>
                <div class="chart-container">
                    <canvas id="moduleChart"></canvas>
                </div>
            </div>
        </div>
    </div>
"""
    
    
    def _create_findings_by_target(self, findings: List[Dict]) -> str:
        """Create findings grouped by target URL."""
        if not findings:
            return ""
        
        # Group findings by target
        findings_by_target = {}
        for finding in findings:
            target = finding.get("target", "Unknown")
            if target not in findings_by_target:
                findings_by_target[target] = []
            findings_by_target[target].append(finding)
        
        # Build HTML for each target
        targets_html = ""
        for target, target_findings in findings_by_target.items():
            # Count by severity for this target
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for finding in target_findings:
                severity = finding.get("severity", "Medium")
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Build findings list for this target
            findings_list = ""
            for i, finding in enumerate(target_findings, 1):
                severity = finding.get("severity", "Medium")
                cvss = finding.get("cvss", 5.0)
                title = finding.get("title", "Unknown Issue")
                description = finding.get("description", "No description")
                module = finding.get("module", "?")
                
                findings_list += f"""
                <tr>
                    <td style="width: 40px; font-weight: 600; color: #cbd5e1;">#{i}</td>
                    <td>
                        <div style="font-weight: 600; color: #f1f5f9; margin-bottom: 5px;">{title}</div>
                        <div style="font-size: 0.9em; color: #94a3b8;">{description}</div>
                    </td>
                    <td style="text-align: center;">
                        <span class="severity-badge severity-{severity.lower()}">{severity}</span>
                    </td>
                    <td style="text-align: center;">
                        <span class="cvss-score">{cvss:.1f}</span>
                    </td>
                    <td style="text-align: center; color: #94a3b8;">M{module}</td>
                </tr>
"""
            
            # Create severity summary badges
            severity_badges = ""
            if severity_counts["Critical"] > 0:
                severity_badges += f'<span class="mini-badge badge-critical">{severity_counts["Critical"]} Critical</span>'
            if severity_counts["High"] > 0:
                severity_badges += f'<span class="mini-badge badge-high">{severity_counts["High"]} High</span>'
            if severity_counts["Medium"] > 0:
                severity_badges += f'<span class="mini-badge badge-medium">{severity_counts["Medium"]} Medium</span>'
            if severity_counts["Low"] > 0:
                severity_badges += f'<span class="mini-badge badge-low">{severity_counts["Low"]} Low</span>'
            
            targets_html += f"""
            <div class="target-card">
                <div class="target-header">
                    <div class="target-url">

                        <code class="target-url-text">{target}</code>
                    </div>
                    <div class="target-summary">
                        {severity_badges}
                        <span class="target-count">{len(target_findings)} issue(s)</span>
                    </div>
                </div>
                <div class="target-findings">
                    <table class="target-findings-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Finding</th>
                                <th>Severity</th>
                                <th>CVSS</th>
                                <th>Module</th>
                            </tr>
                        </thead>
                        <tbody>
                            {findings_list}
                        </tbody>
                    </table>
                </div>
            </div>
"""
        
        return f"""
    <div class="section">
        <h2 class="section-title">Findings by Target</h2>
        <p class="section-subtitle">Security issues grouped by endpoint/URL</p>
        <div class="targets-container">
            {targets_html}
        </div>
    </div>
"""
    
    def _create_findings_overview(self, findings: List[Dict]) -> str:
        """Create findings overview section."""
        # Count by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in findings:
            severity = finding.get("severity", "Medium")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        total_findings = len(findings)
        
        return f"""
    <div class="section">
        <h2 class="section-title">Security Findings Overview</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="label">Total Findings</div>
                <div class="value medium">{total_findings}</div>
            </div>
            <div class="summary-card">
                <div class="label">Critical</div>
                <div class="value critical">{severity_counts['Critical']}</div>
            </div>
            <div class="summary-card">
                <div class="label">High</div>
                <div class="value high">{severity_counts['High']}</div>
            </div>
            <div class="summary-card">
                <div class="label">Medium</div>
                <div class="value medium">{severity_counts['Medium']}</div>
            </div>
            <div class="summary-card">
                <div class="label">Low</div>
                <div class="value success">{severity_counts['Low']}</div>
            </div>
        </div>
    </div>
"""
    
    def _create_detailed_findings_table(self, findings: List[Dict]) -> str:
        """Create detailed findings table."""
        if not findings:
            return """
    <div class="section">
        <h2 class="section-title">Detailed Findings</h2>
        <p style="color: #94a3b8;">No security findings detected. All controls passed or were not tested.</p>
    </div>
"""
        
        rows_html = ""
        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "Medium")
            cvss = finding.get("cvss", 5.0)
            title = finding.get("title", "Unknown Issue")
            description = finding.get("description", "No description available")
            target = finding.get("target", "N/A")
            remediation = finding.get("remediation", "Review security best practices")
            module = finding.get("module", "?")
            
            rows_html += f"""
            <tr>
                <td style="font-weight: 600; color: #cbd5e1;">#{i}</td>
                <td>
                    <div style="font-weight: 600; color: #f1f5f9; margin-bottom: 5px;">{title}</div>
                    <div style="font-size: 0.9em; color: #94a3b8;">{description}</div>
                </td>
                <td>
                    <span class="severity-badge severity-{severity.lower()}">{severity}</span>
                </td>
                <td>
                    <span class="cvss-score">{cvss:.1f}</span>
                </td>
                <td style="font-size: 0.9em; color: #94a3b8;">Module {module}</td>
                <td style="font-size: 0.85em; color: #94a3b8; max-width: 300px;">{remediation}</td>
            </tr>
"""
        
        return f"""
    <div class="section">
        <h2 class="section-title">Detailed Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Module</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
"""
    
    def _create_module_details(self, modules: Dict[str, Any]) -> str:
        """Create module details section."""
        module_names = {
            "1": "Input & Data Validation",
            "2": "Authentication",
            "3": "Authorization",
            "4": "Sensitive Data Protection",
            "5": "Session Management",
            "6": "Logging & Monitoring",
            "7": "API Security",
            "8": "Infrastructure & Containers"
        }
        
        cards_html = ""
        for module_num in sorted(modules.keys(), key=lambda x: int(x)):
            module_data = modules[module_num]
            name = module_names.get(module_num, f"Module {module_num}")
            success = module_data.get("success", False)
            findings_count = len(module_data.get("findings", []))
            controls = module_data.get("controls", {})
            
            passed = sum(1 for v in controls.values() if v == "pass")
            failed = sum(1 for v in controls.values() if v == "fail")
            
            # Get failed control names
            failed_controls = [k.replace("_", " ").title() for k, v in controls.items() if v == "fail"]
            failed_controls_html = ""
            if failed_controls:
                failed_list = ", ".join(failed_controls)  # Show ALL
                failed_controls_html = f"""
                    <div style="margin-top: 10px; padding: 10px; background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; border-radius: 4px;">
                        <div style="font-size: 0.85em; color: #fca5a5; font-weight: 600; margin-bottom: 5px;">Failed Controls:</div>
                        <div style="font-size: 0.8em; color: #fecaca;">{failed_list}</div>
                    </div>
"""
            
            # Check for errors or missing inputs
            error_html = ""
            total_controls = passed + failed
            if total_controls == 0 and not success:
                # Module failed with no controls tested
                error_html = f"""
                    <div style="margin-top: 10px; padding: 10px; background: rgba(239, 68, 68, 0.15); border-left: 3px solid #ef4444; border-radius: 4px;">
                        <div style="font-size: 0.85em; color: #fca5a5; font-weight: 600; margin-bottom: 5px;">⚠ Module Error</div>
                        <div style="font-size: 0.8em; color: #fecaca;">Module failed to execute. Check logs for details.</div>
                    </div>
"""
            elif total_controls == 0 and success:
                # Module succeeded but no controls tested (missing inputs)
                error_html = f"""
                    <div style="margin-top: 10px; padding: 10px; background: rgba(245, 158, 11, 0.15); border-left: 3px solid #f59e0b; border-radius: 4px;">
                        <div style="font-size: 0.85em; color: #fbbf24; font-weight: 600; margin-bottom: 5px;">⚠ Missing Inputs</div>
                        <div style="font-size: 0.8em; color: #fcd34d;">No targets found. Module needs specific input files (logs, configs, etc.)</div>
                    </div>
"""

            
            status_class = "status-success" if success else "status-failed"
            status_text = "Completed" if success else "Failed"
            status_icon = "●" if success else "●"
            
            cards_html += f"""
            <div class="module-card">
                <div class="module-header">
                    <div class="module-number">{module_num}</div>
                    <div class="module-name">{name}</div>
                </div>
                <div style="color: #94a3b8; margin-bottom: 15px;">
                    <div>Findings: <strong style="color: #f1f5f9;">{findings_count}</strong></div>
                    <div>Controls: <strong style="color: #10b981;">{passed} Passed</strong> • <strong style="color: #ef4444;">{failed} Failed</strong></div>
                </div>
                {failed_controls_html}
                {error_html}
                <div class="module-status {status_class}">
                    <span>{status_icon}</span>
                    <span>{status_text}</span>
                </div>
            </div>
"""
        
        return f"""
    <div class="section">
        <h2 class="section-title">Module Details</h2>
        <div class="module-grid">
            {cards_html}
        </div>
    </div>
"""
    
    def _create_enhanced_footer(self, results: Dict[str, Any]) -> str:
        """Create enhanced footer."""
        return """
    <div class="footer">
        <div class="footer-logo">Security GAP Analysis System</div>
        <p style="margin: 10px 0;">Automated Security Testing Across 8 Modules • 65 Controls</p>
        <p style="font-size: 0.9em; margin-top: 15px; opacity: 0.7;">
            Version 1.0.0 • Powered by Advanced Security Analytics
        </p>
    </div>
"""
    
    def _get_enhanced_scripts(
        self,
        controls_summary: Dict[str, int],
        findings: List[Dict],
        modules: Dict[str, Any]
    ) -> str:
        """Get enhanced JavaScript with Chart.js initialization."""
        # Prepare data for charts
        passed = controls_summary.get("passed", 0)
        failed = controls_summary.get("failed", 0)
        not_tested = controls_summary.get("not_tested", 0)
        
        # Count findings by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            severity = finding.get("severity", "Medium")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Module performance data
        module_names = {
            "1": "Input Validation",
            "2": "Authentication",
            "3": "Authorization",
            "4": "Data Protection",
            "5": "Session Mgmt",
            "6": "Logging",
            "7": "API Security",
            "8": "Infrastructure"
        }
        
        module_labels = []
        module_passed = []
        module_failed = []
        
        for module_num in sorted(modules.keys(), key=lambda x: int(x)):
            module_data = modules[module_num]
            controls = module_data.get("controls", {})
            module_labels.append(module_names.get(module_num, f"Module {module_num}"))
            module_passed.append(sum(1 for v in controls.values() if v == "pass"))
            module_failed.append(sum(1 for v in controls.values() if v == "fail"))
        
        return f"""
    <script>
        console.log('Security GAP Analysis Dashboard loaded');
        
        // Chart.js default configuration
        Chart.defaults.color = '#cbd5e1';
        Chart.defaults.borderColor = '#475569';
        Chart.defaults.font.family = "'Inter', sans-serif";
        
        // Control Status Donut Chart
        const controlsCtx = document.getElementById('controlsChart');
        if (controlsCtx) {{
            new Chart(controlsCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Passed', 'Failed', 'Not Tested'],
                    datasets: [{{
                        data: [{passed}, {failed}, {not_tested}],
                        backgroundColor: [
                            'rgba(16, 185, 129, 0.8)',  // Green
                            'rgba(239, 68, 68, 0.8)',   // Red
                            'rgba(59, 130, 246, 0.8)'   // Blue
                        ],
                        borderColor: [
                            'rgba(16, 185, 129, 1)',
                            'rgba(239, 68, 68, 1)',
                            'rgba(59, 130, 246, 1)'
                        ],
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 15,
                                font: {{
                                    size: 12
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = {passed + failed + not_tested};
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return label + ': ' + value + ' (' + percentage + '%)';
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // Risk Distribution Bar Chart
        const riskCtx = document.getElementById('riskChart');
        if (riskCtx) {{
            new Chart(riskCtx, {{
                type: 'bar',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        label: 'Number of Findings',
                        data: [{severity_counts['Critical']}, {severity_counts['High']}, {severity_counts['Medium']}, {severity_counts['Low']}],
                        backgroundColor: [
                            'rgba(220, 38, 38, 0.8)',   // Critical - Red
                            'rgba(245, 158, 11, 0.8)',  // High - Orange
                            'rgba(59, 130, 246, 0.8)',  // Medium - Blue
                            'rgba(16, 185, 129, 0.8)'   // Low - Green
                        ],
                        borderColor: [
                            'rgba(220, 38, 38, 1)',
                            'rgba(245, 158, 11, 1)',
                            'rgba(59, 130, 246, 1)',
                            'rgba(16, 185, 129, 1)'
                        ],
                        borderWidth: 2,
                        borderRadius: 8
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1
                            }},
                            grid: {{
                                color: '#334155'
                            }}
                        }},
                        x: {{
                            grid: {{
                                display: false
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    return 'Findings: ' + context.parsed.y;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // Severity Pie Chart
        const severityCtx = document.getElementById('severityChart');
        if (severityCtx) {{
            new Chart(severityCtx, {{
                type: 'pie',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        data: [{severity_counts['Critical']}, {severity_counts['High']}, {severity_counts['Medium']}, {severity_counts['Low']}],
                        backgroundColor: [
                            'rgba(220, 38, 38, 0.8)',
                            'rgba(245, 158, 11, 0.8)',
                            'rgba(59, 130, 246, 0.8)',
                            'rgba(16, 185, 129, 0.8)'
                        ],
                        borderColor: [
                            'rgba(220, 38, 38, 1)',
                            'rgba(245, 158, 11, 1)',
                            'rgba(59, 130, 246, 1)',
                            'rgba(16, 185, 129, 1)'
                        ],
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 15,
                                font: {{
                                    size: 12
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    return label + ': ' + value + ' findings';
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // Module Performance Horizontal Bar Chart
        const moduleCtx = document.getElementById('moduleChart');
        if (moduleCtx) {{
            new Chart(moduleCtx, {{
                type: 'bar',
                data: {{
                    labels: {module_labels},
                    datasets: [
                        {{
                            label: 'Passed',
                            data: {module_passed},
                            backgroundColor: 'rgba(16, 185, 129, 0.8)',
                            borderColor: 'rgba(16, 185, 129, 1)',
                            borderWidth: 2,
                            borderRadius: 6
                        }},
                        {{
                            label: 'Failed',
                            data: {module_failed},
                            backgroundColor: 'rgba(239, 68, 68, 0.8)',
                            borderColor: 'rgba(239, 68, 68, 1)',
                            borderWidth: 2,
                            borderRadius: 6
                        }}
                    ]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            stacked: false,
                            ticks: {{
                                stepSize: 1
                            }},
                            grid: {{
                                color: '#334155'
                            }}
                        }},
                        y: {{
                            stacked: false,
                            grid: {{
                                display: false
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 15,
                                font: {{
                                    size: 12
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    return context.dataset.label + ': ' + context.parsed.x + ' controls';
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // Filter functionality
        function filterFindings(severity) {{
            const rows = document.querySelectorAll('.findings-table tbody tr');
            rows.forEach(row => {{
                if (severity === 'all' || row.textContent.includes(severity)) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
        
        // Print functionality
        function printReport() {{
            window.print();
        }}
        
        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
            anchor.addEventListener('click', function (e) {{
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {{
                    target.scrollIntoView({{ behavior: 'smooth' }});
                }}
            }});
        }});
    </script>
"""


if __name__ == "__main__":
    # Test enhanced dashboard
    import sys
    logging.basicConfig(level=logging.INFO)
    
    # Load test results
    if len(sys.argv) > 1:
        results_file = sys.argv[1]
        with open(results_file, 'r') as f:
            results = json.load(f)
    else:
        # Use sample results
        results = {
            "timestamp": datetime.now().isoformat(),
            "execution_time": 280.66,
            "summary": {
                "total_modules": 8,
                "successful_modules": 8,
                "failed_modules": 0
            },
            "module_results": {
                "1": {
                    "success": True,
                    "module": "Input & Data Validation",
                    "output_file": "outputs/input_and_data_validation_analyzer.json"
                }
            }
        }
    
    generator = DashboardGenerator(debug=True)
    output_path = generator.generate_dashboard(results)
    print(f"\n✅ Enhanced dashboard generated: {output_path}")
