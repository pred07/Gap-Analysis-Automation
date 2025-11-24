#!/usr/bin/env python3
"""
Module 1: Input & Data Validation Analyzer.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Optional

import requests
import urllib3

from common import (
    BaseModule,
    ModuleResult,
    NiktoRunner,
    ZAPRunner,
    load_config,
)
from common.helpers import timestamp_utc
from module1_input_validation.controls import (
    run_buffer_overflow,
    run_client_validation,
    run_content_type,
    run_dos,
    run_file_upload,
    run_http_smuggling,
    run_schema_validation,
    run_sql_injection,
    run_xml_validation,
    run_xss,
)
from module1_input_validation.directory_scanner import DirectoryScanner
from module1_input_validation.headers_analyzer import HeadersAnalyzer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Module1Analyzer(BaseModule):
    """Automated analyzer for Module 1."""

    module_number = 1

    def __init__(
        self,
        config=None,
        target: Optional[str] = None,
        target_file: Optional[str] = None,
        debug: bool = False,
        enable_zap: bool = False,
        enable_nikto: bool = True,
        max_depth: int = 2,
        max_endpoints: int = 25,
    ):
        super().__init__(config=config, target=target, debug=debug)
        self.target_file = target_file
        self.enable_zap = enable_zap
        self.enable_nikto = enable_nikto
        self.max_depth = max_depth
        self.max_endpoints = max_endpoints
        self.targets = self._load_targets()
        self.scan_results: List[Dict] = []
        discovery_config = self.config.get("modules.module1.discovery", {}) or {}
        self.discovery_depth = discovery_config.get("depth", self.max_depth)
        self.discovery_limit = discovery_config.get("max_endpoints", self.max_endpoints)
        self.wordlist_enabled = discovery_config.get("smart_wordlist", True)
        fuzz_config = self.config.get("modules.module1.fuzz", {}) or {}
        self.fuzz_payloads = fuzz_config.get("max_payloads", 5)
        dos_config = self.config.get("modules.module1.dos", {}) or {}
        self.dos_enabled = dos_config.get("enabled", False)
        self.dos_requests = dos_config.get("requests", 10)
        self.dos_concurrency = dos_config.get("concurrency", 5)

    # ------------------------------------------------------------------ #
    def _load_targets(self) -> List[str]:
        candidates: List[str] = []
        if self.target:
            candidates.append(self.target)
        if self.target_file:
            path = Path(self.target_file)
            if not path.exists():
                raise FileNotFoundError(f"Target list file not found: {path}")
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    url = line.strip()
                    if url and not url.startswith("#"):
                        candidates.append(url)
        if not candidates:
            raise ValueError("No targets supplied. Provide --target or --target-file.")
        # Remove duplicates while preserving order
        seen = set()
        unique_targets = []
        for url in candidates:
            if url not in seen:
                seen.add(url)
                unique_targets.append(url)
        return unique_targets

    # ------------------------------------------------------------------ #
    def execute(self) -> ModuleResult:
        self.logger.log_section("MODULE 1: INPUT & DATA VALIDATION")
        self.logger.info(f"Targets to scan: {len(self.targets)}")
        self.logger.info(f"Discovery depth: {self.discovery_depth}")

        target_records: List[Dict] = []
        for target in self.targets:
            self.logger.log_subsection(f"Target: {target}")
            record = self._scan_target(target)
            target_records.append(record)

        overall_summary = self._overall_summary(target_records)
        payload = {
            "module": self.module_name,
            "module_number": self.module_number,
            "timestamp": timestamp_utc(),
            "targets": target_records,
            "summary": overall_summary,
        }
        output_file = self.writer.write_payload(self.module_name, payload)
        self.logger.info(f"Module output written to {output_file}")
        return ModuleResult(True, self.module_name, self.module_number, output_file, {"summary": overall_summary})

    # ------------------------------------------------------------------ #
    def _scan_target(self, target: str) -> Dict:
        header_analyzer = HeadersAnalyzer(self.logger)
        header_result = header_analyzer.analyze(target)

        discovery_engine = DirectoryScanner(
            self.logger,
            max_depth=self.discovery_depth,
            max_endpoints=self.discovery_limit,
            wordlist_enabled=self.wordlist_enabled,
        )
        discovery = discovery_engine.scan(target)
        endpoints = discovery["endpoints"]

        session = self._build_session()
        control_results = []
        control_results.append(run_sql_injection(endpoints, session, self.logger, self.fuzz_payloads))
        control_results.append(run_xss(endpoints, session, self.logger))
        control_results.append(run_http_smuggling(target, self.logger))
        control_results.append(run_client_validation(endpoints, session, self.logger))
        control_results.append(run_file_upload(endpoints, session, self.logger))
        control_results.append(run_xml_validation(endpoints, session, self.logger))
        control_results.append(run_schema_validation(endpoints, session, self.logger))
        control_results.append(run_content_type(endpoints, self.logger))
        control_results.append(run_buffer_overflow(endpoints, session, self.logger))
        control_results.append(
            run_dos(
                endpoints,
                session_factory=self._build_session,
                logger=self.logger,
                enabled=self.dos_enabled,
                max_requests=self.dos_requests,
                concurrency=self.dos_concurrency,
            )
        )

        controls_map = {result.name: result.status for result in control_results}
        findings = []
        for result in control_results:
            findings.extend(result.findings)

        tool_results = self._run_tools(target)
        if tool_results.get("zap", {}).get("output_file"):
            findings.append({"control": "ZAP", "report": tool_results["zap"]["output_file"]})
        if tool_results.get("nikto", {}).get("output_file"):
            findings.append({"control": "Nikto", "report": tool_results["nikto"]["output_file"]})

        summary = self._control_summary(controls_map)
        evidence = {
            "header_analysis": header_result,
            "endpoints": endpoints,
            "sensitive_files": discovery["sensitive_files"],
            "classifications": discovery["classifications"],
            "findings": findings,
            "reports": self._collect_reports(tool_results),
        }

        return {
            "target": target,
            "controls": controls_map,
            "evidence": evidence,
            "summary": summary,
            "findings": findings,
        }

    # ------------------------------------------------------------------ #
    def _run_tools(self, target: str) -> Dict[str, Dict]:
        results = {}
        tool_paths = self.config.get_all_tool_paths()

        if self.enable_zap and tool_paths.get("zap"):
            zap_runner = ZAPRunner(tool_paths["zap"], logger=self.logger)
            zap_report = Path(self.config.get_output_dir()) / "module1_zap.xml"
            zap_result = zap_runner.quick_scan(target, str(zap_report))
            results["zap"] = zap_result
            if zap_result.get("returncode") == 0:
                self.evidence["reports"].append(str(zap_report))
        elif self.enable_zap:
            self.logger.warning("ZAP requested but path not configured.")

        if self.enable_nikto and tool_paths.get("nikto"):
            nikto_runner = NiktoRunner(tool_paths["nikto"], logger=self.logger)
            nikto_report = Path(self.config.get_output_dir()) / "module1_nikto.txt"
            nikto_result = nikto_runner.scan(target, str(nikto_report))
            results["nikto"] = nikto_result
            if nikto_result.get("returncode") == 0:
                self.evidence["reports"].append(str(nikto_report))
        elif self.enable_nikto:
            self.logger.warning("Nikto requested but path not configured.")

        return results

    def _collect_reports(self, tool_results: Dict[str, Dict]) -> List[str]:
        reports = []
        for tool_name in ["zap", "nikto"]:
            output = tool_results.get(tool_name, {}).get("output_file")
            if output:
                reports.append(output)
        return reports

    def _build_session(self):
        session = requests.Session()
        session.verify = False
        session.headers.update({"User-Agent": "Module1-Analyzer"})
        return session

    def _control_summary(self, controls: Dict[str, str]) -> Dict[str, int]:
        total = len(controls)
        passed = sum(1 for status in controls.values() if status == "pass")
        failed = sum(1 for status in controls.values() if status == "fail")
        not_tested = total - passed - failed
        return {"total": total, "passed": passed, "failed": failed, "not_tested": not_tested}

    def _overall_summary(self, targets: List[Dict]) -> Dict[str, int]:
        total_controls = len(targets) * 10
        passed = sum(t["summary"]["passed"] for t in targets)
        failed = sum(t["summary"]["failed"] for t in targets)
        not_tested = sum(t["summary"]["not_tested"] for t in targets)
        return {
            "total_controls": total_controls,
            "passed": passed,
            "failed": failed,
            "not_tested": not_tested,
        }


# ---------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Module 1: Input & Data Validation Analyzer")
    parser.add_argument("--target", help="Single target URL override.")
    parser.add_argument("--target-file", help="File containing list of URLs (one per line).")
    parser.add_argument("--depth", type=int, default=2, help="Directory discovery depth.")
    parser.add_argument("--max-endpoints", type=int, default=25, help="Max endpoints to fuzz per target.")
    parser.add_argument("--enable-zap", action="store_true", help="Enable OWASP ZAP quick scan.")
    parser.add_argument("--enable-nikto", action="store_true", help="Enable Nikto scan.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("--config-dir", default="config", help="Path to config directory.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config_dir)
    analyzer = Module1Analyzer(
        config=config,
        target=args.target or config.get_target_url(),
        target_file=args.target_file,
        debug=args.debug,
        enable_zap=args.enable_zap,
        enable_nikto=args.enable_nikto,
        max_depth=args.depth,
        max_endpoints=args.max_endpoints,
    )
    result = analyzer.execute()
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())

