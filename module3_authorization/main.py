#!/usr/bin/env python3
"""
Module 3: Authorization Analyzer.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Optional

import requests
import urllib3

from common import BaseModule, ModuleResult, load_config
from common.helpers import timestamp_utc
from module3_authorization.controls import (
    ControlResult,
    run_api_authorization,
    run_database_permission_controls,
    run_os_access_restrictions,
    run_rbac,
    run_user_state_management,
)
from module3_authorization.discovery import AuthzDiscovery

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Module3Analyzer(BaseModule):
    module_number = 3

    def __init__(
        self,
        config=None,
        target: Optional[str] = None,
        target_file: Optional[str] = None,
        debug: bool = False,
        max_depth: int = 2,
        max_pages: int = 60,
    ):
        super().__init__(config=config, target=target, debug=debug)
        self.target_file = target_file
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.targets = self._load_targets()
        self.credentials = self.config.get("credentials", {})

    def _load_targets(self) -> List[str]:
        candidates: List[str] = []
        if self.target:
            candidates.append(self.target)
        if self.target_file:
            path = Path(self.target_file)
            if not path.exists():
                raise FileNotFoundError(f"Target list file not found: {path}")
            candidates.extend(
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            )
        return list(dict.fromkeys(candidates))

    def execute(self) -> ModuleResult:
        self.logger.log_section("MODULE 3: AUTHORIZATION ANALYZER")
        target_records = []
        for target in self.targets:
            self.logger.log_subsection(f"Target: {target}")
            record = self._analyze_target(target)
            target_records.append(record)

        summary = self._overall_summary(target_records)
        payload = {
            "module": self.module_name,
            "module_number": self.module_number,
            "timestamp": timestamp_utc(),
            "targets": target_records,
            "summary": summary,
        }
        output_file = self.writer.write_payload(self.module_name, payload)
        self.logger.info(f"Module output written to {output_file}")
        return ModuleResult(True, self.module_name, self.module_number, output_file, {"summary": summary})

    def _analyze_target(self, target: str) -> Dict:
        discovery = AuthzDiscovery(self.logger, max_depth=self.max_depth, max_pages=self.max_pages).crawl(target)
        pages = discovery["pages"]
        protected_pages = discovery["protected_pages"]
        api_endpoints = discovery["api_endpoints"]

        control_results: List[ControlResult] = []
        control_results.append(run_rbac(pages, self._build_session, self.logger))
        control_results.append(run_user_state_management(protected_pages, self._build_session, self.logger))
        control_results.append(run_database_permission_controls(pages, self._build_session, self.logger))
        control_results.append(run_os_access_restrictions(pages, self._build_session, self.logger))
        control_results.append(run_api_authorization(api_endpoints, self._build_session, self.credentials, self.logger))

        controls_map = {result.name: result.status for result in control_results}
        findings = []
        for result in control_results:
            findings.extend(result.findings)

        evidence = {
            "pages": pages,
            "protected_pages": protected_pages,
            "api_endpoints": api_endpoints,
            "findings": findings,
        }
        summary = self._control_summary(controls_map)
        return {"target": target, "controls": controls_map, "evidence": evidence, "summary": summary}

    def _build_session(self):
        session = requests.Session()
        session.verify = False
        session.headers.update({"User-Agent": "Module3-Analyzer"})
        return session

    def _control_summary(self, controls: Dict[str, str]) -> Dict[str, int]:
        total = len(controls)
        passed = sum(1 for status in controls.values() if status == "pass")
        failed = sum(1 for status in controls.values() if status == "fail")
        not_tested = total - passed - failed
        return {"total": total, "passed": passed, "failed": failed, "not_tested": not_tested}

    def _overall_summary(self, targets: List[Dict]) -> Dict[str, int]:
        total_controls = len(targets) * 5
        passed = sum(t["summary"]["passed"] for t in targets)
        failed = sum(t["summary"]["failed"] for t in targets)
        not_tested = sum(t["summary"]["not_tested"] for t in targets)
        return {
            "total_controls": total_controls,
            "passed": passed,
            "failed": failed,
            "not_tested": not_tested,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Module 3: Authorization Analyzer")
    parser.add_argument("--target", help="Single base URL.")
    parser.add_argument("--target-file", help="File with base URLs (one per line).")
    parser.add_argument("--depth", type=int, default=2, help="Discovery depth.")
    parser.add_argument("--max-pages", type=int, default=60, help="Maximum number of pages to crawl.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--config-dir", default="config", help="Config directory.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config_dir)
    analyzer = Module3Analyzer(
        config=config,
        target=args.target or config.get_target_url(),
        target_file=args.target_file,
        debug=args.debug,
        max_depth=args.depth,
        max_pages=args.max_pages,
    )
    result = analyzer.execute()
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())

