#!/usr/bin/env python3
"""
Module 7: API Security Analyzer.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Optional

import requests
import urllib3

from common import BaseModule, ModuleResult, load_config
from common.helpers import timestamp_utc
from module7_api_security.controls import (
    ControlResult,
    run_api_authentication_validation,
    run_api_cors_configuration,
    run_api_error_handling,
    run_api_input_validation,
    run_api_method_security,
    run_api_rate_limiting,
    run_api_sensitive_params,
    run_api_versioning,
    run_secure_coding_evidence,
    run_third_party_components,
)
from module7_api_security.discovery import APIDiscovery

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Module7Analyzer(BaseModule):
    module_number = 7

    def __init__(
        self,
        config=None,
        target: Optional[str] = None,
        target_file: Optional[str] = None,
        document_path: Optional[str] = None,
        debug: bool = False,
        max_depth: int = 2,
        max_pages: int = 40,
    ):
        super().__init__(config=config, target=target, debug=debug)
        self.target_file = target_file
        self.document_path = document_path
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.targets = self._load_targets()
        self.documents = self._load_documents()
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

    def _load_documents(self) -> List[Dict]:
        """Load documents for policy analysis."""
        documents = []
        if not self.document_path:
            return documents

        doc_path = Path(self.document_path)
        if not doc_path.exists():
            self.logger.warning(f"Document path does not exist: {doc_path}")
            return documents

        if doc_path.is_dir():
            for file_path in doc_path.glob("**/*"):
                if file_path.is_file() and file_path.suffix.lower() in [".pdf", ".docx", ".txt", ".md"]:
                    content = self._extract_document_content(file_path)
                    if content:
                        documents.append({"name": file_path.name, "path": str(file_path), "content": content})
        else:
            content = self._extract_document_content(doc_path)
            if content:
                documents.append({"name": doc_path.name, "path": str(doc_path), "content": content})

        self.logger.info(f"Loaded {len(documents)} documents for analysis")
        return documents

    def _extract_document_content(self, file_path: Path) -> str:
        """Extract text content from document."""
        try:
            if file_path.suffix.lower() in [".txt", ".md"]:
                return file_path.read_text(encoding="utf-8", errors="ignore")
            elif file_path.suffix.lower() == ".pdf":
                try:
                    import PyPDF2
                    with open(file_path, "rb") as f:
                        reader = PyPDF2.PdfReader(f)
                        return "\n".join([page.extract_text() for page in reader.pages])
                except Exception as e:
                    self.logger.warning(f"Failed to extract PDF: {e}")
            elif file_path.suffix.lower() == ".docx":
                try:
                    import docx
                    doc = docx.Document(file_path)
                    return "\n".join([para.text for para in doc.paragraphs])
                except Exception as e:
                    self.logger.warning(f"Failed to extract DOCX: {e}")
        except Exception as e:
            self.logger.warning(f"Error reading document {file_path}: {e}")
        return ""

    def execute(self) -> ModuleResult:
        self.logger.log_section("MODULE 7: API SECURITY ANALYZER")
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
        # Run API discovery
        discovery = APIDiscovery(self.logger, max_depth=self.max_depth, max_pages=self.max_pages).discover(target)
        api_endpoints = discovery["api_endpoints"]

        # Run all 10 controls
        control_results: List[ControlResult] = []
        control_results.append(run_api_method_security(api_endpoints, self._build_session, self.logger))
        control_results.append(run_api_rate_limiting(api_endpoints, self._build_session, self.logger))
        control_results.append(run_api_input_validation(api_endpoints, self._build_session, self.logger))
        control_results.append(run_api_authentication_validation(api_endpoints, self._build_session, self.credentials, self.logger))
        control_results.append(run_api_sensitive_params(api_endpoints, self._build_session, self.logger))
        control_results.append(run_api_error_handling(api_endpoints, self._build_session, self.logger))
        control_results.append(run_api_cors_configuration(api_endpoints, self._build_session, self.logger))
        control_results.append(run_api_versioning(api_endpoints, self.logger))
        control_results.append(run_secure_coding_evidence(self.documents, self.logger))
        control_results.append(run_third_party_components(self.documents, self.logger))

        controls_map = {result.name: result.status for result in control_results}
        findings = []
        for result in control_results:
            findings.extend(result.findings)

        evidence = {
            "api_endpoints": api_endpoints,
            "documents": [{"name": d["name"], "path": d["path"]} for d in self.documents],
            "findings": findings,
        }
        summary = self._control_summary(controls_map)
        return {"target": target, "controls": controls_map, "evidence": evidence, "summary": summary}

    def _build_session(self):
        session = requests.Session()
        session.verify = False
        session.headers.update({"User-Agent": "Module7-Analyzer"})
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Module 7: API Security Analyzer")
    parser.add_argument("--target", help="Single base URL.")
    parser.add_argument("--target-file", help="File with base URLs (one per line).")
    parser.add_argument("--document-path", help="Path to documents or directory for policy analysis.")
    parser.add_argument("--depth", type=int, default=2, help="Discovery depth.")
    parser.add_argument("--max-pages", type=int, default=40, help="Maximum number of pages to crawl.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--config-dir", default="config", help="Config directory.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config_dir)
    analyzer = Module7Analyzer(
        config=config,
        target=args.target or config.get_target_url(),
        target_file=args.target_file,
        document_path=args.document_path,
        debug=args.debug,
        max_depth=args.depth,
        max_pages=args.max_pages,
    )
    result = analyzer.execute()
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
