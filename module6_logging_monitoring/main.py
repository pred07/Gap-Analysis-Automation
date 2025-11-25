#!/usr/bin/env python3
"""
Module 6: Logging & Monitoring Analyzer.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Optional

from common import BaseModule, ModuleResult, load_config
from common.helpers import timestamp_utc
from module6_logging_monitoring.controls import (
    ControlResult,
    run_access_logging,
    run_audit_trail_completeness,
    run_authentication_logging,
    run_authorization_logging,
    run_error_logging,
    run_log_integrity,
    run_log_retention,
    run_security_event_logging,
)
from module6_logging_monitoring.discovery import LogDiscovery


class Module6Analyzer(BaseModule):
    module_number = 6

    def __init__(
        self,
        config=None,
        target: Optional[str] = None,
        log_path: Optional[str] = None,
        document_path: Optional[str] = None,
        debug: bool = False,
    ):
        super().__init__(config=config, target=target, debug=debug)
        self.log_path = log_path
        self.document_path = document_path
        self.log_files = self._load_log_files()
        self.documents = self._load_documents()

    def _load_log_files(self) -> List[Dict]:
        """Load log files for analysis."""
        log_files = []
        if not self.log_path:
            return log_files

        log_dir = Path(self.log_path)
        if not log_dir.exists():
            self.logger.warning(f"Log path does not exist: {log_dir}")
            return log_files

        # If it's a directory, scan for log files
        if log_dir.is_dir():
            for file_path in log_dir.glob("**/*"):
                if file_path.is_file() and file_path.suffix.lower() in [".log", ".txt", ""]:
                    content = self._read_log_file(file_path)
                    if content:
                        log_files.append({"name": file_path.name, "path": str(file_path), "content": content})
        else:
            # Single file
            content = self._read_log_file(log_dir)
            if content:
                log_files.append({"name": log_dir.name, "path": str(log_dir), "content": content})

        self.logger.info(f"Loaded {len(log_files)} log files for analysis")
        return log_files

    def _read_log_file(self, file_path: Path) -> str:
        """Read log file content."""
        try:
            # Read first 100KB of log file (to avoid memory issues with large logs)
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(100000)
        except Exception as e:
            self.logger.warning(f"Error reading log file {file_path}: {e}")
        return ""

    def _load_documents(self) -> List[Dict]:
        """Load documents for policy analysis."""
        documents = []
        if not self.document_path:
            return documents

        doc_path = Path(self.document_path)
        if not doc_path.exists():
            self.logger.warning(f"Document path does not exist: {doc_path}")
            return documents

        # If it's a directory, scan for documents
        if doc_path.is_dir():
            for file_path in doc_path.glob("**/*"):
                if file_path.is_file() and file_path.suffix.lower() in [".pdf", ".docx", ".txt", ".md"]:
                    content = self._extract_document_content(file_path)
                    if content:
                        documents.append({"name": file_path.name, "path": str(file_path), "content": content})
        else:
            # Single file
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
                        text = ""
                        for page in reader.pages:
                            text += page.extract_text() + "\n"
                        return text
                except Exception as e:
                    self.logger.warning(f"Failed to extract PDF content from {file_path}: {e}")
                    return ""
            elif file_path.suffix.lower() == ".docx":
                try:
                    import docx
                    doc = docx.Document(file_path)
                    return "\n".join([para.text for para in doc.paragraphs])
                except Exception as e:
                    self.logger.warning(f"Failed to extract DOCX content from {file_path}: {e}")
                    return ""
        except Exception as e:
            self.logger.warning(f"Error reading document {file_path}: {e}")
        return ""

    def execute(self) -> ModuleResult:
        self.logger.log_section("MODULE 6: LOGGING & MONITORING ANALYZER")
        
        # If no log files or documents provided, try to discover from target
        if not self.log_files and self.target:
            self.logger.info("No log files provided, attempting discovery from target")
            discovery = LogDiscovery(self.logger).discover(self.target)
            self.log_files = discovery.get("log_files", [])
        
        # Run all 8 controls
        control_results: List[ControlResult] = []
        control_results.append(run_authentication_logging(self.log_files, self.logger))
        control_results.append(run_authorization_logging(self.log_files, self.logger))
        control_results.append(run_access_logging(self.log_files, self.logger))
        control_results.append(run_error_logging(self.log_files, self.logger))
        control_results.append(run_security_event_logging(self.log_files, self.logger))
        control_results.append(run_audit_trail_completeness(self.log_files, self.logger))
        control_results.append(run_log_integrity(self.log_files, self.documents, self.logger))
        control_results.append(run_log_retention(self.log_files, self.documents, self.logger))

        controls_map = {result.name: result.status for result in control_results}
        findings = []
        for result in control_results:
            findings.extend(result.findings)

        evidence = {
            "log_files": [{"name": lf["name"], "path": lf["path"]} for lf in self.log_files],
            "documents": [{"name": d["name"], "path": d["path"]} for d in self.documents],
            "findings": findings,
        }
        
        summary = self._control_summary(controls_map)
        
        payload = {
            "module": self.module_name,
            "module_number": self.module_number,
            "timestamp": timestamp_utc(),
            "controls": controls_map,
            "evidence": evidence,
            "summary": summary,
        }
        
        output_file = self.writer.write_payload(self.module_name, payload)
        self.logger.info(f"Module output written to {output_file}")
        return ModuleResult(True, self.module_name, self.module_number, output_file, {"summary": summary})

    def _control_summary(self, controls: Dict[str, str]) -> Dict[str, int]:
        total = len(controls)
        passed = sum(1 for status in controls.values() if status == "pass")
        failed = sum(1 for status in controls.values() if status == "fail")
        not_tested = total - passed - failed
        return {"total": total, "passed": passed, "failed": failed, "not_tested": not_tested}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Module 6: Logging & Monitoring Analyzer")
    parser.add_argument("--target", help="Target URL for log discovery.")
    parser.add_argument("--log-path", help="Path to log files or directory.")
    parser.add_argument("--document-path", help="Path to documents or directory for policy analysis.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--config-dir", default="config", help="Config directory.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config_dir)
    analyzer = Module6Analyzer(
        config=config,
        target=args.target or config.get_target_url(),
        log_path=args.log_path,
        document_path=args.document_path,
        debug=args.debug,
    )
    result = analyzer.execute()
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
