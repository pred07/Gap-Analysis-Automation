#!/usr/bin/env python3
"""
Module 8: Infrastructure & Container Analyzer.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Optional

from common import BaseModule, ModuleResult, load_config
from common.helpers import timestamp_utc
from module8_infrastructure.controls import (
    ControlResult,
    run_container_runtime_security,
    run_container_security,
    run_dos_protection_infrastructure,
    run_host_hardening,
    run_least_privilege,
    run_security_updates,
)


class Module8Analyzer(BaseModule):
    module_number = 8

    def __init__(
        self,
        config=None,
        target: Optional[str] = None,
        document_path: Optional[str] = None,
        debug: bool = False,
    ):
        super().__init__(config=config, target=target, debug=debug)
        self.document_path = document_path
        self.documents = self._load_documents()

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
                if file_path.is_file() and file_path.suffix.lower() in [".pdf", ".docx", ".txt", ".md", ".yaml", ".yml"]:
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
            if file_path.suffix.lower() in [".txt", ".md", ".yaml", ".yml"]:
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
        self.logger.log_section("MODULE 8: INFRASTRUCTURE & CONTAINER ANALYZER")
        
        # Run all 6 controls
        control_results: List[ControlResult] = []
        control_results.append(run_host_hardening(self.documents, self.logger))
        control_results.append(run_container_security(self.documents, self.logger))
        control_results.append(run_container_runtime_security(self.documents, self.logger))
        control_results.append(run_least_privilege(self.documents, self.logger))
        control_results.append(run_dos_protection_infrastructure(self.documents, self.logger))
        control_results.append(run_security_updates(self.documents, self.logger))

        controls_map = {result.name: result.status for result in control_results}
        findings = []
        for result in control_results:
            findings.extend(result.findings)

        evidence = {
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
    parser = argparse.ArgumentParser(description="Module 8: Infrastructure & Container Analyzer")
    parser.add_argument("--target", help="Target URL (optional).")
    parser.add_argument("--document-path", help="Path to documents or directory for policy analysis.")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--config-dir", default="config", help="Config directory.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config_dir)
    analyzer = Module8Analyzer(
        config=config,
        target=args.target,
        document_path=args.document_path,
        debug=args.debug,
    )
    result = analyzer.execute()
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
