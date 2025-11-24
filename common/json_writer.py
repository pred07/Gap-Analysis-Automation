"""
JSON output utilities with schema enforcement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable

from .helpers import ensure_dir, slugify, timestamp_utc
from .schema_validator import validate_final_report, validate_module_output


class JSONWriter:
    def __init__(self, output_dir: str | Path = "outputs"):
        self.output_dir = ensure_dir(output_dir)

    # ------------------------------------------------------------------ #
    def write_module_output(
        self,
        module_name: str,
        controls: Dict[str, str],
        evidence: Dict[str, Any],
        target: str | None = None,
        module_number: int | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> str:
        summary = self._calc_summary(controls)
        payload = {
            "module": module_name,
            "module_number": module_number,
            "timestamp": timestamp_utc(),
            "target": target,
            "controls": controls,
            "evidence": evidence,
            "summary": summary,
        }
        if metadata:
            payload["metadata"] = metadata

        return self.write_payload(module_name, payload)

    def write_payload(self, module_name: str, payload: Dict[str, Any]) -> str:
        validate_module_output(payload)
        filename = f"{slugify(module_name)}.json"
        path = self.output_dir / filename
        self._write(path, payload)
        return str(path)

    # ------------------------------------------------------------------ #
    def merge_outputs(self, files: Iterable[str | Path], out: str = "final_report.json") -> str:
        merged = {
            "report_type": "Security GAP Analysis",
            "generated_at": timestamp_utc(),
            "modules": {},
            "overall_summary": {"total_controls": 0, "passed": 0, "failed": 0, "not_tested": 0},
        }

        for file_path in files:
            path = Path(file_path)
            if not path.exists():
                continue
            data = self.read_json(path)
            validate_module_output(data)
            module_key = data.get("module") or path.stem
            merged["modules"][module_key] = data
            summary = data.get("summary", {})
            merged["overall_summary"]["total_controls"] += summary.get("total", 0)
            merged["overall_summary"]["passed"] += summary.get("passed", 0)
            merged["overall_summary"]["failed"] += summary.get("failed", 0)
            merged["overall_summary"]["not_tested"] += summary.get("not_tested", 0)

        total = merged["overall_summary"]["total_controls"]
        if total:
            merged["overall_summary"]["pass_rate"] = round(
                (merged["overall_summary"]["passed"] / total) * 100,
                2,
            )

        validate_final_report(merged)
        path = self.output_dir / out
        self._write(path, merged)
        return str(path)

    # ------------------------------------------------------------------ #
    def read_json(self, path: str | Path) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write(self, path: Path, data: Dict[str, Any]) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def _calc_summary(self, controls: Dict[str, str]) -> Dict[str, Any]:
        total = len(controls)
        passed = sum(1 for v in controls.values() if v == "pass")
        failed = sum(1 for v in controls.values() if v == "fail")
        not_tested = sum(1 for v in controls.values() if v not in {"pass", "fail"})

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "not_tested": not_tested,
            "pass_rate": round((passed / total) * 100, 2) if total else 0.0,
        }


def write_module_output(*args, **kwargs) -> str:
    return JSONWriter(kwargs.pop("output_dir", "outputs")).write_module_output(*args, **kwargs)


def merge_outputs(files: Iterable[str | Path], output_dir: str | Path = "outputs") -> str:
    return JSONWriter(output_dir).merge_outputs(files)

