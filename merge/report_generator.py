#!/usr/bin/env python3
"""
Generate human-readable summaries from the merged final report.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

from common import JSONWriter
from common.schema_validator import validate_final_report


def load_report(path: Path) -> Dict:
    writer = JSONWriter(path.parent)
    data = writer.read_json(path)
    validate_final_report(data)
    return data


def render_text(report: Dict) -> str:
    summary = report["overall_summary"]
    lines = [
        "Security GAP Analysis - Phase 1",
        f"Generated at: {report['generated_at']}",
        "",
        "Overall Summary:",
        f"  Total Controls : {summary['total_controls']}",
        f"  Passed         : {summary['passed']}",
        f"  Failed         : {summary['failed']}",
        f"  Not Tested     : {summary['not_tested']}",
        f"  Pass Rate      : {summary.get('pass_rate', 0)}%",
        "",
        "Module Results:",
    ]

    for module_name, module_data in report["modules"].items():
        module_summary = module_data.get("summary", {})
        lines.append(f"- {module_name}: {module_summary.get('passed', 0)}/{module_summary.get('total', 0)} passed")

    return "\n".join(lines)


def render_markdown(report: Dict) -> str:
    summary = report["overall_summary"]
    lines = [
        "# Security GAP Analysis Report",
        f"_Generated at {report['generated_at']}_",
        "",
        "## Overall Summary",
        f"- **Total Controls:** {summary['total_controls']}",
        f"- **Passed:** {summary['passed']}",
        f"- **Failed:** {summary['failed']}",
        f"- **Not Tested:** {summary['not_tested']}",
        f"- **Pass Rate:** {summary.get('pass_rate', 0)}%",
        "",
        "## Modules",
    ]

    for module_name, module_data in report["modules"].items():
        module_summary = module_data.get("summary", {})
        lines.append(f"### {module_name}")
        lines.append(
            f"- Controls: {module_summary.get('passed', 0)}/{module_summary.get('total', 0)} passed"
        )
        lines.append(f"- Evidence: {len(module_data.get('evidence', {}).get('findings', []))} findings")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate text/markdown report.")
    parser.add_argument("--report", default="outputs/final_report.json", help="Path to merged JSON report.")
    parser.add_argument("--format", choices=["text", "markdown"], default="text")
    parser.add_argument("--output", help="Optional output file.")
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"Report not found: {report_path}")
        return 1

    report = load_report(report_path)
    content = render_markdown(report) if args.format == "markdown" else render_text(report)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(content, encoding="utf-8")
        print(f"Report written to {output_path}")
    else:
        print(content)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

