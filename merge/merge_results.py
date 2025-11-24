#!/usr/bin/env python3
"""
Merge individual module JSON outputs into the final report.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from common import ConfigurationError, JSONWriter, load_config


def discover_module_outputs(output_dir: Path) -> List[Path]:
    files = []
    for path in sorted(output_dir.glob("*.json")):
        if path.name.startswith("final_"):
            continue
        files.append(path)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge module outputs.")
    parser.add_argument("--config-dir", default="config", help="Configuration directory.")
    parser.add_argument("--output-dir", default=None, help="Override output directory.")
    parser.add_argument("--outfile", default="final_report.json", help="Merged report filename.")
    args = parser.parse_args()

    try:
        config = load_config(args.config_dir)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}")
        return 2

    output_dir = Path(args.output_dir or config.get_output_dir())
    writer = JSONWriter(output_dir)
    module_files = discover_module_outputs(output_dir)

    if not module_files:
        print(f"No module outputs found in {output_dir}.")
        return 1

    final_path = writer.merge_outputs(module_files, out=args.outfile)
    print(f"Final report written to {final_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

