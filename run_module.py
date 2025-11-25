#!/usr/bin/env python3
"""
Module orchestration entry point.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Type

from common import (
    Config,
    ConfigurationError,
    ModuleResult,
    load_config,
)

MODULE_IMPORT_MAP: Dict[int, Tuple[str, str]] = {
    1: ("module1_input_validation.main", "Module1Analyzer"),
    2: ("module2_authentication.main", "Module2Analyzer"),
    3: ("module3_authorization.main", "Module3Analyzer"),
    4: ("module4_sensitive_data.main", "Module4Analyzer"),
    5: ("module5_session_management.main", "Module5Analyzer"),
    6: ("module6_logging_monitoring.main", "Module6Analyzer"),
    7: ("module7_api_security.main", "Module7Analyzer"),
    8: ("module8_infrastructure.main", "Module8Analyzer"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a single GAP Analysis module.")
    parser.add_argument("-m", "--module", type=str, help="Module number or name (e.g., 1 or module1).")
    parser.add_argument("--list", action="store_true", help="List available modules.")
    parser.add_argument("--target", type=str, help="Override target URL for the module.")
    parser.add_argument("--target-file", type=str, help="Path to file containing list of targets (module specific).")
    parser.add_argument("--depth", type=int, help="Discovery depth override (module specific).")
    parser.add_argument("--max-endpoints", type=int, help="Limit of endpoints/pages (module specific).")
    parser.add_argument("--max-pages", type=int, help="Alias for modules expecting page limits.")
    parser.add_argument("--enable-zap", action="store_true", help="Enable OWASP ZAP where supported.")
    parser.add_argument("--enable-nikto", action="store_true", help="Enable Nikto where supported.")
    parser.add_argument("--enable-testssl", action="store_true", help="Enable testssl.sh for Module 4.")
    parser.add_argument("--log-path", type=str, help="Path to log files for Module 6.")
    parser.add_argument("--document-path", type=str, help="Path to documents for Modules 4 and 6.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("--dry-run", action="store_true", help="Only load module without executing tools.")
    parser.add_argument("--config-dir", default="config", help="Path to configuration directory.")
    parser.add_argument("--test", action="store_true", help="Run module in self-test mode, if supported.")
    return parser.parse_args()


def list_modules(config: Config) -> None:
    print("\nAvailable modules:\n")
    for number, (module_path, class_name) in MODULE_IMPORT_MAP.items():
        enabled = "enabled" if config.module_enabled(number) else "disabled"
        try:
            module_info = config.get_module_info(number)
            print(f"  [{number}] {module_info.name} ({enabled}) -> {module_path}:{class_name}")
        except ConfigurationError:
            print(f"  [{number}] UNKNOWN ({enabled}) -> {module_path}:{class_name}")
    print()


def resolve_module_numbers(selection: str | None) -> List[int]:
    if not selection:
        raise ValueError("No module specified. Use --module=<n> or --list.")

    selection = selection.strip().lower()
    if selection in {"all", "*"}:
        return list(MODULE_IMPORT_MAP.keys())

    numbers: List[int] = []
    for part in selection.replace("module", "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            num = int(part)
        except ValueError as exc:
            raise ValueError(f"Invalid module identifier: {part}") from exc

        if num not in MODULE_IMPORT_MAP:
            raise ValueError(f"Module {num} not defined.")
        numbers.append(num)
    return numbers


def load_module_class(module_number: int):
    module_path, class_name = MODULE_IMPORT_MAP[module_number]
    try:
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except (ImportError, AttributeError) as exc:
        raise ConfigurationError(f"Unable to load {class_name} from {module_path}: {exc}") from exc


def instantiate_analyzer(cls, config: Config, args: argparse.Namespace):
    import inspect

    signature = inspect.signature(cls)
    kwargs = {}
    params = signature.parameters

    if "config" in params:
        kwargs["config"] = config
    if "target" in params:
        kwargs["target"] = args.target or config.get_target_url()
    if "target_url" in params and "target" not in kwargs:
        kwargs["target_url"] = args.target or config.get_target_url()
    if "debug" in params:
        kwargs["debug"] = args.debug
    if "debug_mode" in params and "debug" not in kwargs:
        kwargs["debug_mode"] = args.debug
    if "test_mode" in params:
        kwargs["test_mode"] = args.test

    optional_map = {
        "target_file": args.target_file,
        "max_depth": args.depth,
        "max_endpoints": args.max_endpoints,
        "max_pages": args.max_pages,
        "enable_zap": args.enable_zap,
        "enable_nikto": args.enable_nikto,
        "enable_testssl": args.enable_testssl,
        "log_path": args.log_path,
        "document_path": args.document_path,
    }
    for param_name, value in optional_map.items():
        if value is None:
            continue
        if param_name in params:
            kwargs[param_name] = value

    return cls(**kwargs)


def run_module(module_number: int, config: Config, args: argparse.Namespace) -> ModuleResult:
    cls = load_module_class(module_number)
    analyzer = instantiate_analyzer(cls, config, args)

    if args.dry_run:
        print(f"[DRY RUN] Loaded module {module_number}: {cls.__name__}")
        return ModuleResult(success=True, module=str(cls.__name__), module_number=module_number)

    result = analyzer.execute()
    if isinstance(result, ModuleResult):
        return result

    # Legacy dict support
    success = bool(result.get("success", True))
    output_file = result.get("output_file")
    return ModuleResult(success=success, module=str(cls.__name__), module_number=module_number, output_file=output_file)


def main() -> int:
    args = parse_args()
    try:
        config = load_config(args.config_dir)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}")
        return 2

    if args.list:
        list_modules(config)
        return 0

    try:
        module_numbers = resolve_module_numbers(args.module)
    except ValueError as exc:
        print(f"Argument error: {exc}")
        return 1

    exit_code = 0
    for module_number in module_numbers:
        if not config.module_enabled(module_number):
            print(f"Skipping module {module_number} (disabled in config).")
            continue
        try:
            result = run_module(module_number, config, args)
            status = "SUCCESS" if result.success else "FAILED"
            print(f"[{status}] Module {module_number} -> {result.output_file or 'no output'}")
            if not result.success:
                exit_code = 3
        except ConfigurationError as exc:
            print(f"[ERROR] Module {module_number}: {exc}")
            exit_code = 4
        except Exception as exc:  # noqa: BLE001
            print(f"[ERROR] Module {module_number} raised unexpected error: {exc}")
            exit_code = 5

    return exit_code


if __name__ == "__main__":
    sys.exit(main())


