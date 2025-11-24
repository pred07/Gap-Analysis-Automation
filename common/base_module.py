"""
Shared base class for all module analyzers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config_loader import Config, ConfigurationError, load_config
from .helpers import ensure_dir, project_root, slugify, timestamp_utc
from .json_writer import JSONWriter
from .logger import SecurityLogger, get_logger
from .schema_validator import validate_module_output


@dataclass
class ModuleResult:
    success: bool
    module: str
    module_number: int
    output_file: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class BaseModule:
    module_number: int = 0
    module_name: str = "Unnamed Module"

    def __init__(
        self,
        config: Optional[Config] = None,
        debug: bool = False,
        target: Optional[str] = None,
    ):
        if self.module_number <= 0:
            raise ValueError("Module number must be defined for BaseModule subclasses.")

        self.config = config or load_config()
        self.module_info = self.config.get_module_info(self.module_number)
        self.module_name = self.module_info.name
        self.target = target or self.config.get_target_url()
        self.logger: SecurityLogger = get_logger(f"module{self.module_number}", debug_mode=debug)
        self.writer = JSONWriter(self.config.get_output_dir())
        self.controls = {control["name"]: "not_tested" for control in self.config.get_module_controls(self.module_number)}
        self.evidence: Dict[str, Any] = {
            "logs": f"logs/module{self.module_number}.log",
            "reports": [],
            "details": "",
            "findings": [],
            "vulnerabilities": [],
        }

    # ------------------------------------------------------------------ #
    def execute(self) -> ModuleResult:
        """
        Subclasses must override this method to perform their analysis.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------ #
    def mark_control(self, control_name: str, status: str) -> None:
        if control_name not in self.controls:
            raise ConfigurationError(f"Unknown control {control_name} in module {self.module_number}")
        self.controls[control_name] = status

    def add_evidence(self, key: str, value: Any) -> None:
        if key not in self.evidence:
            self.evidence[key] = []
        if isinstance(self.evidence[key], list):
            self.evidence[key].append(value)
        else:
            self.evidence[key] = value

    def finalize(self, metadata: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """
        Generate JSON output and perform schema validation.
        """
        total = len(self.controls)
        passed = sum(1 for v in self.controls.values() if v == "pass")
        failed = sum(1 for v in self.controls.values() if v == "fail")
        not_tested = total - passed - failed

        summary = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "not_tested": not_tested,
            "pass_rate": round((passed / total) * 100, 2) if total else 0.0,
        }

        payload = {
            "module": self.module_name,
            "module_number": self.module_number,
            "timestamp": timestamp_utc(),
            "target": self.target,
            "controls": self.controls,
            "evidence": self.evidence,
            "summary": summary,
        }

        if metadata:
            payload["metadata"] = metadata

        validate_module_output(payload)
        output_file = self.writer.write_payload(self.module_name, payload)
        self.logger.info(f"Module output written to {output_file}")

        return ModuleResult(
            success=True,
            module=self.module_name,
            module_number=self.module_number,
            output_file=output_file,
            details={"summary": summary},
        )


