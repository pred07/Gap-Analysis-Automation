"""
Configuration loader with schema validation for the GAP Analysis framework.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .helpers import ensure_dir, project_root


class ConfigurationError(Exception):
    """Raised when configuration files are missing or invalid."""


class TargetSettings(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: Optional[str] = None
    api_base: Optional[str] = None
    endpoints: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class OutputSettings(BaseModel):
    model_config = ConfigDict(extra="allow")

    directory: str = "outputs"
    format: str = "json"
    additional_formats: List[str] = Field(default_factory=list)
    log_level: str = "INFO"
    log_retention_days: int = 30


class ExecutionSettings(BaseModel):
    model_config = ConfigDict(extra="allow")

    parallel: bool = False
    max_workers: int = 4
    timeout: int = 300
    retry_count: int = 2
    retry_delay: int = 5
    skip_on_missing_tools: bool = True
    continue_on_error: bool = True


class ModuleToggle(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    timeout: Optional[int] = None


class ConfigData(BaseModel):
    model_config = ConfigDict(extra="allow")

    target: TargetSettings = Field(default_factory=TargetSettings)
    credentials: Dict[str, Any] = Field(default_factory=dict)
    documents: List[Dict[str, Any]] = Field(default_factory=list)
    output: OutputSettings = Field(default_factory=OutputSettings)
    execution: ExecutionSettings = Field(default_factory=ExecutionSettings)
    modules: Dict[str, ModuleToggle] = Field(default_factory=dict)
    tool_config: Dict[str, Any] = Field(default_factory=dict)
    notifications: Dict[str, Any] = Field(default_factory=dict)
    proxy: Dict[str, Any] = Field(default_factory=dict)
    advanced: Dict[str, Any] = Field(default_factory=dict)


class ToolPaths(BaseModel):
    model_config = ConfigDict(extra="allow")

    tools: Dict[str, str] = Field(default_factory=dict)


class Control(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None


class ModuleControlMap(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    description: Optional[str] = None
    control_count: Optional[int] = None
    tools: List[str] = Field(default_factory=list)
    controls: List[Control] = Field(default_factory=list)


class ControlMapping(BaseModel):
    model_config = ConfigDict(extra="allow")

    version: Optional[str] = None
    total_controls: Optional[int] = None
    modules: Dict[str, ModuleControlMap] = Field(default_factory=dict)


class Config:
    """Facade for accessing validated configuration data."""

    def __init__(self, config_dir: str | Path = "config"):
        self.config_dir = Path(config_dir)
        if not self.config_dir.exists():
            raise ConfigurationError(f"Config directory not found: {self.config_dir}")

        try:
            self._config = ConfigData(**self._load_yaml("config.yaml"))
            self._tool_paths = ToolPaths(**self._load_yaml("tool_paths.yaml"))
            self._control_mapping = ControlMapping(**self._load_yaml("control_mapping.yaml"))
        except ValidationError as exc:
            raise ConfigurationError(str(exc)) from exc

        # Ensure output directories exist
        ensure_dir(project_root() / self._config.output.directory)
        ensure_dir(project_root() / "logs")
        ensure_dir(project_root() / "evidence")

    # ------------------------------------------------------------------ #
    # YAML helpers
    def _load_yaml(self, filename: str) -> Dict[str, Any]:
        path = self.config_dir / filename
        if not path.exists():
            raise ConfigurationError(f"Missing configuration file: {path}")

        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
            return data

    # ------------------------------------------------------------------ #
    # General getters
    def get(self, dotted_key: str, default: Any = None) -> Any:
        data = self._config.model_dump()
        for part in dotted_key.split("."):
            if isinstance(data, dict) and part in data:
                data = data[part]
            else:
                return default
        return data

    def get_target_url(self) -> Optional[str]:
        return self._config.target.url

    def get_target_api(self) -> Optional[str]:
        return self._config.target.api_base

    def get_documents(self) -> List[Dict[str, Any]]:
        return self._config.documents

    def get_output_dir(self) -> str:
        return self._config.output.directory

    def get_log_level(self) -> str:
        return self._config.output.log_level

    def get_execution_settings(self) -> ExecutionSettings:
        return self._config.execution

    def get_tool_path(self, tool_name: str) -> Optional[str]:
        return self._tool_paths.tools.get(tool_name)

    def get_all_tool_paths(self) -> Dict[str, str]:
        return self._tool_paths.tools

    def get_module_info(self, module_number: int) -> ModuleControlMap:
        key = f"module{module_number}"
        module = self._control_mapping.modules.get(key)
        if not module:
            raise ConfigurationError(f"Control mapping missing for {key}")
        return module

    def get_module_controls(self, module_number: int) -> List[Dict[str, Any]]:
        return [control.model_dump() for control in self.get_module_info(module_number).controls]

    def get_control_by_id(self, control_id: str) -> Optional[Dict[str, Any]]:
        for module in self._control_mapping.modules.values():
            for control in module.controls:
                if control.id == control_id:
                    return control.model_dump()
        return None

    def get_total_controls_count(self) -> int:
        if self._control_mapping.total_controls:
            return self._control_mapping.total_controls
        return sum(len(module.controls) for module in self._control_mapping.modules.values())

    def list_modules(self) -> List[str]:
        return sorted(self._control_mapping.modules.keys())

    def module_enabled(self, module_number: int) -> bool:
        toggle = self._config.modules.get(f"module{module_number}")
        return toggle.enabled if toggle else True

    # ------------------------------------------------------------------ #
    def validate(self) -> Dict[str, Any]:
        errors: List[str] = []
        warnings: List[str] = []

        if not (self.get_target_url() or self.get_target_api()):
            errors.append("No target url/api configured under target section.")

        expected_controls = 65
        total_controls = self.get_total_controls_count()
        if total_controls != expected_controls:
            warnings.append(f"Expected {expected_controls} controls, found {total_controls}.")

        for tool, path in self.get_all_tool_paths().items():
            if not Path(path).exists():
                warnings.append(f"Tool path not found: {tool} -> {path}")

        return {
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
        }

    # ------------------------------------------------------------------ #
    def dump(self) -> Dict[str, Any]:
        """Return combined configuration for debugging."""
        return {
            "config": self._config.model_dump(),
            "tool_paths": self._tool_paths.model_dump(),
            "control_mapping": json.loads(self._control_mapping.model_dump_json()),
        }

    def __repr__(self) -> str:
        return f"Config(target={self.get_target_url()}, controls={self.get_total_controls_count()})"


def load_config(config_dir: str | Path = "config") -> Config:
    return Config(config_dir)

