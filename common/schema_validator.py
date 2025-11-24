"""
JSON schema validation helpers for module outputs and merged reports.
"""

from __future__ import annotations

from typing import Any, Dict

from jsonschema import Draft202012Validator, ValidationError


TARGET_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["target", "controls", "evidence", "summary"],
    "properties": {
        "target": {"type": "string"},
        "controls": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {"type": "string"},
        },
        "evidence": {
            "type": "object",
            "properties": {
                "endpoints": {"type": "array", "items": {"type": "object"}},
                "findings": {"type": "array", "items": {"type": "object"}},
                "logs": {"type": ["string", "null"]},
                "reports": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
        "summary": {
            "type": "object",
            "required": ["total", "passed", "failed", "not_tested"],
            "properties": {
                "total": {"type": "integer", "minimum": 0},
                "passed": {"type": "integer", "minimum": 0},
                "failed": {"type": "integer", "minimum": 0},
                "not_tested": {"type": "integer", "minimum": 0},
            },
            "additionalProperties": True,
        },
        "metadata": {"type": "object", "additionalProperties": True},
    },
    "additionalProperties": True,
}


MODULE_OUTPUT_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ModuleOutput",
    "type": "object",
    "required": ["module", "timestamp"],
    "properties": {
        "module": {"type": "string", "minLength": 1},
        "module_number": {"type": "integer", "minimum": 1},
        "timestamp": {"type": "string", "format": "date-time"},
        "target": {"type": ["string", "null"]},
        "controls": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "minProperties": 0,
        },
        "targets": {
            "type": "array",
            "items": TARGET_SCHEMA,
        },
        "evidence": {"type": "object", "additionalProperties": True},
        "summary": {"type": "object", "additionalProperties": True},
        "metadata": {"type": "object", "additionalProperties": True},
    },
    "additionalProperties": True,
}


FINAL_REPORT_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "FinalReport",
    "type": "object",
    "required": ["report_type", "generated_at", "modules", "overall_summary"],
    "properties": {
        "report_type": {"type": "string"},
        "generated_at": {"type": "string", "format": "date-time"},
        "modules": {
            "type": "object",
            "additionalProperties": MODULE_OUTPUT_SCHEMA,
        },
        "overall_summary": {
            "type": "object",
            "required": ["total_controls", "passed", "failed", "not_tested"],
            "properties": {
                "total_controls": {"type": "integer", "minimum": 0},
                "passed": {"type": "integer", "minimum": 0},
                "failed": {"type": "integer", "minimum": 0},
                "not_tested": {"type": "integer", "minimum": 0},
                "pass_rate": {"type": "number"},
                "coverage": {"type": "number"},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


module_validator = Draft202012Validator(MODULE_OUTPUT_SCHEMA)
final_validator = Draft202012Validator(FINAL_REPORT_SCHEMA)


def validate_module_output(data: Dict[str, Any]) -> None:
    """Validate module JSON output."""
    module_validator.validate(data)


def validate_final_report(data: Dict[str, Any]) -> None:
    """Validate merged final report."""
    final_validator.validate(data)


