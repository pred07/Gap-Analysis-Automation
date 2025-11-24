"""
General helper utilities shared across modules.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable


ROOT_DIR = Path(__file__).resolve().parent.parent


def project_root() -> Path:
    """Return repository root."""
    return ROOT_DIR


def ensure_dir(path: os.PathLike | str) -> Path:
    """Create directory if it does not exist and return Path."""
    path_obj = Path(path)
    path_obj.mkdir(parents=True, exist_ok=True)
    return path_obj


def slugify(value: str, allow_ampersand: bool = False) -> str:
    """
    Convert arbitrary text into a filesystem-safe slug.
    """
    value = value.strip().lower()
    if not allow_ampersand:
        value = value.replace("&", "and")
    value = re.sub(r"[^a-z0-9\-\_]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_")


def timestamp_utc() -> str:
    """Return ISO 8601 timestamp with Z suffix."""
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def expand_path(path: str | None) -> Path | None:
    """Expand user/environment variables for a path string."""
    if not path:
        return None
    return Path(os.path.expandvars(os.path.expanduser(path))).resolve()


def deep_update(dest: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge src into dest.
    """
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dest.get(key), dict):
            deep_update(dest[key], value)
        else:
            dest[key] = value
    return dest


def listify(value: Any) -> Iterable:
    """Ensure value is iterable, wrapping non-iterables."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return value
    return [value]


