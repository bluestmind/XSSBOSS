"""
Log serializer and parser utility.
Provides fast JSON serialization and robust parsing with backwards-compatible fallbacks.
"""
from __future__ import annotations

import ast
import json
from typing import Any, Dict


def parse_execution_logs(raw_logs: Any) -> Dict[str, Any]:
    """
    Safely parse execution logs.
    Prioritizes JSON parsing and provides graceful fallback for legacy Python dict string reprs.
    """
    if not raw_logs:
        return {}
    if isinstance(raw_logs, dict):
        return raw_logs
    if not isinstance(raw_logs, str):
        return {}

    # 1. Primary: Standard JSON parser
    try:
        data = json.loads(raw_logs)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass

    # 2. Secondary fallback: AST literal parser for legacy records
    try:
        data = ast.literal_eval(raw_logs)
        if isinstance(data, dict):
            return data
    except (ValueError, SyntaxError, MemoryError, TypeError):
        pass

    return {}


def serialize_execution_logs(logs_dict: Dict[str, Any]) -> str:
    """
    Serialize logs dictionary to standard JSON string format.
    """
    if not isinstance(logs_dict, dict):
        return "{}"
    try:
        return json.dumps(logs_dict, default=str)
    except Exception:
        return "{}"
