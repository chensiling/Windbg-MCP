"""Shared response helpers for LLM-facing tools."""

import json
from typing import Any


def error_item(code: str, message: str, recoverable: bool = True) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "recoverable": recoverable,
    }


def next_action(tool: str, args: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "tool": tool,
        "args": args,
        "reason": reason,
    }


def is_error_output(raw: str) -> bool:
    return raw.lstrip().lower().startswith("error:")


def make_response(
    tool: str,
    command: str | list[str],
    data: dict[str, Any] | list[Any] | None = None,
    *,
    ok: bool = True,
    mode: str = "unknown",
    raw: str = "",
    errors: list[dict[str, Any]] | None = None,
    next_actions: list[dict[str, Any]] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "ok": ok,
        "tool": tool,
        "command": command,
        "mode": mode,
        "data": data if data is not None else {},
        "raw": raw,
        "errors": errors or [],
        "next_actions": next_actions or [],
    }
    return json.dumps(payload, ensure_ascii=False)


def make_error(
    tool: str,
    command: str | list[str],
    code: str,
    message: str,
    *,
    mode: str = "unknown",
    raw: str = "",
    recoverable: bool = True,
    next_actions: list[dict[str, Any]] | None = None,
) -> str:
    return make_response(
        tool,
        command,
        ok=False,
        mode=mode,
        raw=raw,
        errors=[error_item(code, message, recoverable=recoverable)],
        next_actions=next_actions,
    )


def parsed_response(
    tool: str,
    command: str | list[str],
    parsed: dict[str, Any],
    raw: str,
    *,
    mode: str = "unknown",
    data: dict[str, Any] | None = None,
    parse_error_code: str = "parse_failed",
    parse_error_message: str = "Could not parse debugger output; raw output is available.",
    next_actions: list[dict[str, Any]] | None = None,
) -> str:
    if is_error_output(raw):
        return make_error(
            tool,
            command,
            "debugger_error",
            raw.strip(),
            mode=mode,
            raw=raw,
            next_actions=next_actions,
        )

    if "raw" in parsed:
        return make_response(
            tool,
            command,
            data=data or {},
            mode=mode,
            raw=parsed["raw"],
            errors=[error_item(parse_error_code, parse_error_message)],
            next_actions=next_actions,
        )

    return make_response(
        tool,
        command,
        data=data if data is not None else parsed,
        mode=mode,
        raw=raw,
        next_actions=next_actions,
    )


def parse_int_arg(
    value: Any,
    name: str,
    *,
    default: int | None = None,
    min_value: int = 1,
    max_value: int | None = None,
) -> tuple[int | None, dict[str, Any] | None]:
    if value is None or str(value).strip() == "":
        if default is not None:
            return default, None
        return None, error_item("invalid_argument", f"'{name}' is required.")

    text = str(value).strip().lower()
    try:
        if text.endswith("h") and all(c in "0123456789abcdef" for c in text[:-1]):
            number = int(text[:-1], 16)
        else:
            number = int(text, 0)
    except ValueError:
        return None, error_item(
            "invalid_argument",
            f"'{name}' must be an integer; decimal and 0x-prefixed hex are supported.",
        )

    if number < min_value:
        return None, error_item("invalid_argument", f"'{name}' must be >= {min_value}.")

    if max_value is not None and number > max_value:
        return None, error_item("invalid_argument", f"'{name}' must be <= {max_value}.")

    return number, None
