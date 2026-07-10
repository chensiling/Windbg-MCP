"""Breakpoint management with deterministic postcondition checks."""

import re
from typing import Literal

from ._evidence import resolve_expression, run_mutation, run_read
from ._models import ToolEnvelope
from ._parser import parse_breakpoints
from ._response import error_item, make_response, validate_intent_text


BreakpointAction = Literal["set", "list", "clear", "enable", "disable"]


def _address_value(value: str) -> int | None:
    try:
        return int(value.lower().replace("`", "").removeprefix("0x"), 16)
    except ValueError:
        return None


def register_breakpoint_tool(mcp):
    @mcp.tool()
    def windbg_breakpoint(
        action: BreakpointAction,
        target: str = "",
        condition: str = "",
        id: str = "",
    ) -> ToolEnvelope:
        """Manage breakpoints and verify every mutation against `bl`."""

        normalized_action = action.lower().strip()
        if normalized_action not in ("set", "list", "clear", "enable", "disable"):
            return make_response(
                "windbg_breakpoint",
                errors=[error_item("invalid_argument", "Unknown breakpoint action.")],
                verification_status="not_run",
            )

        supplied_errors = [
            validate_intent_text(target, "target", required=False),
            validate_intent_text(condition, "condition", required=False),
            validate_intent_text(id, "id", required=False),
        ]
        supplied_errors = [error for error in supplied_errors if error]
        if supplied_errors:
            return make_response(
                "windbg_breakpoint",
                errors=supplied_errors,
                verification_status="not_run",
            )

        if normalized_action == "list":
            listing = run_read("bl", parse_breakpoints)
            data = dict(listing.parsed.data) if listing.parsed is not None else {}
            return make_response("windbg_breakpoint", [listing.source], data)

        if normalized_action == "set":
            target_error = validate_intent_text(target, "target")
            condition_error = validate_intent_text(
                condition,
                "condition",
                required=False,
            )
            if condition and '"' in condition:
                condition_error = error_item(
                    "unsafe_argument",
                    "'condition' cannot contain a quote.",
                    recoverable=False,
                )
            if target_error or condition_error:
                return make_response(
                    "windbg_breakpoint",
                    errors=[error for error in (target_error, condition_error) if error],
                    verification_status="not_run",
                )
            resolution, resolved_address = resolve_expression(target)
            sources = [resolution.source]
            data = {"action": "set", "input": target, "condition": condition or None}
            if resolved_address is None:
                return make_response(
                    "windbg_breakpoint",
                    sources,
                    data,
                    verification_status="not_run",
                )
            data["resolved_address"] = resolved_address
            before = run_read("bl", parse_breakpoints)
            sources.append(before.source)
            if before.parsed is None or before.parsed.status != "complete":
                return make_response(
                    "windbg_breakpoint",
                    sources,
                    data,
                    verification_status="not_run",
                )
            command = (
                f'bp /w "{condition}" {resolved_address}'
                if condition
                else f"bp {resolved_address}"
            )
            mutation = run_mutation(command)
        else:
            id_error = validate_intent_text(id, "id")
            valid_id = id == "*" or bool(re.fullmatch(r"\d+", id))
            if id_error or not valid_id:
                return make_response(
                    "windbg_breakpoint",
                    errors=[id_error or error_item(
                        "invalid_argument",
                        "'id' must be a decimal breakpoint id or '*'.",
                    )],
                    verification_status="not_run",
                )
            command_id = "*" if id == "*" else f"0n{int(id)}"
            command_prefix = {"clear": "bc", "enable": "be", "disable": "bd"}
            command = f"{command_prefix[normalized_action]} {command_id}"
            data = {"action": normalized_action, "id": id}
            before = run_read("bl", parse_breakpoints)
            sources = [before.source]
            if before.parsed is None or before.parsed.status != "complete":
                return make_response(
                    "windbg_breakpoint",
                    sources,
                    data,
                    verification_status="not_run",
                )
            mutation = run_mutation(command)

        sources.append(mutation.source)
        if mutation.execution.status != "completed":
            return make_response(
                "windbg_breakpoint",
                sources,
                data,
                verification_status="indeterminate",
                errors=[error_item(
                    "verification_not_run",
                    "Breakpoint mutation did not complete.",
                    stage="verification",
                )],
            )

        listing = run_read("bl", parse_breakpoints)
        sources.append(listing.source)
        listing_complete = (
            listing.execution.status == "completed"
            and listing.parsed is not None
            and listing.parsed.status == "complete"
        )
        if not listing_complete:
            return make_response(
                "windbg_breakpoint",
                sources,
                data,
                verification_status="indeterminate",
                errors=[error_item(
                    "verification_indeterminate",
                    "Breakpoint list refresh was incomplete.",
                    stage="verification",
                )],
            )
        breakpoints = (
            list(listing.parsed.data.get("breakpoints", []))
            if listing.parsed is not None
            else []
        )
        data["breakpoints"] = breakpoints
        before_breakpoints = list(before.parsed.data.get("breakpoints", []))
        if normalized_action == "set":
            expected_address = _address_value(data["resolved_address"])
            before_ids = {str(item.get("id")) for item in before_breakpoints}
            verified = any(
                _address_value(str(item.get("address", ""))) == expected_address
                and str(item.get("id")) not in before_ids
                and (
                    not condition
                    or condition.lower() in str(item.get("detail", "")).lower()
                )
                for item in breakpoints
            )
        elif normalized_action == "clear":
            existed_before = bool(before_breakpoints) if id == "*" else any(
                str(item.get("id")) == id for item in before_breakpoints
            )
            absent_after = not breakpoints if id == "*" else all(
                str(item.get("id")) != id for item in breakpoints
            )
            verified = existed_before and absent_after
        else:
            expected_enabled = normalized_action == "enable"
            if id == "*":
                before_ids = {str(item.get("id")) for item in before_breakpoints}
                after_ids = {str(item.get("id")) for item in breakpoints}
                data["affected_ids"] = sorted(before_ids)
                verified = before_ids == after_ids and all(
                    item.get("enabled") is expected_enabled
                    for item in breakpoints
                )
            else:
                existed_before = any(
                    str(item.get("id")) == id for item in before_breakpoints
                )
                data["affected_ids"] = [id] if existed_before else []
                verified = existed_before and any(
                    str(item.get("id")) == id
                    and item.get("enabled") is expected_enabled
                    for item in breakpoints
                )

        errors = [] if verified else [error_item(
            "verification_failed",
            "Refreshed breakpoint list did not confirm the requested mutation.",
            recoverable=False,
            stage="verification",
        )]
        return make_response(
            "windbg_breakpoint",
            sources,
            data,
            verification_status="verified" if verified else "failed",
            errors=errors,
        )
