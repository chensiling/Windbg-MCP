"""Execution-control tool with explicit target-state reporting."""

from typing import Literal

from ._annotations import DESTRUCTIVE_EXTERNAL_TOOL
from ._evidence import run_mutation
from ._models import ToolEnvelope
from ._response import error_item, make_response, parse_int_arg


ControlAction = Literal[
    "go", "g", "step_into", "t", "step_over", "p", "step_out", "gu",
]


def _target_state(execution) -> str:
    if execution.status == "completed":
        return "broken"
    if execution.status == "timeout" and execution.session_state == "draining":
        return "running"
    if execution.status in ("cancelled", "timeout") and execution.complete:
        return "broken"
    return "indeterminate"


def register_control_tool(mcp):
    @mcp.tool(annotations=DESTRUCTIVE_EXTERNAL_TOOL, structured_output=True)
    def windbg_control(action: ControlAction, count: str = "1") -> ToolEnvelope:
        """Resume or step the target without reporting an invented completion state."""

        count_value, count_error = parse_int_arg(
            count,
            "count",
            default=1,
            min_value=1,
            max_value=1000,
        )
        if count_error:
            return make_response(
                "windbg_control",
                errors=[count_error],
                verification_status="not_run",
            )
        normalized = action.lower().strip()
        aliases = {
            "g": "go",
            "t": "step_into",
            "p": "step_over",
            "gu": "step_out",
        }
        normalized = aliases.get(normalized, normalized)
        if normalized not in ("go", "step_into", "step_over", "step_out"):
            return make_response(
                "windbg_control",
                errors=[error_item("invalid_argument", "Unknown control action.")],
                verification_status="not_run",
            )
        if normalized == "go" and count_value != 1:
            return make_response(
                "windbg_control",
                errors=[error_item(
                    "invalid_argument",
                    "'go' does not support count values other than 1.",
                )],
                verification_status="not_run",
            )

        if normalized == "go":
            commands = ["g"]
        elif normalized == "step_into":
            commands = [f"t 0n{count_value}"]
        elif normalized == "step_over":
            commands = [f"p 0n{count_value}"]
        else:
            commands = ["gu"] * count_value

        sources = []
        final_status = "indeterminate"
        for command in commands:
            evidence = run_mutation(
                command,
                cancel_on_timeout=normalized != "go",
            )
            sources.append(evidence.source)
            final_status = _target_state(evidence.execution)
            if evidence.execution.status != "completed":
                break

        verification_status = "verified" if final_status == "broken" else "indeterminate"
        return make_response(
            "windbg_control",
            sources,
            {
                "action": normalized,
                "count": count_value,
                "target_state": final_status,
            },
            verification_status=verification_status,
        )
