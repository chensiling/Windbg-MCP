"""Stack and frame inspection tool."""

from ._evidence import run_command, run_mutation, run_read
from ._models import ToolEnvelope
from ._parser import parse_frame_selection, parse_stack_k, parse_stack_kp
from ._response import error_item, make_response, next_action, parse_int_arg


_TRUE_VALUES = {"true", "1", "yes"}
_FALSE_VALUES = {"false", "0", "no"}


def register_stack_tool(mcp):
    @mcp.tool()
    def windbg_backtrace(
        depth: str = "20",
        show_params: str = "true",
        frame: str = "",
    ) -> ToolEnvelope:
        """Return a parsed stack or inspect locals in one numeric frame."""

        if frame:
            frame_number, frame_error = parse_int_arg(
                frame,
                "frame",
                min_value=0,
                max_value=200,
            )
            if frame_error:
                return make_response("windbg_backtrace", errors=[frame_error])
            selection = run_mutation(
                f".frame 0n{frame_number}",
                parse_frame_selection,
            )
            sources = [selection.source]
            data: dict[str, object] = {"requested_frame": frame_number}
            selection_data = (
                dict(selection.parsed.data)
                if selection.parsed is not None
                else {}
            )
            if "message" in selection_data:
                data["selection_error"] = selection_data["message"]
            if "current_frame" in selection_data:
                data["current_frame"] = selection_data["current_frame"]

            selection_complete = (
                selection.execution.status == "completed"
                and selection.parsed is not None
                and selection.parsed.status == "complete"
            )
            if not selection_complete or selection_data.get("selected") is not True:
                explicit_failure = (
                    selection_complete
                    and selection_data.get("selected") is False
                )
                return make_response(
                    "windbg_backtrace",
                    sources,
                    data,
                    verification_status=(
                        "failed" if explicit_failure else "indeterminate"
                    ),
                    errors=[error_item(
                        (
                            "frame_selection_failed" if explicit_failure
                            else "frame_selection_indeterminate"
                        ),
                        (
                            "The debugger rejected the requested frame."
                            if explicit_failure
                            else "The selected frame could not be observed."
                        ),
                        recoverable=not explicit_failure,
                        stage="verification",
                    )],
                )

            selected_frame = selection_data.get("frame")
            data["selected_frame"] = selected_frame
            if selected_frame != frame_number:
                return make_response(
                    "windbg_backtrace",
                    sources,
                    data,
                    verification_status="failed",
                    errors=[error_item(
                        "frame_selection_mismatch",
                        "The debugger selected a different frame than requested.",
                        recoverable=False,
                        stage="verification",
                    )],
                )

            data["frame"] = selected_frame
            locals_evidence = run_command(
                "dv /t /i",
                read_only=True,
                retryable=False,
            )
            sources.append(locals_evidence.source)
            if locals_evidence.execution.output:
                data["locals_raw"] = locals_evidence.execution.output
            return make_response(
                "windbg_backtrace",
                sources,
                data,
                verification_status="verified",
            )

        depth_value, depth_error = parse_int_arg(
            depth,
            "depth",
            default=20,
            min_value=1,
            max_value=200,
        )
        if depth_error:
            return make_response("windbg_backtrace", errors=[depth_error])

        normalized_show_params = show_params.lower().strip()
        if normalized_show_params not in _TRUE_VALUES | _FALSE_VALUES:
            return make_response(
                "windbg_backtrace",
                errors=[error_item(
                    "invalid_argument",
                    "'show_params' must be true or false.",
                )],
            )
        include_params = normalized_show_params in _TRUE_VALUES
        command = f"{'kP' if include_params else 'k'} 0n{depth_value}"
        parser = parse_stack_kp if include_params else parse_stack_k
        evidence = run_read(command, parser)
        data = {"depth": depth_value, "show_params": include_params}
        if evidence.parsed is not None:
            data.update(dict(evidence.parsed.data))
        actions = []
        if data.get("frames"):
            actions.append(next_action(
                "windbg_disassemble",
                {"at": "@rip", "count": "8"},
                "Inspect instructions near the current frame.",
            ))
        return make_response(
            "windbg_backtrace",
            [evidence.source],
            data,
            next_actions=actions,
        )
