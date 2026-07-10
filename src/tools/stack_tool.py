"""Stack and frame inspection tool."""

from ._evidence import run_command, run_mutation, run_read
from ._models import ToolEnvelope
from ._parser import parse_stack_k, parse_stack_kp
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
            selection = run_mutation(f".frame 0n{frame_number}")
            sources = [selection.source]
            data = {"frame": frame_number}
            if selection.execution.status != "completed":
                return make_response("windbg_backtrace", sources, data)
            locals_evidence = run_command(
                "dv /t /i",
                read_only=True,
                retryable=False,
            )
            sources.append(locals_evidence.source)
            if locals_evidence.execution.output:
                data["locals_raw"] = locals_evidence.execution.output
            return make_response("windbg_backtrace", sources, data)

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
