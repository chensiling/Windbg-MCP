"""Crash and hang analysis with retained context evidence."""

from typing import Literal

from ._annotations import MIXED_STATE_TOOL
from ._evidence import run_command, run_mutation, run_read
from ._models import ToolEnvelope
from ._parser import parse_analyze, parse_registers, parse_stack_kp
from ._response import error_item, make_response, next_action
from .context_tool import _session_kind, _target_mode


AnalyzeScope = Literal["crash", "hang", "quick"]


def register_analyze_tool(mcp):
    @mcp.tool(annotations=MIXED_STATE_TOOL, structured_output=True)
    def windbg_analyze(scope: AnalyzeScope = "crash") -> ToolEnvelope:
        """Collect crash or hang observations without collapsing command evidence."""

        normalized_scope = scope.lower().strip()
        if normalized_scope not in ("crash", "hang", "quick"):
            return make_response(
                "windbg_analyze",
                errors=[error_item("invalid_argument", "Unknown analysis scope.")],
            )

        analyze_command = (
            "!analyze -v -hang" if normalized_scope == "hang" else "!analyze -v"
        )
        if normalized_scope != "crash":
            analysis = run_read(analyze_command, parse_analyze)
            data: dict[str, object] = {"scope": normalized_scope}
            if analysis.parsed is not None:
                data.update(dict(analysis.parsed.data))
            return make_response(
                "windbg_analyze",
                [analysis.source],
                data,
                next_actions=[next_action(
                    "windbg_context",
                    {"scope": "default"},
                    "Correlate analysis evidence with current target context.",
                )],
            )

        target = run_read("vertarget")
        debug_systems = run_read("||")
        target_mode = _target_mode(
            target.execution.output,
            debug_systems.execution.output,
        )
        session_kind = _session_kind(
            target.execution.output,
            debug_systems.execution.output,
        )
        analysis = run_read(analyze_command, parse_analyze)
        sources = [target.source, debug_systems.source, analysis.source]
        data = {
            "scope": "crash",
            "target_mode": target_mode,
            "session_kind": session_kind,
            "context_kind": "current_context",
        }
        errors = []
        if analysis.parsed is not None:
            data.update(dict(analysis.parsed.data))

        dependent_context = False
        if target_mode == "user" and session_kind == "dump":
            exception_context = run_mutation(".ecxr", parse_registers)
            sources.append(exception_context.source)
            exception_registers = (
                exception_context.parsed.data.get("registers")
                if exception_context.parsed is not None
                else None
            )
            if (
                exception_context.execution.status == "completed"
                and isinstance(exception_registers, dict)
                and exception_registers
            ):
                data["context_kind"] = "exception_context"
                dependent_context = True
            else:
                errors.append(error_item(
                    "exception_context_unavailable",
                    ".ecxr did not produce an observable exception register context.",
                    stage="execution",
                ))

        if dependent_context:
            registers = run_command(
                "r",
                parse_registers,
                read_only=True,
                retryable=False,
            )
            backtrace = run_command(
                "kP 0n30",
                parse_stack_kp,
                read_only=True,
                retryable=False,
            )
        else:
            registers = run_read("r", parse_registers)
            backtrace = run_read("kP 0n30", parse_stack_kp)
        sources.extend([registers.source, backtrace.source])

        if registers.parsed is not None:
            register_data = dict(registers.parsed.data)
            for key in ("registers", "flags", "segments", "current"):
                if key in register_data:
                    data[key] = register_data[key]
        if backtrace.parsed is not None:
            data["backtrace"] = list(backtrace.parsed.data.get("frames", []))

        actions = [next_action(
            "windbg_context",
            {"scope": "default"},
            "Correlate analysis evidence with current target context.",
        )]
        if data.get("faulting_ip"):
            actions.append(next_action(
                "windbg_disassemble",
                {"at": "@rip", "count": "8"},
                "Inspect the faulting instruction region.",
            ))
        return make_response(
            "windbg_analyze",
            sources,
            data,
            errors=errors,
            next_actions=actions,
        )
