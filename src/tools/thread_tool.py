"""Structured kernel thread inspection."""

from ._annotations import READ_ONLY_TOOL
from ._evidence import probe_target_info, resolve_expression, run_read
from ._models import ToolEnvelope
from ._parser import parse_thread_info
from ._response import (
    error_item,
    limitation_item,
    make_response,
    validate_intent_text,
)


def register_thread_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_thread(thread: str = "", include_raw: bool = False) -> ToolEnvelope:
        """Inspect the current or specified kernel thread and its available stack."""

        input_error = validate_intent_text(thread, "thread", required=False)
        if input_error:
            return make_response("windbg_thread", errors=[input_error])

        target, target_info = probe_target_info(include_raw=include_raw)
        sources = [target.source]
        data = {"input": thread or "current", **target_info}
        if target_info["target_mode"] != "kernel":
            return make_response(
                "windbg_thread",
                sources,
                data,
                errors=[error_item(
                    "command_unsupported_for_target",
                    "Kernel thread inspection requires a kernel target.",
                    stage="target",
                )],
                core_result_status="unavailable",
            )

        if thread.strip():
            resolution, resolved_thread = resolve_expression(
                thread,
                include_raw=include_raw,
            )
            sources.append(resolution.source)
            if resolved_thread is None:
                return make_response(
                    "windbg_thread",
                    sources,
                    data,
                    core_result_status="unavailable",
                )
            data["resolved_thread"] = resolved_thread
            command = f"!thread {resolved_thread} 0x6"
        else:
            command = "!thread"
        evidence = run_read(
            command,
            parse_thread_info,
            include_raw=include_raw,
        )
        sources.append(evidence.source)
        if evidence.parsed is not None:
            data.update(dict(evidence.parsed.data))

        errors = []
        limitations = []
        core_status = None
        if (
            evidence.parsed is not None
            and "target_data_unavailable" in evidence.parsed.warnings
        ):
            is_dump = str(target_info["session_kind"]).endswith("_dump")
            code = "dump_data_unavailable" if is_dump else "target_data_unavailable"
            message = "The target does not contain the requested thread data."
            limitations.append(limitation_item(code, message, path="data.thread"))
            if not data.get("available"):
                errors.append(error_item(code, message, stage="target"))
                core_status = "unavailable"
        return make_response(
            "windbg_thread",
            sources,
            data,
            errors=errors,
            limitations=limitations,
            core_result_status=core_status,
        )
