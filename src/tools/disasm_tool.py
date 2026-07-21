"""Disassembly intent tool."""

from ._annotations import READ_ONLY_TOOL
from ._evidence import probe_target_info, resolve_expression, run_read
from ._models import ToolEnvelope
from ._parser import parse_disassembly
from ._response import (
    error_item,
    limitation_item,
    make_response,
    parse_int_arg,
    validate_intent_text,
)


def register_disasm_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_disassemble(at: str, count: str = "8") -> ToolEnvelope:
        """Resolve an address expression and disassemble a bounded instruction range."""

        input_error = validate_intent_text(at, "at")
        if input_error:
            return make_response("windbg_disassemble", errors=[input_error])
        count_value, count_error = parse_int_arg(
            count,
            "count",
            default=8,
            min_value=1,
            max_value=128,
        )
        if count_error:
            return make_response("windbg_disassemble", errors=[count_error])

        resolution, resolved_address = resolve_expression(at)
        sources = [resolution.source]
        data = {"input": at, "count": count_value}
        if resolved_address is None:
            return make_response("windbg_disassemble", sources, data)

        data["resolved_address"] = resolved_address
        disassembly = run_read(
            f"u {resolved_address} L0n{count_value}",
            parse_disassembly,
        )
        sources.append(disassembly.source)
        if disassembly.parsed is not None:
            data.update(dict(disassembly.parsed.data))
        data["returned_count"] = len(data.get("instructions", []))
        data["range_complete"] = (
            data["returned_count"] == count_value
            and data.get("complete_range", True)
        )

        errors = []
        limitations = []
        core_status = None
        if (
            disassembly.parsed is not None
            and "memory_access_error" in disassembly.parsed.warnings
        ):
            target_evidence, target_info = probe_target_info()
            sources.append(target_evidence.source)
            session_kind = str(target_info["session_kind"])
            data["target_mode"] = target_info["target_mode"]
            data["session_kind"] = session_kind
            data["capabilities"] = target_info["capabilities"]
            is_dump = session_kind.endswith("_dump")
            code = "dump_data_unavailable" if is_dump else "memory_access_error"
            message = (
                "The dump did not capture the complete instruction range."
                if is_dump
                else "The target could not provide the complete instruction range."
            )
            limitations.append(limitation_item(
                code,
                message,
                path="data.instructions",
            ))
            if not data.get("instructions"):
                errors.append(error_item(code, message, stage="target"))
                core_status = "unavailable"
        return make_response(
            "windbg_disassemble",
            sources,
            data,
            errors=errors,
            limitations=limitations,
            core_result_status=core_status,
        )
