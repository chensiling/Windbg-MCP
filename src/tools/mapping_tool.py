"""Structured kernel virtual-memory mapping inspection."""

from ._annotations import READ_ONLY_TOOL
from ._evidence import probe_target_info, resolve_expression, run_read
from ._models import ToolEnvelope
from ._parser import parse_pte
from ._response import (
    error_item,
    limitation_item,
    make_response,
    validate_intent_text,
)


def register_mapping_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_memory_mapping(
        address: str,
        include_raw: bool = False,
    ) -> ToolEnvelope:
        """Resolve an address and inspect its kernel page-table entries with `!pte`."""

        input_error = validate_intent_text(address, "address")
        if input_error:
            return make_response("windbg_memory_mapping", errors=[input_error])

        target, target_info = probe_target_info(include_raw=include_raw)
        sources = [target.source]
        data = {"input": address, **target_info}
        if target_info["target_mode"] != "kernel":
            return make_response(
                "windbg_memory_mapping",
                sources,
                data,
                errors=[error_item(
                    "command_unsupported_for_target",
                    "Page-table inspection requires a kernel target.",
                    stage="target",
                )],
                core_result_status="unavailable",
            )

        resolution, resolved_address = resolve_expression(
            address,
            include_raw=include_raw,
        )
        sources.append(resolution.source)
        if resolved_address is None:
            return make_response(
                "windbg_memory_mapping",
                sources,
                data,
                core_result_status="unavailable",
            )
        data["resolved_address"] = resolved_address
        evidence = run_read(
            f"!pte {resolved_address}",
            parse_pte,
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
            code = "page_not_captured" if is_dump else "target_data_unavailable"
            message = "Page-table data for the requested address is unavailable."
            limitations.append(limitation_item(code, message, path="data.entries"))
            if not data.get("entries"):
                errors.append(error_item(code, message, stage="target"))
                core_status = "unavailable"
        return make_response(
            "windbg_memory_mapping",
            sources,
            data,
            errors=errors,
            limitations=limitations,
            core_result_status=core_status,
        )
