"""Capability-aware kernel pool inspection."""

from ._annotations import READ_ONLY_TOOL
from ._evidence import probe_target_info, resolve_expression, run_read
from ._models import ToolEnvelope
from ._parser import parse_pool
from ._response import (
    error_item,
    limitation_item,
    make_response,
    validate_intent_text,
)


def register_pool_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_pool(
        address: str,
        force: bool = False,
        include_raw: bool = False,
    ) -> ToolEnvelope:
        """Inspect a kernel pool address, with dump-capability checks by default."""

        input_error = validate_intent_text(address, "address")
        if input_error:
            return make_response("windbg_pool", errors=[input_error])

        target, target_info = probe_target_info(include_raw=include_raw)
        sources = [target.source]
        data = {"input": address, "forced": force, **target_info}
        if target_info["target_mode"] != "kernel":
            return make_response(
                "windbg_pool",
                sources,
                data,
                errors=[error_item(
                    "command_unsupported_for_target",
                    "Pool inspection requires a kernel target.",
                    stage="target",
                )],
                core_result_status="unavailable",
            )

        capabilities = target_info.get("capabilities", {})
        pool_capability = (
            capabilities.get("supports_kernel_pool")
            if isinstance(capabilities, dict)
            else None
        )
        if pool_capability is not True and not force:
            if pool_capability is False:
                code = "command_unsupported_for_dump_type"
                limitation_code = "dump_data_unavailable"
                message = (
                    "This dump type does not reliably retain pool metadata; set "
                    "force=true to attempt the command anyway."
                )
            else:
                code = "target_capability_unknown"
                limitation_code = code
                message = (
                    "The target session kind is unknown, so pool-data support "
                    "cannot be determined; set force=true to attempt the command."
                )
            return make_response(
                "windbg_pool",
                sources,
                data,
                errors=[error_item(
                    code,
                    message,
                    stage="target",
                )],
                limitations=[limitation_item(
                    limitation_code,
                    message,
                    path="data.allocations",
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
                "windbg_pool",
                sources,
                data,
                core_result_status="unavailable",
            )
        data["resolved_address"] = resolved_address
        evidence = run_read(
            f"!pool {resolved_address}",
            parse_pool,
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
            message = "Pool metadata for the requested address is unavailable."
            limitations.append(limitation_item(
                "dump_data_unavailable",
                message,
                path="data.allocations",
            ))
            if not data.get("available"):
                errors.append(error_item(
                    "dump_data_unavailable",
                    message,
                    stage="target",
                ))
                core_status = "unavailable"
        return make_response(
            "windbg_pool",
            sources,
            data,
            errors=errors,
            limitations=limitations,
            core_result_status=core_status,
        )
