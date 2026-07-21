"""Structured loaded-module details."""

from ._annotations import READ_ONLY_TOOL
from ._evidence import run_read
from ._models import ToolEnvelope
from ._parser import parse_module_info
from ._response import make_response, validate_module_name


def register_module_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_module(module: str, include_raw: bool = False) -> ToolEnvelope:
        """Return structured `lmvm` details for one loaded module."""

        input_error = validate_module_name(module)
        if input_error:
            return make_response("windbg_module", errors=[input_error])
        normalized = module.strip()
        evidence = run_read(
            f"lmvm {normalized}",
            parse_module_info,
            include_raw=include_raw,
        )
        data = {"input": normalized}
        if evidence.parsed is not None:
            data.update(dict(evidence.parsed.data))
        return make_response(
            "windbg_module",
            [evidence.source],
            data,
            core_result_status=(
                "empty" if data.get("found") is False else None
            ),
        )
