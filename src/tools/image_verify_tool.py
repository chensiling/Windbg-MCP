"""Structured read-only image verification."""

from ._annotations import READ_ONLY_TOOL
from ._evidence import run_read
from ._models import ToolEnvelope
from ._parser import parse_image_verify
from ._response import make_response, validate_module_name


def register_image_verify_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_image_verify(
        module: str,
        include_raw: bool = False,
    ) -> ToolEnvelope:
        """Compare a loaded image with its symbol-backed image using `!chkimg -d`."""

        input_error = validate_module_name(module)
        if input_error:
            return make_response("windbg_image_verify", errors=[input_error])
        normalized = module.strip()
        evidence = run_read(
            f"!chkimg -d {normalized}",
            parse_image_verify,
            include_raw=include_raw,
            timeout=120,
        )
        data = {"module": normalized}
        if evidence.parsed is not None:
            data.update(dict(evidence.parsed.data))
        return make_response("windbg_image_verify", [evidence.source], data)
