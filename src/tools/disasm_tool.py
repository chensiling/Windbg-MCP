"""Disassembly intent tool."""

from ._evidence import resolve_expression, run_read
from ._models import ToolEnvelope
from ._parser import parse_disassembly
from ._response import make_response, parse_int_arg, validate_intent_text


def register_disasm_tool(mcp):
    @mcp.tool()
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
        return make_response("windbg_disassemble", sources, data)
