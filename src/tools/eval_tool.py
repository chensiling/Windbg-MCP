"""WinDbg expression evaluation tool."""

from ._evidence import run_read
from ._models import ToolEnvelope
from ._parser import parse_evaluate
from ._response import make_response, validate_intent_text


def register_eval_tool(mcp):
    @mcp.tool()
    def windbg_evaluate(expression: str) -> ToolEnvelope:
        """Evaluate one WinDbg expression without composing debugger commands."""

        input_error = validate_intent_text(expression, "expression")
        if input_error:
            return make_response("windbg_evaluate", errors=[input_error])

        evidence = run_read(f"? {expression}", parse_evaluate)
        data = {"input": expression}
        if evidence.parsed is not None:
            value = evidence.parsed.data.get("hex")
            decimal = evidence.parsed.data.get("decimal")
            if isinstance(value, str):
                data["value"] = value
            if isinstance(decimal, int):
                data["decimal"] = str(decimal)
        return make_response("windbg_evaluate", [evidence.source], data)
