"""Explicit open-world raw WinDbg command escape hatch."""

from ._annotations import RAW_EXEC_TOOL
from ._registry import _exec_result


def register_exec_tool(mcp):
    @mcp.tool(
        annotations=RAW_EXEC_TOOL,
        structured_output=False,
    )
    def windbg_exec(command: str) -> str:
        """Execute a raw, open-world WinDbg command that may be destructive."""
        result = _exec_result(command, read_only=False, retryable=False)
        if result.status == "completed" and result.complete:
            return result.output
        detail = result.error or f"command ended with status '{result.status}'"
        if result.output:
            return f"error: {detail}\npartial output:\n{result.output}"
        return f"error: {detail}"
