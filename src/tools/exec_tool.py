"""Explicit open-world raw WinDbg command escape hatch."""

from ._registry import _exec_result


def register_exec_tool(mcp):
    @mcp.tool()
    def windbg_exec(command: str) -> str:
        result = _exec_result(command, read_only=False, retryable=False)
        if result.status == "completed" and result.complete:
            return result.output
        detail = result.error or f"command ended with status '{result.status}'"
        if result.output:
            return f"error: {detail}\npartial output:\n{result.output}"
        return f"error: {detail}"
