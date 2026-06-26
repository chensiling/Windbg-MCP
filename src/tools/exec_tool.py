from ._registry import _exec


def register_exec_tool(mcp):
    @mcp.tool()
    def windbg_exec(command: str) -> str:
        return _exec(command)
