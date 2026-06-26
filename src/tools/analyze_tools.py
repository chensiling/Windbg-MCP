from ._registry import _exec


def register_analyze_tools(mcp):
    @mcp.tool()
    def windbg_analyze() -> str:
        return _exec("!analyze -v")

    @mcp.tool()
    def windbg_bugcheck() -> str:
        return _exec(".bugcheck")
