from ._registry import _exec


def register_control_tools(mcp):
    @mcp.tool()
    def windbg_go() -> str:
        return _exec("g")

    @mcp.tool()
    def windbg_step_into(count: str = "1") -> str:
        n = max(1, int(count))
        return _exec(f"t {n}")

    @mcp.tool()
    def windbg_step_over(count: str = "1") -> str:
        n = max(1, int(count))
        return _exec(f"p {n}")

    @mcp.tool()
    def windbg_step_out() -> str:
        return _exec("gu")
