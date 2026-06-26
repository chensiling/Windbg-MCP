from ._registry import _exec


def register_breakpoint_tools(mcp):
    @mcp.tool()
    def windbg_bp_set(address: str, condition: str = "") -> str:
        if condition:
            return _exec(f'bp {address} "{condition}"')
        return _exec(f"bp {address}")

    @mcp.tool()
    def windbg_bp_list() -> str:
        return _exec("bl")

    @mcp.tool()
    def windbg_bp_clear(id: str) -> str:
        return _exec(f"bc {id}")

    @mcp.tool()
    def windbg_bp_enable(id: str) -> str:
        return _exec(f"be {id}")

    @mcp.tool()
    def windbg_bp_disable(id: str) -> str:
        return _exec(f"bd {id}")
