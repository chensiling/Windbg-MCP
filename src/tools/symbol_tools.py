from ._registry import _exec


def register_symbol_tools(mcp):
    @mcp.tool()
    def windbg_sym_lookup(pattern: str, type: str = "function") -> str:
        return _exec(f"x {pattern}")

    @mcp.tool()
    def windbg_sym_name(address: str) -> str:
        return _exec(f"ln {address}")
