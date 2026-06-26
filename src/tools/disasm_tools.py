from ._registry import _exec


def register_disasm_tools(mcp):
    @mcp.tool()
    def windbg_disasm(address: str, count: str = "8") -> str:
        n = max(1, int(count))
        return _exec(f"u {address} L{n}")
