from ._registry import _exec


def register_type_tools(mcp):
    @mcp.tool()
    def windbg_dt(type: str, address: str = "", depth: str = "1") -> str:
        d = max(0, int(depth))
        addr = address if address else ""
        if d > 0:
            return _exec(f"dt {type} {addr} -r{d}")
        return _exec(f"dt {type} {addr}")

    @mcp.tool()
    def windbg_eval(expression: str) -> str:
        return _exec(f"? {expression}")
