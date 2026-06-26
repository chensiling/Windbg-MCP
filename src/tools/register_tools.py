from ._registry import _exec


def register_register_tools(mcp):
    @mcp.tool()
    def windbg_reg_read(reg: str = "") -> str:
        if reg:
            return _exec(f"r {reg}")
        return _exec("r")

    @mcp.tool()
    def windbg_reg_write(reg: str, value: str) -> str:
        return _exec(f"r {reg}={value}")
