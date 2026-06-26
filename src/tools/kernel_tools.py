from ._registry import _exec


def register_kernel_tools(mcp):
    @mcp.tool()
    def windbg_process_list() -> str:
        return _exec("!process 0 0")

    @mcp.tool()
    def windbg_process_info(address: str) -> str:
        return _exec(f"!process {address} 7")

    @mcp.tool()
    def windbg_module_list() -> str:
        return _exec("lm")

    @mcp.tool()
    def windbg_status() -> str:
        return _exec(".lastevent")
