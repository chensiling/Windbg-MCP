from ._registry import _exec


def register_memory_tools(mcp):
    @mcp.tool()
    def windbg_mem_read(address: str, size: str = "0x20", format: str = "dword") -> str:
        fmt_map = {"byte": "b", "word": "w", "dword": "d", "qword": "q", "ascii": "a"}
        f = fmt_map.get(format, "d")
        return _exec(f"d{f} {address} L{size}")

    @mcp.tool()
    def windbg_mem_write(address: str, bytes: str) -> str:
        return _exec(f"e{address} {bytes}")

    @mcp.tool()
    def windbg_mem_search(start: str, end: str, pattern: str) -> str:
        return _exec(f"s -b {start} {end} {pattern}")
