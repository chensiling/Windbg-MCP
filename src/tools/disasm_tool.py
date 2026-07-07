"""反汇编工具。"""

from ._registry import _exec
from ._parser import parse_disassembly


def register_disasm_tool(mcp):
    @mcp.tool()
    def windbg_disassemble(at: str, count: str = "8") -> str:
        """反汇编指定地址处的指令。

        at: 起始地址或表达式（支持 @rip, @rsp, 0x..., 符号名）。
        count: 指令数量，默认 8。

        返回指令列表（每条含 address, bytes, instruction），首条附 symbol 标签。
        """
        n = max(1, int(count))
        raw = _exec(f"u {at} L{n}")
        parsed = parse_disassembly(raw)
        if "raw" in parsed:
            return parsed["raw"]
        return str(parsed)
