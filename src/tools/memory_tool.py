"""内存读写工具。"""

from ._registry import _exec
from ._parser import parse_memory_dump


def register_memory_tool(mcp):
    @mcp.tool()
    def windbg_read_memory(address: str, size: str = "0x20", format: str = "auto") -> str:
        """读取指定地址的内存。

        address: 起始地址（支持 @rip, @rsp+0x20, 0x..., 符号名）。
        size: 读取元素数量，默认 0x20。
        format: 数据格式——
          "byte" 或 "b": 字节 (db)
          "word" 或 "w": 字 (dw)
          "dword" 或 "d": 双字 (dd)
          "qword" 或 "q": 四字 (dq)
          "ascii" 或 "a": ASCII 字符串 (da)
          "auto" 或未指定: 用 dd 读取（最常用）

        返回结构化数据：address, format, data[{offset, value, ascii?}]。
        """
        fmt_map = {"byte": "b", "word": "w", "dword": "d", "qword": "q", "ascii": "a", "auto": "d"}
        f = fmt_map.get(format.lower(), "d")
        raw = _exec(f"d{f} {address} L{size}")
        parsed = parse_memory_dump(raw)
        if "raw" in parsed:
            return parsed["raw"]
        return str(parsed)

    @mcp.tool()
    def windbg_write_memory(address: str, values: str) -> str:
        """写入内存。

        address: 目标地址（支持 @rip, 0x..., 符号名）。
        values: 空格分隔的十六进制值。

        示例: windbg_write_memory("0x7ff600010000", "90 90") — 写入两个 NOP
        """
        return _exec(f"e{address} {values}")
