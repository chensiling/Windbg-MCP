"""内存读写工具。"""

from typing import Literal

from ._registry import _exec
from ._parser import parse_memory_dump
from ._response import is_error_output, make_error, make_response, next_action, parse_int_arg, parsed_response


def register_memory_tool(mcp):
    @mcp.tool()
    def windbg_read_memory(address: str, size: str = "0x20", format: Literal["auto", "byte", "b", "word", "w", "dword", "d", "qword", "q", "ascii", "a"] = "auto") -> str:
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
        f = fmt_map.get(format.lower(), format.lower())
        if f not in ("b", "w", "d", "q", "a"):
            return make_error(
                "windbg_read_memory",
                "",
                "invalid_argument",
                "format must be one of auto, byte, word, dword, qword, ascii.",
            )

        n, arg_error = parse_int_arg(size, "size", default=0x20, min_value=1, max_value=0x400)
        if arg_error:
            return make_response("windbg_read_memory", "", ok=False, errors=[arg_error])

        command = f"d{f} {address} L{n:x}"
        raw = _exec(command)
        parsed = parse_memory_dump(raw)
        actions = []
        if "raw" in parsed and not is_error_output(raw):
            actions.append(next_action("windbg_evaluate", {"expression": address}, "Validate the address expression before reading memory again."))
        return parsed_response(
            "windbg_read_memory",
            command,
            parsed,
            raw,
            data={**parsed, "requested_address": address, "requested_format": format, "requested_size": n} if "raw" not in parsed else None,
            next_actions=actions,
        )

    @mcp.tool()
    def windbg_write_memory(address: str, values: str) -> str:
        """写入内存。

        address: 目标地址（支持 @rip, 0x..., 符号名）。
        values: 空格分隔的十六进制值。

        示例: windbg_write_memory("0x7ff600010000", "90 90") — 写入两个 NOP
        """
        if not address.strip():
            return make_error("windbg_write_memory", "", "invalid_argument", "'address' is required.")
        if not values.strip():
            return make_error("windbg_write_memory", "", "invalid_argument", "'values' is required.")

        command = f"eb {address} {values}"
        raw = _exec(command)
        if is_error_output(raw):
            return make_error("windbg_write_memory", command, "debugger_error", raw.strip(), raw=raw)

        return make_response(
            "windbg_write_memory",
            command,
            data={"address": address, "values": values, "status": "completed"},
            raw=raw,
            next_actions=[next_action("windbg_read_memory", {"address": address, "size": "0x20", "format": "byte"}, "Verify the bytes after writing memory.")],
        )
