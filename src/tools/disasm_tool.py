"""反汇编工具。"""

from ._registry import _exec
from ._parser import parse_disassembly
from ._response import make_response, parse_int_arg, parsed_response


def register_disasm_tool(mcp):
    @mcp.tool()
    def windbg_disassemble(at: str, count: str = "8") -> str:
        """反汇编指定地址处的指令。

        at: 起始地址或表达式（支持 @rip, @rsp, 0x..., 符号名）。
        count: 指令数量，默认 8。

        返回指令列表（每条含 address, bytes, instruction），首条附 symbol 标签。
        """
        n, arg_error = parse_int_arg(count, "count", default=8, min_value=1, max_value=128)
        if arg_error:
            return make_response("windbg_disassemble", "", ok=False, errors=[arg_error])

        command = f"u {at} L{n}"
        raw = _exec(command)
        parsed = parse_disassembly(raw)
        return parsed_response(
            "windbg_disassemble",
            command,
            parsed,
            raw,
            data={**parsed, "at": at, "count": n} if "raw" not in parsed else None,
            next_actions=[],
        )
