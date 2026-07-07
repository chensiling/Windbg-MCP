"""表达式求值工具。"""

from ._registry import _exec
from ._parser import parse_evaluate
from ._response import make_error, parsed_response


def register_eval_tool(mcp):
    @mcp.tool()
    def windbg_evaluate(expression: str) -> str:
        """计算 WinDbg 表达式并返回结果。

        支持:
        - 寄存器: @rcx, @rip, @rsp
        - 指针间接引用: poi(@rsp+8), dwo(@rcx+0x10), qwo(@rax)
        - 算术: @rcx + 0x10, @rsp - 8
        - 伪寄存器: $teb, $peb, $proc, $thread
        - sizeof: sizeof(ntdll!_TEB)
        - 类型转换: (ntdll!_TEB *)@$teb

        示例:
        - windbg_evaluate("@rcx + 0x10")
        - windbg_evaluate("poi(@rsp+8)")
        - windbg_evaluate("sizeof(nt!_EPROCESS)")
        """
        if not expression.strip():
            return make_error("windbg_evaluate", "", "invalid_argument", "'expression' is required.")

        command = f"? {expression}"
        raw = _exec(command)
        parsed = parse_evaluate(raw)
        return parsed_response(
            "windbg_evaluate",
            command,
            parsed,
            raw,
            data={**parsed, "expression": expression} if "raw" not in parsed else None,
            next_actions=[],
        )
