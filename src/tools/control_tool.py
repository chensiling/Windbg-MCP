"""执行控制工具 — 继续运行、单步。"""

from typing import Literal

from ._registry import _exec
from ._response import is_error_output, make_error, make_response, next_action, parse_int_arg


def register_control_tool(mcp):
    @mcp.tool()
    def windbg_control(action: Literal["go", "g", "step_into", "t", "step_over", "p", "step_out", "gu"], count: str = "1") -> str:
        """控制目标执行流程。

        action 值:
        - "go" 或 "g": 继续运行
        - "step_into" 或 "t": 单步进入
        - "step_over" 或 "p": 单步跳过
        - "step_out" 或 "gu": 单步跳出

        count: 执行次数，默认 1。

        执行后返回目标状态。如果目标仍在运行中（go 未断下），返回提示。
        """
        n, arg_error = parse_int_arg(count, "count", default=1, min_value=1, max_value=1000)
        if arg_error:
            return make_response("windbg_control", "", ok=False, errors=[arg_error])

        a = action.lower()
        if a in ("go", "g"):
            command = "g"
        elif a in ("step_into", "t"):
            command = f"t {n}"
        elif a in ("step_over", "p"):
            command = f"p {n}"
        elif a in ("step_out", "gu"):
            command = f"gu {n}" if n == 1 else "gu"
        else:
            return make_error(
                "windbg_control",
                "",
                "invalid_argument",
                f"unknown action '{action}'; valid: go, step_into, step_over, step_out",
            )

        raw = _exec(command)
        if is_error_output(raw):
            return make_error("windbg_control", command, "debugger_error", raw.strip(), raw=raw)

        actions = []
        if a not in ("go", "g"):
            actions.append(next_action("windbg_context", {"scope": "default"}, "Refresh state after execution control."))

        return make_response(
            "windbg_control",
            command,
            data={"action": a, "count": n, "status": "completed"},
            raw=raw,
            next_actions=actions,
        )
