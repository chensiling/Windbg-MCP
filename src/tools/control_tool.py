"""执行控制工具 — 继续运行、单步。"""

from ._registry import _exec


def register_control_tool(mcp):
    @mcp.tool()
    def windbg_control(action: str, count: str = "1") -> str:
        """控制目标执行流程。

        action 值:
        - "go" 或 "g": 继续运行
        - "step_into" 或 "t": 单步进入
        - "step_over" 或 "p": 单步跳过
        - "step_out" 或 "gu": 单步跳出

        count: 执行次数，默认 1。

        执行后返回目标状态。如果目标仍在运行中（go 未断下），返回提示。
        """
        n = max(1, int(count))

        a = action.lower()
        if a in ("go", "g"):
            return _exec("g")
        elif a in ("step_into", "t"):
            return _exec(f"t {n}")
        elif a in ("step_over", "p"):
            return _exec(f"p {n}")
        elif a in ("step_out", "gu"):
            return _exec(f"gu {n}" if n == 1 else f"gu")
        else:
            return f"error: unknown action '{action}' — valid: go, step_into, step_over, step_out"
