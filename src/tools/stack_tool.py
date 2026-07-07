"""调用栈工具。"""

from ._registry import _exec
from ._parser import parse_stack_k, parse_stack_kp


def register_stack_tool(mcp):
    @mcp.tool()
    def windbg_backtrace(depth: str = "20", show_params: str = "true", frame: str = "") -> str:
        """获取当前线程的调用栈。

        depth: 栈帧数量，默认 20。
        show_params: 是否显示函数参数 ("true"/"1"/"yes" → kP, "false"/"0"/"no" → k)。
        frame: 如果指定帧号，显示该帧的局部变量 (等价于 .frame N; dv /t /i)。

        返回:
        - 不指定 frame: 解析后的栈帧列表（每个含 child_sp, ret_addr, call_site）。
        - 指定 frame: 该帧的局部变量原始输出。
        """
        if frame:
            return _exec(f".frame {frame}; dv /t /i")

        n = max(1, int(depth))
        if show_params.lower() in ("true", "1", "yes"):
            raw = _exec(f"kP {n}")
        else:
            raw = _exec(f"k {n}")

        parsed = parse_stack_kp(raw) if show_params.lower() in ("true", "1", "yes") else parse_stack_k(raw)
        if "raw" in parsed:
            return parsed["raw"]
        return str(parsed)
