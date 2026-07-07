"""调用栈工具。"""

from ._registry import _exec
from ._parser import parse_stack_k, parse_stack_kp
from ._response import is_error_output, make_error, make_response, next_action, parse_int_arg, parsed_response


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
            frame_no, arg_error = parse_int_arg(frame, "frame", min_value=0, max_value=200)
            if arg_error:
                return make_response("windbg_backtrace", "", ok=False, errors=[arg_error])
            command = f".frame {frame_no}; dv /t /i"
            raw = _exec(command)
            if is_error_output(raw):
                return make_error("windbg_backtrace", command, "debugger_error", raw.strip(), raw=raw)
            return make_response(
                "windbg_backtrace",
                command,
                data={"frame": frame_no, "locals_raw": raw.strip()},
                raw=raw,
            )

        n, arg_error = parse_int_arg(depth, "depth", default=20, min_value=1, max_value=200)
        if arg_error:
            return make_response("windbg_backtrace", "", ok=False, errors=[arg_error])

        if show_params.lower() in ("true", "1", "yes"):
            command = f"kP {n}"
            raw = _exec(command)
        else:
            command = f"k {n}"
            raw = _exec(command)

        parsed = parse_stack_kp(raw) if show_params.lower() in ("true", "1", "yes") else parse_stack_k(raw)
        actions = []
        if "raw" not in parsed and parsed.get("frames"):
            actions.append(next_action("windbg_disassemble", {"at": "@rip", "count": "8"}, "Inspect instructions near the current frame."))
        return parsed_response(
            "windbg_backtrace",
            command,
            parsed,
            raw,
            data={**parsed, "depth": n} if "raw" not in parsed else None,
            next_actions=actions,
        )
