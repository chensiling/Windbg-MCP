"""断点管理工具。"""

from typing import Literal

from ._registry import _exec
from ._parser import parse_breakpoints
from ._response import is_error_output, make_error, make_response, next_action, parsed_response


def register_breakpoint_tool(mcp):
    @mcp.tool()
    def windbg_breakpoint(action: Literal["set", "list", "clear", "enable", "disable"], target: str = "", condition: str = "", id: str = "") -> str:
        """管理断点。

        action 值:
        - "set": 设置断点。需要 target（地址或符号），可选 condition（条件表达式）。
          示例: windbg_breakpoint("set", target="ntdll!NtCreateFile")
          示例: windbg_breakpoint("set", target="myapp!main", condition="@rcx == 0")
        - "list": 列出所有断点。无需其他参数。
        - "clear": 清除断点。需要 id（断点编号，支持 * 清除全部）。
          示例: windbg_breakpoint("clear", id="0")
          示例: windbg_breakpoint("clear", id="*")
        - "enable": 启用断点。需要 id。
        - "disable": 禁用断点。需要 id。

        返回断点操作结果或断点列表。
        """
        a = action.lower().strip()

        if a == "set":
            if not target:
                return make_error("windbg_breakpoint", "", "invalid_argument", "'set' action requires 'target' parameter.")
            if condition:
                command = f'bp {target} "{condition}"'
            else:
                command = f"bp {target}"
            raw = _exec(command)
            if is_error_output(raw):
                return make_error("windbg_breakpoint", command, "debugger_error", raw.strip(), raw=raw)
            return make_response(
                "windbg_breakpoint",
                command,
                data={"action": "set", "target": target, "condition": condition or None, "status": "completed"},
                raw=raw,
                next_actions=[next_action("windbg_breakpoint", {"action": "list"}, "Confirm the breakpoint was installed.")],
            )

        elif a == "list":
            command = "bl"
            raw = _exec(command)
            parsed = parse_breakpoints(raw)
            return parsed_response("windbg_breakpoint", command, parsed, raw)

        elif a == "clear":
            if not id:
                return make_error("windbg_breakpoint", "", "invalid_argument", "'clear' action requires 'id' parameter.")
            command = f"bc {id}"

        elif a == "enable":
            if not id:
                return make_error("windbg_breakpoint", "", "invalid_argument", "'enable' action requires 'id' parameter.")
            command = f"be {id}"

        elif a == "disable":
            if not id:
                return make_error("windbg_breakpoint", "", "invalid_argument", "'disable' action requires 'id' parameter.")
            command = f"bd {id}"

        else:
            return make_error(
                "windbg_breakpoint",
                "",
                "invalid_argument",
                f"unknown action '{action}'; valid: set, list, clear, enable, disable",
            )

        raw = _exec(command)
        if is_error_output(raw):
            return make_error("windbg_breakpoint", command, "debugger_error", raw.strip(), raw=raw)

        return make_response(
            "windbg_breakpoint",
            command,
            data={"action": a, "id": id, "status": "completed"},
            raw=raw,
            next_actions=[next_action("windbg_breakpoint", {"action": "list"}, "Refresh the breakpoint list.")],
        )
