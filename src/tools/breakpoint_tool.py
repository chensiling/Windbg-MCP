"""断点管理工具。"""

from ._registry import _exec


def register_breakpoint_tool(mcp):
    @mcp.tool()
    def windbg_breakpoint(action: str, target: str = "", condition: str = "", id: str = "") -> str:
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
                return "error: 'set' action requires 'target' parameter (address or symbol)"
            if condition:
                return _exec(f'bp {target} "{condition}"')
            return _exec(f"bp {target}")

        elif a == "list":
            return _exec("bl")

        elif a == "clear":
            if not id:
                return "error: 'clear' action requires 'id' parameter (breakpoint number, or * for all)"
            return _exec(f"bc {id}")

        elif a == "enable":
            if not id:
                return "error: 'enable' action requires 'id' parameter"
            return _exec(f"be {id}")

        elif a == "disable":
            if not id:
                return "error: 'disable' action requires 'id' parameter"
            return _exec(f"bd {id}")

        else:
            return f"error: unknown action '{action}' — valid: set, list, clear, enable, disable"
