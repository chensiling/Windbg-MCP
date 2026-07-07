"""符号路径管理工具。"""

from ._registry import _exec


def register_sympath_tool(mcp):
    @mcp.tool()
    def windbg_sympath(action: str, path: str = "", module: str = "") -> str:
        """管理调试符号路径——不需要记忆 WinDbg 语法。

        action 值:
        - "show": 显示当前符号路径。无需其他参数。
        - "set": 设置符号路径。需要 path（符号服务器或本地路径）。
          示例: windbg_sympath("set", "srv*c:\\symbols*https://msdl.microsoft.com/download/symbols")
        - "reload": 重载符号。可选 module 指定模块名，不指定则重载全部。
          示例: windbg_sympath("reload") — 重载全部
          示例: windbg_sympath("reload", module="ntdll") — 只重载 ntdll
        - "check": 检查模块符号加载状态。可选 module 过滤。
          示例: windbg_sympath("check") — 列出所有模块的符号状态
          示例: windbg_sympath("check", module="myapp") — 只查 myapp

        Microsoft 公共符号服务器:
        https://msdl.microsoft.com/download/symbols
        """
        a = action.lower().strip()

        if a == "show":
            return _exec(".sympath")

        elif a == "set":
            if not path:
                return "error: 'set' 需要 path 参数。示例: windbg_sympath('set', 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols')"
            return _exec(f".sympath {path}")

        elif a == "reload":
            if module:
                return _exec(f".reload /f {module}")
            return _exec(".reload /f")

        elif a == "check":
            if module:
                return _exec(f"lm m {module}")
            return _exec("lm")

        else:
            return "error: 未知 action。可用: show, set, reload, check"
