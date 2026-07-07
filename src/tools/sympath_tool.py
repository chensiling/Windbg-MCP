"""符号路径管理工具。"""

from typing import Literal

from ._registry import _exec
from ._parser import parse_modules
from ._response import is_error_output, make_error, make_response, next_action, parsed_response


def _symbol_health(modules: list[dict[str, str]]) -> dict[str, object]:
    if not modules:
        return {"status": "unknown", "missing_modules": []}

    missing = []
    partial = []
    for mod in modules:
        info = mod.get("info", "").lower()
        if "deferred" in info or "no symbols" in info:
            missing.append(mod.get("name", ""))
        elif "export symbols" in info:
            partial.append(mod.get("name", ""))

    if missing:
        status = "bad" if len(missing) == len(modules) else "partial"
    elif partial:
        status = "partial"
    else:
        status = "good"

    return {
        "status": status,
        "missing_modules": [m for m in missing if m],
        "partial_modules": [m for m in partial if m],
    }


def register_sympath_tool(mcp):
    @mcp.tool()
    def windbg_sympath(action: Literal["show", "set", "reload", "check"], path: str = "", module: str = "") -> str:
        """管理调试符号路径——不需要记忆 WinDbg 语法。

        action 值:
        - "show": 显示当前符号路径。无需其他参数。
        - "set": 设置符号路径。需要 path（符号服务器或本地路径）。
        - "reload": 重载符号。可选 module 指定模块名，不指定则重载全部。
        - "check": 检查模块符号加载状态。可选 module 过滤。

        Microsoft 公共符号服务器:
        https://msdl.microsoft.com/download/symbols
        """
        a = action.lower().strip()

        if a == "show":
            command = ".sympath"
            raw = _exec(command)
            if is_error_output(raw):
                return make_error("windbg_sympath", command, "debugger_error", raw.strip(), raw=raw)
            return make_response("windbg_sympath", command, data={"sympath_raw": raw.strip()}, raw=raw)

        if a == "set":
            if not path:
                return make_error(
                    "windbg_sympath",
                    "",
                    "invalid_argument",
                    "'set' action requires 'path'. Example: srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
                )
            command = f".sympath {path}"
            raw = _exec(command)
            if is_error_output(raw):
                return make_error("windbg_sympath", command, "debugger_error", raw.strip(), raw=raw)
            return make_response(
                "windbg_sympath",
                command,
                data={"action": "set", "path": path, "status": "completed"},
                raw=raw,
                next_actions=[next_action("windbg_sympath", {"action": "reload"}, "Reload symbols after changing the symbol path.")],
            )

        if a == "reload":
            command = f".reload /f {module}" if module else ".reload /f"
            raw = _exec(command)
            if is_error_output(raw):
                return make_error("windbg_sympath", command, "debugger_error", raw.strip(), raw=raw)
            return make_response(
                "windbg_sympath",
                command,
                data={"action": "reload", "module": module or None, "status": "completed"},
                raw=raw,
                next_actions=[next_action("windbg_sympath", {"action": "check", "module": module} if module else {"action": "check"}, "Check symbol load status after reload.")],
            )

        if a == "check":
            command = f"lm m {module}" if module else "lm"
            raw = _exec(command)
            parsed = parse_modules(raw)
            if "raw" not in parsed:
                data = {**parsed, "symbol_health": _symbol_health(parsed.get("modules", []))}
                actions = []
                if data["symbol_health"]["status"] in ("bad", "partial"):
                    actions.append(next_action("windbg_sympath", {"action": "set", "path": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"}, "Set a public symbol path before reloading missing symbols."))
                return parsed_response("windbg_sympath", command, parsed, raw, data=data, next_actions=actions)
            return parsed_response("windbg_sympath", command, parsed, raw)

        return make_error("windbg_sympath", "", "invalid_argument", "unknown action; valid: show, set, reload, check")
