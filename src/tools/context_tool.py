"""上下文工具 — 获取当前调试状态快照。一次调用替代多次分散查询。"""

from typing import Literal

from ._registry import _exec
from ._parser import (
    parse_modules,
    parse_process_list,
    parse_registers,
    parse_stack_kp,
    parse_thread_list_kernel,
    parse_thread_list_user,
)
from ._response import error_item, is_error_output, make_error, make_response, next_action

_MODULE_LIMIT = 60


def _detect_debug_mode(vertarget_raw: str) -> str:
    text = vertarget_raw.lower()
    if "dump" in text:
        return "dump"
    if "kernel" in text or "kd>" in text:
        return "kernel"
    if "user" in text or "cdb" in text:
        return "user"
    return "unknown"


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


def _split_sections(raw: str) -> tuple[str, str, str, str, str]:
    target_raw = ""
    reg_raw = raw
    stack_raw = ""
    event_raw = ""
    modules_raw = ""

    if "__CTX0__" not in raw:
        return target_raw, reg_raw, stack_raw, event_raw, modules_raw

    target_raw, rest = raw.split("__CTX0__", 1)
    if "__CTX1__" not in rest:
        return target_raw, rest, stack_raw, event_raw, modules_raw

    reg_raw, rest = rest.split("__CTX1__", 1)
    if "__CTX2__" not in rest:
        return target_raw, reg_raw, rest, event_raw, modules_raw

    stack_raw, rest = rest.split("__CTX2__", 1)
    if "__CTX3__" not in rest:
        return target_raw, reg_raw, stack_raw, rest, modules_raw

    event_raw, modules_raw = rest.split("__CTX3__", 1)
    return target_raw, reg_raw, stack_raw, event_raw, modules_raw


def register_context_tool(mcp):
    @mcp.tool()
    def windbg_context(
        scope: Literal["default", "threads", "processes", "all"] = "default",
        include_raw: bool = False,
    ) -> str:
        """获取当前调试状态快照——一次调用，返回 LLM 最常用的全部上下文。

        scope 值:
        - "default" (默认): 寄存器 + 当前指令 + 栈顶帧 + 最近事件 + 模块摘要。
        - "threads": default + 线程列表（内核态解析 !running -ti，用户态解析 ~）。
        - "processes": default + 内核进程列表。
        - "all": 全部信息。

        include_raw:
        - False (默认): 不在 envelope 中返回完整原始输出，模块列表按 top-N 截断，避免挤占上下文。
        - True: 返回完整原始输出和完整模块列表，用于深度排查。

        返回统一 JSON envelope；结构化主结果在 data 字段中。
        """
        s = scope.lower().strip()
        if s not in ("default", "threads", "processes", "all"):
            return make_error("windbg_context", "", "invalid_argument", "scope must be one of default, threads, processes, all.")

        core_command = (
            'vertarget; .printf "__CTX0__\\n"; '
            'r; .printf "__CTX1__\\n"; '
            'kP 1; .printf "__CTX2__\\n"; '
            '.lastevent; .printf "__CTX3__\\n"; lm'
        )
        try:
            raw = _exec(core_command)
        except Exception as e:
            return make_error("windbg_context", core_command, "exec_failed", f"context collection failed: {e}")

        if is_error_output(raw):
            return make_error(
                "windbg_context",
                core_command,
                "debugger_error",
                raw.strip(),
                raw=raw,
                next_actions=[next_action("windbg_exec", {"command": ".server tcp:port=50000"}, "Start or verify the WinDbg remote server before reconnecting the MCP server.")],
            )

        target_raw, reg_raw, stack_raw, event_raw, modules_raw = _split_sections(raw)
        mode = _detect_debug_mode(target_raw)
        commands: list[str] = [core_command]
        errors: list[dict[str, object]] = []
        actions = []

        data: dict[str, object] = {
            "debugger_connected": True,
            "target_state": "unknown",
            "debug_mode": mode,
            "target_raw": target_raw.strip(),
        }

        parsed = parse_registers(reg_raw)
        if "raw" not in parsed:
            data["target_state"] = "broken"
            data["registers"] = parsed.get("registers", {})
            data["flags"] = parsed.get("flags", {})
            data["segments"] = parsed.get("segments", {})
            cur = parsed.get("current", {})
            if cur:
                data["current_instruction"] = cur
                actions.append(next_action("windbg_disassemble", {"at": "@rip", "count": "8"}, "Inspect instructions near the current instruction pointer."))
        else:
            errors.append(error_item("parse_failed", "Could not parse register output."))
            actions.append(next_action("windbg_exec", {"command": "r"}, "Verify that the target is broken in and registers are available."))

        parsed = parse_stack_kp(stack_raw)
        if "raw" not in parsed and parsed.get("frames"):
            data["stack_frame"] = parsed["frames"][0]
            actions.append(next_action("windbg_backtrace", {"depth": "30"}, "Collect a deeper parsed call stack."))
        else:
            errors.append(error_item("parse_failed", "Could not parse stack output."))

        if event_raw.strip():
            data["last_event"] = event_raw.strip()

        parsed = parse_modules(modules_raw)
        if "raw" not in parsed:
            modules = parsed.get("modules", [])
            data["module_count"] = len(modules)
            if include_raw or len(modules) <= _MODULE_LIMIT:
                data["modules"] = modules
            else:
                data["modules"] = modules[:_MODULE_LIMIT]
                data["modules_truncated"] = True
                errors.append(error_item(
                    "output_truncated",
                    f"Showing first {_MODULE_LIMIT} of {len(modules)} modules; call with include_raw=true for the full list.",
                    recoverable=True,
                ))
            data["symbol_health"] = _symbol_health(modules)
            if data["symbol_health"]["status"] in ("bad", "partial"):
                actions.append(next_action("windbg_sympath", {"action": "set", "path": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"}, "Symbols appear incomplete; set a public symbol path before reloading."))
        else:
            data["modules_raw"] = modules_raw.strip()
            data["symbol_health"] = {"status": "unknown", "missing_modules": []}
            errors.append(error_item("parse_failed", "Could not parse module list."))

        if s in ("threads", "all"):
            if mode == "kernel":
                thread_command = "!running -ti"
                thread_raw = _exec(thread_command)
                commands.append(thread_command)
                parsed = parse_thread_list_kernel(thread_raw)
                if "raw" not in parsed:
                    data["processors"] = parsed.get("processors", [])
                    if parsed.get("system_processors"):
                        data["system_processors"] = parsed["system_processors"]
                    if parsed.get("idle_processors"):
                        data["idle_processors"] = parsed["idle_processors"]
                else:
                    data["threads_raw"] = thread_raw.strip()
                    errors.append(error_item("parse_failed", "Could not parse kernel !running -ti output."))
                    actions.append(next_action("windbg_context", {"scope": "processes"}, "Use process context for kernel debugging if thread parsing is unavailable."))
            else:
                thread_command = "~"
                thread_raw = _exec(thread_command)
                commands.append(thread_command)
                parsed = parse_thread_list_user(thread_raw)
                if "raw" not in parsed:
                    data["threads"] = parsed.get("threads", [])
                else:
                    data["threads_raw"] = thread_raw.strip()
                    errors.append(error_item("parse_failed", "Could not parse user-mode thread list."))
                    if mode == "unknown":
                        actions.append(next_action("windbg_context", {"scope": "processes"}, "If this is kernel debugging, inspect process context instead of user-mode threads."))

        if s in ("processes", "all"):
            proc_command = "!process 0 0"
            proc_raw = _exec(proc_command)
            commands.append(proc_command)
            parsed = parse_process_list(proc_raw)
            if "raw" not in parsed:
                data["processes"] = parsed.get("processes", [])
            else:
                data["processes_raw"] = proc_raw.strip()
                errors.append(error_item("parse_failed", "Could not parse process list."))

        if data.get("target_state") != "broken":
            actions.append(next_action("windbg_exec", {"command": "r"}, "Most inspection commands require the target to be broken in."))

        return make_response(
            "windbg_context",
            commands,
            data=data,
            mode=mode,
            raw=raw if include_raw else "",
            errors=errors,
            next_actions=actions,
        )
