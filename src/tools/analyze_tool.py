"""崩溃分析工具。"""

from typing import Literal

from ._registry import _exec
from ._parser import parse_analyze, parse_registers, parse_stack_kp
from ._response import is_error_output, make_error, make_response, next_action, parsed_response


def register_analyze_tool(mcp):
    @mcp.tool()
    def windbg_analyze(scope: Literal["crash", "hang", "quick"] = "crash") -> str:
        """运行自动化崩溃/挂起分析。

        scope 值:
        - "crash": 完整崩溃分析。运行 !analyze -v，同时收集寄存器、调用栈。
          返回: {bugcheck_code?, faulting_ip?, process_name?, stack_text?, registers, backtrace}
        - "hang": 挂起分析。使用 !analyze -v -hang 并收集所有线程栈。
          返回分析输出。
        - "quick": 快速分析。仅运行 !analyze -v，不收集额外数据。
          返回: {bugcheck_code?, faulting_ip?, process_name?, image_name?, stack_text?}

        返回 JSON 或结构化字典。解析失败时返回原始文本。
        """
        s = scope.lower().strip()

        if s == "quick":
            command = "!analyze -v"
            raw = _exec(command)
            parsed = parse_analyze(raw)
            return parsed_response(
                "windbg_analyze",
                command,
                parsed,
                raw,
                data={**parsed, "scope": "quick"} if "raw" not in parsed else None,
                next_actions=[next_action("windbg_context", {"scope": "default"}, "Collect registers, stack top, event, and modules around the analysis result.")],
            )

        elif s == "hang":
            command = "!analyze -v -hang"
            raw = _exec(command)
            if is_error_output(raw):
                return make_error("windbg_analyze", command, "debugger_error", raw.strip(), raw=raw)
            return make_response(
                "windbg_analyze",
                command,
                data={"scope": "hang", "analysis_raw": raw.strip()},
                raw=raw,
                next_actions=[next_action("windbg_context", {"scope": "threads"}, "Inspect threads after hang analysis.")],
            )

        elif s == "crash":
            result = {}
            errors = []
            commands = ["!analyze -v"]

            # !analyze -v
            raw = _exec("!analyze -v")
            parsed = parse_analyze(raw)
            if "raw" not in parsed:
                result.update(parsed)
            else:
                result["analyze_raw"] = parsed["raw"]
                errors.append({"code": "parse_failed", "message": "Could not parse !analyze -v output.", "recoverable": True})

            # 寄存器
            try:
                commands.append("r")
                raw = _exec("r")
                parsed = parse_registers(raw)
                if "raw" not in parsed:
                    result["registers"] = parsed.get("registers", {})
                    result["flags"] = parsed.get("flags", {})
                else:
                    errors.append({"code": "parse_failed", "message": "Could not parse register output.", "recoverable": True})
            except Exception as e:
                errors.append({"code": "exec_failed", "message": f"register collection failed: {e}", "recoverable": True})

            # 调用栈
            try:
                commands.append("kP 30")
                raw = _exec("kP 30")
                parsed = parse_stack_kp(raw)
                if "raw" not in parsed:
                    result["backtrace"] = parsed.get("frames", [])
                else:
                    errors.append({"code": "parse_failed", "message": "Could not parse backtrace output.", "recoverable": True})
            except Exception as e:
                errors.append({"code": "exec_failed", "message": f"backtrace collection failed: {e}", "recoverable": True})

            if not result:
                return make_error(
                    "windbg_analyze",
                    commands,
                    "analyze_failed",
                    "No usable analysis data was collected.",
                    next_actions=[next_action("windbg_context", {"scope": "default"}, "Collect the current debugger context before retrying analysis.")],
                )

            actions = [
                next_action("windbg_context", {"scope": "default"}, "Correlate analysis with current registers and instruction."),
                next_action("windbg_backtrace", {"depth": "30"}, "Review the full parsed call stack."),
            ]
            if "faulting_ip" in result:
                actions.append(next_action("windbg_disassemble", {"at": "@rip", "count": "8"}, "Inspect instructions near the faulting instruction pointer."))

            return make_response(
                "windbg_analyze",
                commands,
                data={**result, "scope": "crash"},
                errors=errors,
                next_actions=actions,
            )

        return make_error("windbg_analyze", "", "invalid_argument", "scope must be one of crash, hang, quick.")
