"""崩溃分析工具。"""

from ._registry import _exec
from ._parser import parse_analyze, parse_registers, parse_stack_kp


def register_analyze_tool(mcp):
    @mcp.tool()
    def windbg_analyze(scope: str = "crash") -> str:
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
            raw = _exec("!analyze -v")
            parsed = parse_analyze(raw)
            if "raw" in parsed:
                return parsed["raw"]
            return str(parsed)

        elif s == "hang":
            return _exec("!analyze -v -hang")

        else:  # crash (default)
            result = {}

            # !analyze -v
            raw = _exec("!analyze -v")
            parsed = parse_analyze(raw)
            if "raw" not in parsed:
                result.update(parsed)
            else:
                result["analyze_raw"] = parsed["raw"]

            # 寄存器
            try:
                raw = _exec("r")
                parsed = parse_registers(raw)
                if "raw" not in parsed:
                    result["registers"] = parsed.get("registers", {})
                    result["flags"] = parsed.get("flags", {})
            except Exception:
                pass

            # 调用栈
            try:
                raw = _exec("kP 30")
                parsed = parse_stack_kp(raw)
                if "raw" not in parsed:
                    result["backtrace"] = parsed.get("frames", [])
            except Exception:
                pass

            if not result:
                return str({"error": "analyze failed"})

            return str(result)
