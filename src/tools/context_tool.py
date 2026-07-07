"""上下文工具 — 获取当前调试状态快照。一次调用替代多次分散查询。"""

from ._registry import _exec
from ._parser import parse_registers, parse_stack_kp, parse_modules, parse_process_list


def register_context_tool(mcp):
    @mcp.tool()
    def windbg_context(scope: str = "default") -> str:
        """获取当前调试状态快照——一次调用，返回 LLM 最常用的全部上下文。

        scope 值:
        - "default" (默认): 寄存器 + 当前指令 + 栈顶帧 + 最近事件 + 模块列表。
          适用场景：断点命中后、崩溃后、想知道"现在什么情况"时。
        - "threads": default + 线程列表。适用场景：多线程死锁、需要切换线程。
        - "processes": default + 内核进程列表。适用场景：内核调试中需要知道系统有哪些进程。
        - "all": 全部信息（default + threads + processes）。

        返回 JSON:
        {
          "registers": {rax: "0x...", rip: "0x...", ...},
          "flags": {iopl: "0", list: "nv up ei ..."},
          "current_instruction": {address: "0x...", bytes: "...", instruction: "..."},
          "stack_frame": {child_sp: "0x...", ret_addr: "0x...", call_site: "module!func+0x42"},
          "last_event": "Breakpoint 0 hit",
          "modules": [{start: "0x...", end: "0x...", name: "ntdll", info: "(pdb symbols)"}],
          "threads": [{id: "000", status: "Running", ...}]  (scope=threads 时),
          "processes": [{address: "0x...", pid: "1234", name: "notepad.exe"}]  (scope=processes 时)
        }

        失败时返回 {"error": "..."}。
        """
        s = scope.lower().strip()
        results = {}
        errors = []

        # ── 核心状态：寄存器 + 栈 + 最近事件 + 模块（一次执行）──
        try:
            raw = _exec("r; .printf \"__S1__\\n\"; kP 1; .printf \"__S2__\\n\"; .lastevent; .printf \"__S3__\\n\"; lm")
        except Exception as e:
            return str({"error": f"exec failed: {e}"})

        sections = raw.split("__S1__", 1) if "__S1__" in raw else (raw, "")
        # 第一部分是 r 输出
        reg_raw = sections[0] if sections else raw

        parsed = parse_registers(reg_raw)
        if "raw" not in parsed:
            results["registers"] = parsed.get("registers", {})
            results["flags"] = parsed.get("flags", {})
            cur = parsed.get("current", {})
            if cur:
                results["current_instruction"] = cur
        else:
            errors.append("registers 解析失败")

        if len(sections) > 1:
            rest = sections[1].split("__S2__", 1)
            # kP 输出
            if rest:
                parsed = parse_stack_kp(rest[0])
                if "raw" not in parsed and parsed.get("frames"):
                    results["stack_frame"] = parsed["frames"][0]
                else:
                    errors.append("stack 解析失败")

            if len(rest) > 1:
                rest2 = rest[1].split("__S3__", 1)
                results["last_event"] = rest2[0].strip()
                if len(rest2) > 1:
                    parsed = parse_modules(rest2[1])
                    if "raw" not in parsed:
                        results["modules"] = parsed.get("modules", [])
                    else:
                        errors.append("modules 解析失败")

        # ── 线程列表 ──
        if s in ("threads", "all"):
            try:
                raw = _exec("~")
                threads: list[dict[str, str]] = []
                for line in raw.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    # 格式: "  0  Id: 1234.5678 Suspend: 1 Teb: 00000012`34560000 Unfrozen"
                    # 或简写: ". 0  Id: ..." / "# 0  Id: ..."
                    import re
                    m = re.match(r"^[.#]?\s*(?P<id>\d+)\s+Id:\s*(?P<tid>[0-9a-f.`]+)\s+Suspend:\s*(?P<suspend>\d+)\s+Teb:\s*(?P<teb>[0-9a-f`]+)\s*(?P<state>.*)$", line, re.IGNORECASE)
                    if m:
                        threads.append({
                            "id": m.group("id"),
                            "tid": m.group("tid").replace("`", ""),
                            "suspend": m.group("suspend"),
                            "teb": "0x" + m.group("teb").replace("`", ""),
                            "state": m.group("state").strip() or "Running",
                        })
                if threads:
                    results["threads"] = threads
                else:
                    results["threads_raw"] = raw.strip()
            except Exception as e:
                errors.append(f"threads error: {e}")

        # ── 内核进程列表 ──
        if s in ("processes", "all"):
            try:
                raw = _exec("!process 0 0")
                parsed = parse_process_list(raw)
                if "raw" not in parsed:
                    results["processes"] = parsed.get("processes", [])
                else:
                    results["processes_raw"] = parsed["raw"]
            except Exception as e:
                errors.append(f"processes error: {e}")

        if errors:
            results["errors"] = errors

        if not results or results.keys() <= {"errors"}:
            return str({"error": "context collection failed", "detail": errors})

        return str(results)
