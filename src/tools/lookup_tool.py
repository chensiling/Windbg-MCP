"""符号/类型查找工具 — 统一入口，自动识别意图。"""

import re

from ._registry import _exec
from ._parser import parse_nearest_symbol, parse_symbol_list, parse_type_info
from ._response import make_response, next_action, parsed_response


def register_lookup_tool(mcp):
    @mcp.tool()
    def windbg_lookup(what: str) -> str:
        """根据输入自动识别并执行符号、类型或地址解析。

        自动识别规则：
        - 纯十六进制地址（如 0x7ff... 或 00007ff9`850bd78d）→ 用 'ln' 查找最近的符号。
        - 包含通配符 * 或 ?（如 ntdll!*CreateFile*）→ 用 'x' 搜索符号。
        - 以 ! 结尾或以 _ 开头的大写名（如 ntdll!_TEB、_EPROCESS）→ 用 'dt' 显示类型。
        - 其他 → 按符号搜索。

        参数 what: 地址、符号模式或类型名。

        返回结构化结果：
        - 地址解析: {symbol: {name, displacement}}
        - 符号搜索: {symbols: [{address, name}]}
        - 类型信息: {fields: [{offset, name, type}]}
        解析失败时返回原始文本。
        """
        w = what.strip()
        if not w:
            return make_response(
                "windbg_lookup",
                "",
                ok=False,
                errors=[{"code": "invalid_argument", "message": "'what' is required.", "recoverable": True}],
            )

        # 纯十六进制地址 → ln
        cleaned = w.replace("`", "").lower()
        is_hex_address = (
            (cleaned.startswith("0x") and all(c in "0123456789abcdefx" for c in cleaned))
            or bool(re.fullmatch(r"[0-9a-f]{8,}", cleaned))
        )
        if is_hex_address:
            command = f"ln {w}"
            raw = _exec(command)
            parsed = parse_nearest_symbol(raw)
            return parsed_response("windbg_lookup", command, parsed, raw, data={**parsed, "kind": "address"} if "raw" not in parsed else None)

        # 包含通配符 → x
        if "*" in w or "?" in w:
            command = f"x {w}"
            raw = _exec(command)
            parsed = parse_symbol_list(raw)
            actions = []
            if "raw" not in parsed and len(parsed.get("symbols", [])) > 50:
                actions.append(next_action("windbg_lookup", {"what": w.replace("*", "") + "*"}, "Too many matches; narrow the symbol pattern."))
            return parsed_response("windbg_lookup", command, parsed, raw, data={**parsed, "kind": "symbol_search"} if "raw" not in parsed else None, next_actions=actions)

        # 以 _ 开头的大写名或包含 ! 的已知类型 → dt
        if (w[0] == "_" and w[1:].upper() == w[1:]) or "!" in w:
            # 尝试 dt
            command = f"dt {w}"
            raw = _exec(command)
            parsed = parse_type_info(raw)
            if "raw" in parsed:
                # dt 失败，尝试 x
                command2 = f"x {w}"
                raw2 = _exec(command2)
                parsed2 = parse_symbol_list(raw2)
                return parsed_response("windbg_lookup", [command, command2], parsed2, raw2, data={**parsed2, "kind": "symbol_search"} if "raw" not in parsed2 else None)
            return parsed_response("windbg_lookup", command, parsed, raw, data={**parsed, "kind": "type"} if "raw" not in parsed else None)

        # 默认：按符号搜索
        command = f"x {w}"
        raw = _exec(command)
        parsed = parse_symbol_list(raw)
        return parsed_response("windbg_lookup", command, parsed, raw, data={**parsed, "kind": "symbol_search"} if "raw" not in parsed else None)
