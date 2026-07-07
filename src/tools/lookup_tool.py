"""符号/类型查找工具 — 统一入口，自动识别意图。"""

from ._registry import _exec
from ._parser import parse_symbol_list, parse_type_info


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

        # 纯十六进制地址 → ln
        cleaned = w.replace("`", "").lower()
        if cleaned.startswith("0x") and all(c in "0123456789abcdefx" for c in cleaned):
            raw = _exec(f"ln {w}")
            return raw.strip()

        # 包含通配符 → x
        if "*" in w or "?" in w:
            raw = _exec(f"x {w}")
            parsed = parse_symbol_list(raw)
            if "raw" in parsed:
                return parsed["raw"]
            return str(parsed)

        # 以 _ 开头的大写名或包含 ! 的已知类型 → dt
        if (w[0] == "_" and w[1:].upper() == w[1:]) or "!" in w:
            # 尝试 dt
            raw = _exec(f"dt {w}")
            parsed = parse_type_info(raw)
            if "raw" in parsed:
                # dt 失败，尝试 x
                raw2 = _exec(f"x {w}")
                parsed2 = parse_symbol_list(raw2)
                if "raw" in parsed2:
                    return parsed2["raw"]
                return str(parsed2)
            return str(parsed)

        # 默认：按符号搜索
        raw = _exec(f"x {w}")
        parsed = parse_symbol_list(raw)
        if "raw" in parsed:
            return parsed["raw"]
        return str(parsed)
