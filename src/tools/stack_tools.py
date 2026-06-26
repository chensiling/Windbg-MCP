import re
from ._registry import _exec


def _parse_stack(output: str) -> str:
    lines = []
    for line in output.split("\n"):
        m = re.match(r"^\s*(\d+)\s+([0-9a-f`]+)\s+([0-9a-f`]+)\s+(.+)$", line)
        if not m:
            continue
        idx, child_sp, ret_addr, call_site = m.groups()
        child_sp = child_sp.replace("`", "")
        ret_addr = ret_addr.replace("`", "")
        lines.append(f"| [0x{idx}] | {call_site.strip()} | 0x{child_sp} | 0x{ret_addr} |")
    header = "| Frame   | Call Site                                          | Child-SP             | RetAddr              |"
    sep = "|---------|----------------------------------------------------|----------------------|----------------------|"
    result = header + "\n" + sep
    if lines:
        result += "\n" + "\n".join(lines)
    return result


def register_stack_tools(mcp):
    @mcp.tool()
    def windbg_stack(count: str = "20", params: str = "true") -> str:
        n = max(1, int(count))
        if params.lower() in ("true", "1", "yes"):
            raw = _exec(f"kP {n}")
        else:
            raw = _exec(f"k {n}")
        parsed = _parse_stack(raw)
        return parsed if parsed else raw

    @mcp.tool()
    def windbg_stack_frame(frame: str) -> str:
        return _exec(f".frame {frame}; dv /t /i")
