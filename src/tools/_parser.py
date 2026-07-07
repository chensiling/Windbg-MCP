"""
WinDbg cdb.exe 输出格式共享解析器。

每个解析器接收原始文本，返回 dict/list。
解析失败时返回 {"raw": raw_text} 作为兜底——绝不抛异常。
"""

import re
from typing import Any


def _failback(raw: str) -> dict[str, str]:
    return {"raw": raw}


# ---------------------------------------------------------------------------
# parse_registers — 解析 "r" 输出
# ---------------------------------------------------------------------------

_RE_REG_VALUE_SINGLE = re.compile(
    r"(?P<reg>(?:[re]?[abc]x|[re]?[ds]i|[re]?[ds]p|[re]?[bd]p|"
    r"r\d+[dw]?|[xy]mm\d+|"
    r"rip|eip))"
    r"\s*=\s*(?P<value>[0-9a-f`]+)",
    re.IGNORECASE,
)

_RE_FLAGS = re.compile(
    r"^\s*iopl=(?P<iopl>\d+)\s+(?P<flags>[a-z ]+)\s*$"
)

_RE_CUR_SYM = re.compile(
    r"^\s*(?P<symbol>\S+!?\S+):\s*$"
)

_RE_CUR_ADDR = re.compile(
    r"^\s*(?P<address>[0-9a-f`]+)\s+(?P<bytes>[0-9a-f ]+)\s+(?P<insn>.+)$"
)


def parse_registers(raw: str) -> dict[str, Any]:
    """解析 'r' 输出，返回 {registers: {name: value}, flags: ..., segments: ..., current: ...}"""
    if not raw or not raw.strip():
        return _failback(raw)

    registers: dict[str, str] = {}
    flags: dict[str, str] = {}
    segments: dict[str, str] = {}
    current: dict[str, str] = {}

    lines = [l.rstrip() for l in raw.split("\n")]

    for line in lines:
        # 跳过段寄存器和标志行
        if re.search(r"\bcs=\S+\s+ss=", line, re.IGNORECASE):
            for part in line.split():
                if "=" in part:
                    k, v = part.split("=", 1)
                    kl = k.strip().lower()
                    if kl in ("efl",):
                        flags["efl"] = v
                    elif kl in ("cs", "ss", "ds", "es", "fs", "gs"):
                        segments[kl] = v
            continue

        # 标志行: "iopl=0         nv up ei pl zr na po nc"
        mf = _RE_FLAGS.match(line)
        if mf:
            flags["iopl"] = mf.group("iopl")
            flags["list"] = mf.group("flags").strip()
            continue

        # 符号行: "ntdll!LdrpDoDebuggerBreak+0x35:"
        msym = _RE_CUR_SYM.match(line)
        if msym:
            current["symbol"] = msym.group("symbol")
            continue

        # 地址/指令行: "00007ff9`850bd78d cc              int     3"
        ma = _RE_CUR_ADDR.match(line)
        if ma:
            current["address"] = ma.group("address").replace("`", "")
            current["bytes"] = ma.group("bytes").strip()
            current["instruction"] = re.sub(r"\s+", " ", ma.group("insn").strip())
            continue

        # 寄存器行: "rax=... rbx=... rcx=..." (一行可能有多个寄存器)
        for mm in _RE_REG_VALUE_SINGLE.finditer(line):
            registers[mm.group("reg").lower()] = mm.group("value").replace("`", "")

    result: dict[str, Any] = {}
    if registers:
        result["registers"] = registers
    if flags:
        result["flags"] = flags
    if segments:
        result["segments"] = segments
    if current:
        result["current"] = current

    if not result:
        return _failback(raw)
    return result


# ---------------------------------------------------------------------------
# parse_stack_k / parse_stack_kp — 解析 "k" / "kP" 调用栈
# ---------------------------------------------------------------------------

_RE_STACK_LINE = re.compile(
    r"^\s*(?P<child_sp>[0-9a-f`]+)\s+(?P<ret_addr>[0-9a-f`]+)\s+(?P<call_site>.+)$",
    re.IGNORECASE,
)

_RE_STACK_HEADER = re.compile(r"Child-SP\s+RetAddr\s+Call Site", re.IGNORECASE)


def _parse_stack_core(raw: str, has_params: bool) -> dict[str, Any]:
    """k/kP 共用解析核心"""
    if not raw or not raw.strip():
        return _failback(raw)

    frames: list[dict[str, str]] = []
    header_seen = False

    for line in raw.split("\n"):
        line = line.rstrip()
        if not line.strip():
            continue

        if _RE_STACK_HEADER.search(line):
            header_seen = True
            continue

        if not header_seen:
            continue

        m = _RE_STACK_LINE.match(line)
        if not m:
            continue

        frames.append({
            "child_sp": "0x" + m.group("child_sp").replace("`", ""),
            "ret_addr": "0x" + m.group("ret_addr").replace("`", ""),
            "call_site": m.group("call_site").strip(),
        })

    if not frames:
        return _failback(raw)

    return {"frames": frames, "has_params": has_params}


def parse_stack_k(raw: str) -> dict[str, Any]:
    return _parse_stack_core(raw, has_params=False)


def parse_stack_kp(raw: str) -> dict[str, Any]:
    return _parse_stack_core(raw, has_params=True)


# ---------------------------------------------------------------------------
# parse_disassembly — 解析 "u" 反汇编输出
# ---------------------------------------------------------------------------

_RE_DISASM_ADDR = re.compile(
    r"^\s*(?P<address>[0-9a-f`]+)\s+(?P<bytes>[0-9a-f ]+?)\s{2,}(?P<insn>.+)$",
    re.IGNORECASE,
)

_RE_DISASM_LABEL = re.compile(r"^\s*(?P<symbol>\S+):\s*$")


def parse_disassembly(raw: str) -> dict[str, Any]:
    """解析 'u' 输出，返回 {instructions: [{address, bytes, instruction, symbol?}], label?}"""
    if not raw or not raw.strip():
        return _failback(raw)

    instructions: list[dict[str, str]] = []
    current_label: str | None = None

    for line in raw.split("\n"):
        line = line.rstrip()
        if not line.strip():
            continue

        # 标签行: "ntdll!LdrpDoDebuggerBreak+0x35:"
        ml = _RE_DISASM_LABEL.match(line)
        if ml:
            current_label = ml.group("symbol")
            continue

        # 指令行: "00007ff9`850bd78d cc              int     3"
        ma = _RE_DISASM_ADDR.match(line)
        if ma:
            insn = re.sub(r"\s+", " ", ma.group("insn").strip())
            # 去掉尾部的符号注解括号，如 "(00007ff9`12345678)"
            insn = re.sub(r"\s*\([0-9a-f`]+\)\s*$", "", insn)
            entry: dict[str, str] = {
                "address": "0x" + ma.group("address").replace("`", ""),
                "bytes": ma.group("bytes").strip(),
                "instruction": insn,
            }
            if current_label and not instructions:
                entry["symbol"] = current_label
                current_label = None
            instructions.append(entry)
            continue

    if not instructions:
        return _failback(raw)

    result: dict[str, Any] = {"instructions": instructions}
    if current_label:
        result["label"] = current_label
    return result


# ---------------------------------------------------------------------------
# parse_memory_dump — 解析 "dd" / "dq" / "db" 内存转储
# ---------------------------------------------------------------------------

_RE_MEM_ADDR_LINE = re.compile(
    r"^\s*(?P<address>[0-9a-f`]+)\s+(?P<data>.+)$",
    re.IGNORECASE,
)


def parse_memory_dump(raw: str) -> dict[str, Any]:
    """解析 dd/dq/db 输出。自动检测格式。"""
    if not raw or not raw.strip():
        return _failback(raw)

    entries: list[dict[str, str]] = []
    base_address: str | None = None
    format_type = "hex_dword"

    for line in raw.split("\n"):
        line = line.rstrip()
        if not line.strip():
            continue

        m = _RE_MEM_ADDR_LINE.match(line)
        if not m:
            continue

        addr = m.group("address").replace("`", "")
        data_part = m.group("data").strip()

        if base_address is None:
            base_address = "0x" + addr

        # 检测格式：db 的 hex 字节中间有 "-"（第8和第9字节之间），末尾有 ASCII 列
        # db: "cc eb 00 48 83 c4 38 c3-cc cc cc cc cc cc cc 48  ...H..8........H"
        if "-" in data_part:
            format_type = "hex_byte"
            # 分割 hex 部分和 ascii 部分
            parts = re.split(r"\s{2,}", data_part, maxsplit=1)
            hex_part = parts[0].strip() if parts else data_part
            ascii_part = parts[1].strip() if len(parts) > 1 else ""

            hex_bytes = hex_part.replace("-", " ")
            byte_values = hex_bytes.split()

            for j, bv in enumerate(byte_values):
                entry: dict[str, str] = {"offset": f"0x{j:x}"}
                entry["value"] = bv
                if j < len(ascii_part):
                    entry["ascii"] = ascii_part[j] if ascii_part[j] != "." else "."
                entries.append(entry)
            continue

        # dd/dq 格式: "4800ebcc c338c483 cccccccc 48cccccc"
        values = data_part.split()
        for j, v in enumerate(values):
            clean = v.replace("`", "")
            # 含反引号通常是 qword（系统地址）
            if "`" in v:
                format_type = "hex_qword"
            stride = 8 if format_type == "hex_qword" else 4
            entries.append({"offset": f"0x{j * stride:x}", "value": clean})

    if not entries:
        return _failback(raw)

    return {
        "address": base_address or "0x0",
        "format": format_type,
        "data": entries,
    }


# ---------------------------------------------------------------------------
# parse_modules — 解析 "lm" 模块列表
# ---------------------------------------------------------------------------

_RE_MODULE_LINE = re.compile(
    r"^\s*(?P<start>[0-9a-f`]+)\s+(?P<end>[0-9a-f`]+)\s+(?P<name>\S+)\s*(?P<info>.+)?$",
    re.IGNORECASE,
)

_RE_MODULE_HEADER = re.compile(r"start\s+end\s+module name", re.IGNORECASE)


def parse_modules(raw: str) -> dict[str, Any]:
    """解析 'lm' 输出，返回 {modules: [{start, end, name, info?}]}"""
    if not raw or not raw.strip():
        return _failback(raw)

    modules: list[dict[str, str]] = []
    header_seen = False

    for line in raw.split("\n"):
        line = line.rstrip()
        if not line.strip():
            continue

        if _RE_MODULE_HEADER.search(line):
            header_seen = True
            continue

        if not header_seen:
            continue

        m = _RE_MODULE_LINE.match(line)
        if not m:
            continue

        mod: dict[str, str] = {
            "start": "0x" + m.group("start").replace("`", ""),
            "end": "0x" + m.group("end").replace("`", ""),
            "name": m.group("name"),
        }
        info = (m.group("info") or "").strip()
        if info:
            mod["info"] = info
        modules.append(mod)

    if not modules:
        return _failback(raw)

    return {"modules": modules}


# ---------------------------------------------------------------------------
# parse_symbol_list — 解析 "x" 符号搜索
# ---------------------------------------------------------------------------

_RE_SYMBOL_LINE = re.compile(
    r"^\s*(?P<address>[0-9a-f`]+)\s+(?P<symbol>\S+)\s*(?P<rest>.*)$",
)


def parse_symbol_list(raw: str) -> dict[str, Any]:
    """解析 'x' 输出，返回 {symbols: [{address, name, info?}]}"""
    if not raw or not raw.strip():
        return _failback(raw)

    symbols: list[dict[str, str]] = []

    for line in raw.split("\n"):
        line = line.rstrip()
        if not line.strip():
            continue

        m = _RE_SYMBOL_LINE.match(line)
        if not m:
            continue

        sym: dict[str, str] = {
            "address": "0x" + m.group("address").replace("`", ""),
            "name": m.group("symbol"),
        }
        rest = m.group("rest").strip()
        if rest:
            sym["info"] = rest
        symbols.append(sym)

    if not symbols:
        return _failback(raw)

    return {"symbols": symbols}


# ---------------------------------------------------------------------------
# parse_type_info — 解析 "dt" 类型信息
# ---------------------------------------------------------------------------

_RE_TYPE_LINE = re.compile(
    r"^\s*\+(?P<offset>[0-9a-fx]+)\s+(?P<name>\S+)\s*:\s*(?P<type>.+)$",
)


def parse_type_info(raw: str) -> dict[str, Any]:
    """解析 'dt' 输出，返回 {fields: [{offset, name, type}]}"""
    if not raw or not raw.strip():
        return _failback(raw)

    fields: list[dict[str, str]] = []

    for line in raw.split("\n"):
        line = line.rstrip()
        if not line.strip():
            continue

        m = _RE_TYPE_LINE.match(line)
        if not m:
            continue

        fields.append({
            "offset": m.group("offset"),
            "name": m.group("name"),
            "type": m.group("type").strip(),
        })

    if not fields:
        return _failback(raw)

    return {"fields": fields}


# ---------------------------------------------------------------------------
# parse_analyze — 解析 "!analyze -v" 崩溃分析
# ---------------------------------------------------------------------------

_RE_BUGCHECK = re.compile(r"BUGCHECK_CODE:\s+(?P<code>[0-9a-fx]+)", re.IGNORECASE)

_RE_FAULT_IP_MULTILINE = re.compile(
    r"FAULTING_IP:\s*\n?\s*(?P<module>\S+?)(?:!|\+)(?P<rest>\S+)"
    r"\s*\n\s*(?P<address>[0-9a-f`]+)\s+(?P<bytes>[0-9a-f? ]+)\s+(?P<insn>.+)",
    re.IGNORECASE,
)

_RE_FAULT_IP_SIMPLE = re.compile(
    r"FAULTING_IP:\s*\n?\s*(?P<module>\S+?)(?:!|\+)(?P<rest>\S+)",
    re.IGNORECASE,
)

_RE_PROCESS_NAME = re.compile(
    r"PROCESS_NAME:\s+(?P<name>\S+)"
)
_RE_IMAGE_NAME = re.compile(
    r"IMAGE_NAME:\s+(?P<name>\S+)"
)
_RE_STACK_TEXT = re.compile(
    r"STACK_TEXT:\s*\n(?P<text>(?:.*\n)*?)\n\s*\n", re.IGNORECASE
)


def parse_analyze(raw: str) -> dict[str, Any]:
    """解析 '!analyze -v' 输出，提取关键字段。失败返回 raw。"""
    if not raw or not raw.strip():
        return _failback(raw)

    result: dict[str, Any] = {}

    m = _RE_BUGCHECK.search(raw)
    if m:
        result["bugcheck_code"] = m.group("code")

    m = _RE_FAULT_IP_MULTILINE.search(raw)
    if m:
        result["faulting_ip"] = {
            "module": m.group("module"),
            "rest": m.group("rest"),
        }
    else:
        m = _RE_FAULT_IP_SIMPLE.search(raw)
        if m:
            result["faulting_ip"] = {
                "module": m.group("module"),
                "rest": m.group("rest"),
            }

    m = _RE_PROCESS_NAME.search(raw)
    if m:
        result["process_name"] = m.group("name")

    m = _RE_IMAGE_NAME.search(raw)
    if m:
        result["image_name"] = m.group("name")

    m = _RE_STACK_TEXT.search(raw)
    if m:
        result["stack_text"] = m.group("text").strip()

    if not result:
        return _failback(raw)

    return result


# ---------------------------------------------------------------------------
# parse_process_list — 解析 "!process 0 0" 输出
# ---------------------------------------------------------------------------

_RE_PROC_ENTRY = re.compile(
    r"PROCESS\s+(?P<address>[0-9a-f`]+)\s*\n?"
    r".*?SessionId:\s*(?P<session>\S+)\s+"
    r"Cid:\s*(?P<cid>[0-9a-f]+)\s+"
    r"Peb:\s*(?P<peb>[0-9a-f`]+)\s+"
    r"ParentCid:\s*(?P<parent>[0-9a-f]+)",
    re.IGNORECASE | re.DOTALL,
)
_RE_PROC_DIR = re.compile(
    r"DirBase:\s*(?P<dirbase>[0-9a-f`]+)\s+"
    r"ObjectTable:\s*(?P<objtable>[0-9a-f`]+)\s+"
    r"HandleCount:\s*(?P<handles>\S+)",
    re.IGNORECASE,
)
_RE_PROC_IMAGE = re.compile(r"Image:\s*(?P<name>\S+)")


def parse_process_list(raw: str) -> dict[str, Any]:
    """解析 '!process 0 0' 输出，返回 {processes: [{address, pid, name?, ...}]}"""
    if not raw or not raw.strip():
        return _failback(raw)

    processes: list[dict[str, str]] = []

    # 按 PROCESS 关键词分割
    blocks = re.split(r"\n(?=PROCESS\s+)", raw)
    for block in blocks:
        m = _RE_PROC_ENTRY.search(block)
        if not m:
            continue

        current: dict[str, str] = {
            "address": "0x" + m.group("address").replace("`", ""),
            "pid": m.group("cid"),
            "peb": "0x" + m.group("peb").replace("`", ""),
            "parent_pid": m.group("parent"),
        }

        md = _RE_PROC_DIR.search(block)
        if md:
            current["dirbase"] = "0x" + md.group("dirbase").replace("`", "")
            current["handle_count"] = md.group("handles")

        mi = _RE_PROC_IMAGE.search(block)
        if mi:
            current["name"] = mi.group("name")

        processes.append(current)

    if not processes:
        return _failback(raw)

    return {"processes": processes}
