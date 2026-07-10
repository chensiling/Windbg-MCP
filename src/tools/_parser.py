"""Shared parsers for WinDbg and cdb.exe output."""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal


ParseStatus = Literal["complete", "partial", "failed"]


@dataclass(frozen=True)
class ParseResult(Mapping[str, Any]):
    """Structured parser result with a read-only legacy mapping view.

    Complete results expose their parsed data through the mapping interface.
    Partial and failed results expose only ``{"raw": raw}``, matching the
    historical parser fallback without hiding the structured diagnostics.
    """

    status: ParseStatus
    data: dict[str, Any]
    raw: str
    unparsed_lines: list[str]
    warnings: list[str]

    def __post_init__(self) -> None:
        if self.status not in ("complete", "partial", "failed"):
            raise ValueError(f"invalid parse status: {self.status}")
        if self.status == "failed" and self.data:
            raise ValueError("failed parse results cannot contain parsed data")

        object.__setattr__(self, "data", dict(self.data))
        object.__setattr__(self, "unparsed_lines", list(self.unparsed_lines))
        object.__setattr__(self, "warnings", list(self.warnings))

    def __getitem__(self, key: str) -> Any:
        if self.status == "complete":
            return self.data[key]
        if key == "raw":
            return self.raw
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        if self.status == "complete":
            return iter(self.data)
        return iter(("raw",))

    def __len__(self) -> int:
        if self.status == "complete":
            return len(self.data)
        return 1


_RE_DEBUGGER_PROMPT = re.compile(r"^\s*(?:(?:\d+:\s*)?[^>\s]+)>\s*")
_RE_DEBUGGER_COMMAND = re.compile(
    r"(?:r(?:\s+.*)?|k[bcpvlnf]*(?:\s+.*)?|u[a-z]?(?:\s+.*)?|"
    r"d[abuwdq](?:\s+.*)?|lm(?:\s+.*)?|x\s+.+|ln\s+.+|dt\s+.+|"
    r"\?\s+.+|!analyze(?:\s+.*)?|!process(?:\s+.*)?|~(?:\s+.*)?|"
    r"bl(?:\s+.*)?|!running(?:\s+.*)?)",
    re.IGNORECASE,
)


def _clean_line(line: str) -> str:
    prompt_seen = _RE_DEBUGGER_PROMPT.match(line) is not None
    cleaned = _RE_DEBUGGER_PROMPT.sub("", line.rstrip())
    if prompt_seen and _RE_DEBUGGER_COMMAND.fullmatch(cleaned.strip()):
        return ""
    return cleaned


def _canonical_hex(value: str) -> str:
    clean = value.strip().lower().replace("`", "")
    if clean.startswith("0x"):
        clean = clean[2:]
    return "0x" + clean


def _meaningful_lines(raw: str) -> list[str]:
    return [
        cleaned.strip()
        for line in raw.splitlines()
        if (cleaned := _clean_line(line)).strip()
    ]


def _parse_result(
    raw: str,
    data: dict[str, Any],
    unparsed_lines: list[str],
    *,
    recognized: bool = True,
    warnings: list[str] | None = None,
) -> ParseResult:
    normalized_unparsed = [line.strip() for line in unparsed_lines if line.strip()]
    normalized_warnings = list(warnings or [])

    if not recognized:
        if not normalized_warnings:
            normalized_warnings.append("no_recognized_output")
        return ParseResult(
            status="failed",
            data={},
            raw=raw,
            unparsed_lines=normalized_unparsed,
            warnings=normalized_warnings,
        )

    if normalized_unparsed:
        if "unparsed_lines" not in normalized_warnings:
            normalized_warnings.append("unparsed_lines")
        return ParseResult(
            status="partial",
            data=data,
            raw=raw,
            unparsed_lines=normalized_unparsed,
            warnings=normalized_warnings,
        )

    return ParseResult(
        status="complete",
        data=data,
        raw=raw,
        unparsed_lines=[],
        warnings=normalized_warnings,
    )


def _failed(raw: str, warnings: list[str] | None = None) -> ParseResult:
    return _parse_result(
        raw,
        {},
        _meaningful_lines(raw),
        recognized=False,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# parse_registers — 解析 "r" 输出
# ---------------------------------------------------------------------------

_RE_REG_VALUE_SINGLE = re.compile(
    r"(?P<reg>(?:[re]?[abcd]x|[re]?[ds]i|[re]?[ds]p|[re]?[bd]p|"
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


def parse_registers(raw: str) -> ParseResult:
    """解析 'r' 输出，返回 {registers: {name: value}, flags: ..., segments: ..., current: ...}"""
    if not raw or not raw.strip():
        return _failed(raw)

    registers: dict[str, str] = {}
    flags: dict[str, str] = {}
    segments: dict[str, str] = {}
    current: dict[str, str] = {}

    unparsed_lines: list[str] = []

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        if not line.strip():
            continue

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
            current["address"] = _canonical_hex(ma.group("address"))
            current["bytes"] = ma.group("bytes").strip()
            current["instruction"] = re.sub(r"\s+", " ", ma.group("insn").strip())
            continue

        # 寄存器行: "rax=... rbx=... rcx=..." (一行可能有多个寄存器)
        matches = list(_RE_REG_VALUE_SINGLE.finditer(line))
        for mm in matches:
            registers[mm.group("reg").lower()] = mm.group("value").replace("`", "")
        if matches and not _RE_REG_VALUE_SINGLE.sub("", line).strip():
            continue

        unparsed_lines.append(line)

    result: dict[str, Any] = {}
    if registers:
        result["registers"] = registers
    if flags:
        result["flags"] = flags
    if segments:
        result["segments"] = segments
    if current:
        result["current"] = current

    return _parse_result(
        raw,
        result,
        unparsed_lines,
        recognized=bool(result),
    )


# ---------------------------------------------------------------------------
# parse_stack_k / parse_stack_kp — 解析 "k" / "kP" 调用栈
# ---------------------------------------------------------------------------

_RE_STACK_LINE = re.compile(
    r"^\s*(?:(?P<index>[0-9a-f]{1,3})\s+)?(?P<child_sp>[0-9a-f`]+)\s+"
    r"(?P<ret_addr>[0-9a-f`]+)\s+(?P<call_site>.+)$",
    re.IGNORECASE,
)

_RE_STACK_HEADER = re.compile(
    r"(?:Child-(?:SP|EBP)|ChildEBP)\s+RetAddr(?:\s+Args to Child)?(?:\s+Call Site)?",
    re.IGNORECASE,
)

_RE_STACK_PARAMETER_VALUE = re.compile(r"(?:0x)?[0-9a-f`]+", re.IGNORECASE)


def _split_stack_call_site(call_site: str) -> tuple[str, list[str]]:
    tokens = call_site.split()
    site_index = next(
        (index for index, token in enumerate(tokens) if "!" in token),
        None,
    )
    if not site_index:
        return call_site.strip(), []

    parameter_tokens = tokens[:site_index]
    if not all(_RE_STACK_PARAMETER_VALUE.fullmatch(token) for token in parameter_tokens):
        return call_site.strip(), []

    parameters = [_canonical_hex(token) for token in parameter_tokens]
    return " ".join(tokens[site_index:]), parameters


def _is_stack_parameter_line(line: str) -> bool:
    stripped = line.strip()
    return bool(
        line[:1].isspace()
        and stripped
        and (
            "=" in stripped
            or stripped in (")", "),")
            or stripped.endswith(",")
        )
    )


def _parse_stack_core(raw: str, has_params: bool) -> ParseResult:
    """k/kP 共用解析核心"""
    if not raw or not raw.strip():
        return _failed(raw)

    frames: list[dict[str, Any]] = []
    header_seen = False
    unparsed_lines: list[str] = []
    current_frame: dict[str, Any] | None = None

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        if not line.strip():
            continue

        if _RE_STACK_HEADER.search(line):
            header_seen = True
            continue

        if not header_seen:
            unparsed_lines.append(line)
            continue

        m = _RE_STACK_LINE.match(line)
        if m:
            call_site = m.group("call_site").strip()
            parameters: list[str] = []
            if has_params:
                call_site, parameters = _split_stack_call_site(call_site)

            current_frame = {
                "child_sp": _canonical_hex(m.group("child_sp")),
                "ret_addr": _canonical_hex(m.group("ret_addr")),
                "call_site": call_site,
            }
            if m.group("index") is not None:
                current_frame["index"] = m.group("index")
            if parameters:
                current_frame["parameters"] = parameters
            frames.append(current_frame)
            continue

        if has_params and current_frame is not None and _is_stack_parameter_line(line):
            current_frame.setdefault("parameters", []).append(line.strip())
            continue

        unparsed_lines.append(line)

    return _parse_result(
        raw,
        {"frames": frames, "has_params": has_params},
        unparsed_lines,
        recognized=bool(frames),
    )


def parse_stack_k(raw: str) -> ParseResult:
    return _parse_stack_core(raw, has_params=False)


def parse_stack_kp(raw: str) -> ParseResult:
    return _parse_stack_core(raw, has_params=True)


# ---------------------------------------------------------------------------
# parse_disassembly — 解析 "u" 反汇编输出
# ---------------------------------------------------------------------------

_RE_DISASM_ADDR = re.compile(
    r"^\s*(?P<address>[0-9a-f`]+)\s+(?P<bytes>[0-9a-f ]+?)\s{2,}(?P<insn>.+)$",
    re.IGNORECASE,
)

_RE_DISASM_LABEL = re.compile(r"^\s*(?P<symbol>\S+):\s*$")


def parse_disassembly(raw: str) -> ParseResult:
    """解析 'u' 输出，返回 {instructions: [{address, bytes, instruction, symbol?}], label?}"""
    if not raw or not raw.strip():
        return _failed(raw)

    instructions: list[dict[str, str]] = []
    current_label: str | None = None
    unparsed_lines: list[str] = []

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
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
                "address": _canonical_hex(ma.group("address")),
                "bytes": ma.group("bytes").strip(),
                "instruction": insn,
            }
            if current_label and not instructions:
                entry["symbol"] = current_label
                current_label = None
            instructions.append(entry)
            continue

        unparsed_lines.append(line)

    result: dict[str, Any] = {"instructions": instructions}
    if current_label:
        result["label"] = current_label
    return _parse_result(
        raw,
        result if instructions else {},
        unparsed_lines,
        recognized=bool(instructions),
    )


# ---------------------------------------------------------------------------
# parse_memory_dump — 解析 "dd" / "dq" / "db" 内存转储
# ---------------------------------------------------------------------------

_RE_MEM_ADDR_LINE = re.compile(
    r"^\s*(?P<address>[0-9a-f`]+)\s+(?P<data>.+)$",
    re.IGNORECASE,
)

_MEMORY_FORMAT_BY_WIDTH = {
    2: ("hex_byte", 1),
    4: ("hex_word", 2),
    8: ("hex_dword", 4),
    16: ("hex_qword", 8),
}

_RE_MEMORY_ASCII = re.compile(r'^"(?P<text>.*)"$')


def _parse_memory_line(data_part: str) -> tuple[str, int, list[str], str] | None:
    sections = re.split(r"\s{2,}", data_part.rstrip(), maxsplit=1)
    hex_part = sections[0].replace("-", " ")
    ascii_part = sections[1] if len(sections) > 1 else ""
    tokens = hex_part.split()
    if not tokens:
        return None

    cleaned_tokens = [token.lower().replace("`", "") for token in tokens]
    if not all(re.fullmatch(r"[0-9a-f]+", token) for token in cleaned_tokens):
        return None

    widths = {len(token) for token in cleaned_tokens}
    if len(widths) != 1:
        return None

    width = widths.pop()
    format_info = _MEMORY_FORMAT_BY_WIDTH.get(width)
    if format_info is None:
        return None

    format_type, stride = format_info
    return format_type, stride, cleaned_tokens, ascii_part


def parse_memory_dump(raw: str) -> ParseResult:
    """解析 dd/dq/db 输出。自动检测格式。"""
    if not raw or not raw.strip():
        return _failed(raw)

    entries: list[dict[str, str]] = []
    base_address: str | None = None
    base_address_value: int | None = None
    format_type: str | None = None
    unparsed_lines: list[str] = []
    warnings: list[str] = []

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        if not line.strip():
            continue

        m = _RE_MEM_ADDR_LINE.match(line)
        if not m:
            unparsed_lines.append(line)
            continue

        addr = m.group("address").lower().replace("`", "")
        data_part = m.group("data").strip()
        ascii_match = _RE_MEMORY_ASCII.fullmatch(data_part)
        if ascii_match:
            ascii_part = ascii_match.group("text")
            parsed_line = (
                "ascii",
                1,
                [f"{ord(character):02x}" for character in ascii_part],
                ascii_part,
            )
        else:
            parsed_line = _parse_memory_line(data_part)
        if parsed_line is None:
            unparsed_lines.append(line)
            continue

        line_format, stride, values, ascii_part = parsed_line
        if format_type is not None and line_format != format_type:
            unparsed_lines.append(line)
            if "mixed_memory_formats" not in warnings:
                warnings.append("mixed_memory_formats")
            continue

        if base_address is None:
            base_address = _canonical_hex(addr)
            base_address_value = int(addr, 16)
            format_type = line_format

        assert base_address_value is not None
        line_offset = int(addr, 16) - base_address_value
        if line_offset < 0:
            unparsed_lines.append(line)
            if "non_monotonic_memory_address" not in warnings:
                warnings.append("non_monotonic_memory_address")
            continue

        for index, value in enumerate(values):
            entry: dict[str, str] = {
                "offset": f"0x{line_offset + index * stride:x}",
                "value": value,
            }
            if line_format in ("hex_byte", "ascii") and index < len(ascii_part):
                entry["ascii"] = ascii_part[index]
            entries.append(entry)

    data = {
        "address": base_address,
        "format": format_type,
        "data": entries,
    } if entries else {}
    return _parse_result(
        raw,
        data,
        unparsed_lines,
        recognized=bool(entries),
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# parse_modules — 解析 "lm" 模块列表
# ---------------------------------------------------------------------------

_RE_MODULE_LINE = re.compile(
    r"^\s*(?P<start>[0-9a-f`]+)\s+(?P<end>[0-9a-f`]+)\s+(?P<name>\S+)\s*(?P<info>.+)?$",
    re.IGNORECASE,
)

_RE_MODULE_HEADER = re.compile(r"start\s+end\s+module name", re.IGNORECASE)


def parse_modules(raw: str) -> ParseResult:
    """解析 'lm' 输出，返回 {modules: [{start, end, name, info?}]}"""
    if not raw or not raw.strip():
        return _failed(raw)

    modules: list[dict[str, str]] = []
    header_seen = False
    unparsed_lines: list[str] = []

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        if not line.strip():
            continue

        if _RE_MODULE_HEADER.search(line):
            header_seen = True
            continue

        if not header_seen:
            unparsed_lines.append(line)
            continue

        m = _RE_MODULE_LINE.match(line)
        if not m:
            unparsed_lines.append(line)
            continue

        mod: dict[str, str] = {
            "start": _canonical_hex(m.group("start")),
            "end": _canonical_hex(m.group("end")),
            "name": m.group("name"),
        }
        info = (m.group("info") or "").strip()
        if info:
            mod["info"] = info
        modules.append(mod)

    return _parse_result(
        raw,
        {"modules": modules},
        unparsed_lines,
        recognized=header_seen,
    )


# ---------------------------------------------------------------------------
# parse_symbol_list — 解析 "x" 符号搜索
# ---------------------------------------------------------------------------

_RE_SYMBOL_LINE = re.compile(
    r"^\s*(?P<address>[0-9a-f`]+)\s+(?P<symbol>\S+)\s*(?P<rest>.*)$",
    re.IGNORECASE,
)


def parse_symbol_list(raw: str) -> ParseResult:
    """解析 'x' 输出，返回 {symbols: [{address, name, info?}]}"""
    if not raw or not raw.strip():
        return _failed(raw)

    symbols: list[dict[str, str]] = []
    unparsed_lines: list[str] = []

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        if not line.strip():
            continue

        m = _RE_SYMBOL_LINE.match(line)
        if not m:
            unparsed_lines.append(line)
            continue

        sym: dict[str, str] = {
            "address": _canonical_hex(m.group("address")),
            "name": m.group("symbol"),
        }
        rest = m.group("rest").strip()
        if rest:
            sym["info"] = rest
        symbols.append(sym)

    return _parse_result(
        raw,
        {"symbols": symbols} if symbols else {},
        unparsed_lines,
        recognized=bool(symbols),
    )


# ---------------------------------------------------------------------------
# parse_nearest_symbol — 解析 "ln" 最近符号输出
# ---------------------------------------------------------------------------

_RE_LN_SYMBOL = re.compile(
    r"\((?P<address>[0-9a-f`]+)\)\s+(?P<symbol>\S+)",
    re.IGNORECASE,
)

_RE_LN_HEADER = re.compile(
    r"^(?:Browse module|Set b[up] breakpoint)$",
    re.IGNORECASE,
)


def parse_nearest_symbol(raw: str) -> ParseResult:
    """解析 'ln address' 输出，返回 {symbol: {address, name}}"""
    if not raw or not raw.strip():
        return _failed(raw)

    symbol: dict[str, str] | None = None
    unparsed_lines: list[str] = []
    for raw_line in raw.splitlines():
        line = _clean_line(raw_line).strip()
        if not line or _RE_LN_HEADER.fullmatch(line):
            continue

        m = _RE_LN_SYMBOL.search(line)
        if m and symbol is None:
            symbol = {
                "address": _canonical_hex(m.group("address")),
                "name": m.group("symbol"),
            }
            continue

        unparsed_lines.append(line)

    return _parse_result(
        raw,
        {"symbol": symbol} if symbol else {},
        unparsed_lines,
        recognized=symbol is not None,
    )


# ---------------------------------------------------------------------------
# parse_type_info — 解析 "dt" 类型信息
# ---------------------------------------------------------------------------

_RE_TYPE_LINE = re.compile(
    r"^\s*\+(?P<offset>[0-9a-fx]+)\s+(?P<name>\S+)\s*:\s*(?P<type>.+)$",
    re.IGNORECASE,
)


def parse_type_info(raw: str) -> ParseResult:
    """解析 'dt' 输出，返回 {fields: [{offset, name, type}]}"""
    if not raw or not raw.strip():
        return _failed(raw)

    fields: list[dict[str, str]] = []
    unparsed_lines: list[str] = []

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        if not line.strip():
            continue

        m = _RE_TYPE_LINE.match(line)
        if not m:
            unparsed_lines.append(line)
            continue

        fields.append({
            "offset": m.group("offset"),
            "name": m.group("name"),
            "type": m.group("type").strip(),
        })

    return _parse_result(
        raw,
        {"fields": fields} if fields else {},
        unparsed_lines,
        recognized=bool(fields),
    )


# ---------------------------------------------------------------------------
# parse_evaluate — 解析 "? expression" 输出
# ---------------------------------------------------------------------------

_RE_EVAL = re.compile(
    r"Evaluate expression:\s*(?P<decimal>-?\d+)\s*=\s*(?P<hex>[0-9a-f`]+)",
    re.IGNORECASE,
)


def parse_evaluate(raw: str) -> ParseResult:
    """解析 '?' 表达式结果，返回 {decimal, hex}。"""
    if not raw or not raw.strip():
        return _failed(raw)

    data: dict[str, Any] = {}
    unparsed_lines: list[str] = []
    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        if not line.strip():
            continue

        m = _RE_EVAL.search(line)
        if m and not data:
            data = {
                "decimal": int(m.group("decimal")),
                "hex": _canonical_hex(m.group("hex")),
            }
            continue

        unparsed_lines.append(line)

    return _parse_result(
        raw,
        data,
        unparsed_lines,
        recognized=bool(data),
    )


# ---------------------------------------------------------------------------
# parse_analyze — 解析 "!analyze -v" 崩溃分析
# ---------------------------------------------------------------------------

_RE_BUGCHECK = re.compile(r"BUGCHECK_CODE:\s+(?P<code>[0-9a-fx]+)", re.IGNORECASE)

_RE_FAULT_IP_HEADER = re.compile(r"^FAULTING_IP:\s*(?P<symbol>.*)$", re.IGNORECASE)
_RE_FAULT_SYMBOL = re.compile(
    r"^(?P<module>\S+?)(?:!|\+)(?P<rest>\S+)$",
    re.IGNORECASE,
)

_RE_PROCESS_NAME = re.compile(
    r"PROCESS_NAME:\s+(?P<name>\S+)", re.IGNORECASE
)
_RE_IMAGE_NAME = re.compile(
    r"IMAGE_NAME:\s+(?P<name>\S+)", re.IGNORECASE
)
_RE_STACK_TEXT_HEADER = re.compile(r"^STACK_TEXT:\s*$", re.IGNORECASE)


def parse_analyze(raw: str) -> ParseResult:
    """解析 '!analyze -v' 输出，提取关键字段。失败返回 raw。"""
    if not raw or not raw.strip():
        return _failed(raw)

    result: dict[str, Any] = {}
    unparsed_lines: list[str] = []
    lines = [_clean_line(line) for line in raw.splitlines()]
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue

        m = _RE_BUGCHECK.search(stripped)
        if m:
            result["bugcheck_code"] = m.group("code").lower()
            index += 1
            continue

        m = _RE_PROCESS_NAME.search(stripped)
        if m:
            result["process_name"] = m.group("name")
            index += 1
            continue

        m = _RE_IMAGE_NAME.search(stripped)
        if m:
            result["image_name"] = m.group("name")
            index += 1
            continue

        fault_header = _RE_FAULT_IP_HEADER.match(stripped)
        if fault_header:
            symbol_text = fault_header.group("symbol").strip()
            symbol_index = index
            if not symbol_text:
                symbol_index += 1
                while symbol_index < len(lines) and not lines[symbol_index].strip():
                    symbol_index += 1
                if symbol_index < len(lines):
                    symbol_text = lines[symbol_index].strip()

            symbol_match = _RE_FAULT_SYMBOL.match(symbol_text)
            if symbol_match:
                faulting_ip: dict[str, str] = {
                    "module": symbol_match.group("module"),
                    "rest": symbol_match.group("rest"),
                }
                instruction_index = symbol_index + 1
                while instruction_index < len(lines) and not lines[instruction_index].strip():
                    instruction_index += 1
                if instruction_index < len(lines):
                    instruction_match = _RE_CUR_ADDR.match(lines[instruction_index])
                    if instruction_match:
                        faulting_ip.update({
                            "address": _canonical_hex(instruction_match.group("address")),
                            "bytes": instruction_match.group("bytes").strip(),
                            "instruction": re.sub(
                                r"\s+",
                                " ",
                                instruction_match.group("insn").strip(),
                            ),
                        })
                        symbol_index = instruction_index
                result["faulting_ip"] = faulting_ip
                index = symbol_index + 1
                continue

            index += 1
            continue

        if _RE_STACK_TEXT_HEADER.match(stripped):
            stack_lines: list[str] = []
            stack_index = index + 1
            while stack_index < len(lines) and lines[stack_index].strip():
                stack_lines.append(lines[stack_index].rstrip())
                stack_index += 1
            if stack_lines:
                result["stack_text"] = "\n".join(stack_lines).strip()
            index = stack_index
            continue

        unparsed_lines.append(line)
        index += 1

    return _parse_result(
        raw,
        result,
        unparsed_lines,
        recognized=bool(result),
    )


# ---------------------------------------------------------------------------
# parse_process_list — 解析 "!process 0 0" 输出
# ---------------------------------------------------------------------------

_RE_PROC_HEADER = re.compile(
    r"^PROCESS\s+(?P<address>[0-9a-f`]+)\s*$",
    re.IGNORECASE,
)
_RE_PROC_SESSION = re.compile(
    r"SessionId:\s*(?P<session>\S+)\s+"
    r"Cid:\s*(?P<cid>[0-9a-f]+)\s+"
    r"Peb:\s*(?P<peb>[0-9a-f`]+)\s+"
    r"ParentCid:\s*(?P<parent>[0-9a-f]+)",
    re.IGNORECASE,
)
_RE_PROC_DIR = re.compile(
    r"DirBase:\s*(?P<dirbase>[0-9a-f`]+)\s+"
    r"ObjectTable:\s*(?P<objtable>[0-9a-f`]+)\s+"
    r"HandleCount:\s*(?P<handles>\S+)",
    re.IGNORECASE,
)
_RE_PROC_IMAGE = re.compile(r"Image:\s*(?P<name>\S+)", re.IGNORECASE)
_RE_PROC_LIST_HEADER = re.compile(r"^\*+\s+NT ACTIVE PROCESS DUMP\s+\*+$", re.IGNORECASE)


def parse_process_list(raw: str) -> ParseResult:
    """解析 '!process 0 0' 输出，返回 {processes: [{address, pid, name?, ...}]}"""
    if not raw or not raw.strip():
        return _failed(raw)

    processes: list[dict[str, str]] = []
    unparsed_lines: list[str] = []
    current: dict[str, str] | None = None
    current_header: str | None = None
    current_complete = False

    def finish_current() -> None:
        nonlocal current, current_header, current_complete
        if current is None:
            return
        if current_complete:
            processes.append(current)
        elif current_header is not None:
            unparsed_lines.append(current_header)
        current = None
        current_header = None
        current_complete = False

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        stripped = line.strip()
        if not stripped:
            continue
        if _RE_PROC_LIST_HEADER.match(stripped):
            continue

        m = _RE_PROC_HEADER.match(stripped)
        if m:
            finish_current()
            current = {"address": _canonical_hex(m.group("address"))}
            current_header = line
            continue

        session_match = _RE_PROC_SESSION.search(stripped)
        if session_match and current is not None:
            current.update({
                "session_id": session_match.group("session"),
                "pid": session_match.group("cid"),
                "peb": _canonical_hex(session_match.group("peb")),
                "parent_pid": session_match.group("parent"),
            })
            current_complete = True
            continue

        directory_match = _RE_PROC_DIR.search(stripped)
        if directory_match and current is not None:
            current.update({
                "dirbase": _canonical_hex(directory_match.group("dirbase")),
                "object_table": _canonical_hex(directory_match.group("objtable")),
                "handle_count": directory_match.group("handles"),
            })
            continue

        image_match = _RE_PROC_IMAGE.search(stripped)
        if image_match and current is not None:
            current["name"] = image_match.group("name")
            continue

        unparsed_lines.append(line)

    finish_current()
    return _parse_result(
        raw,
        {"processes": processes} if processes else {},
        unparsed_lines,
        recognized=bool(processes),
    )


# ---------------------------------------------------------------------------
# parse_thread_list_user — 解析 "~" 用户态线程列表
# ---------------------------------------------------------------------------

_RE_USER_THREAD = re.compile(
    r"^(?P<markers>[.#* ]*)\s*(?P<id>\d+)\s+Id:\s*(?P<tid>[0-9a-f.`]+)"
    r"\s+Suspend:\s*(?P<suspend>\d+)\s+Teb:\s*(?P<teb>[0-9a-f`]+)\s*(?P<state>.*)$",
    re.IGNORECASE,
)


def parse_thread_list_user(raw: str) -> ParseResult:
    """解析用户态 '~' 输出，返回 {threads: [...]}。"""
    if not raw or not raw.strip():
        return _failed(raw)

    threads: list[dict[str, Any]] = []
    unparsed_lines: list[str] = []

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line).strip()
        if not line:
            continue

        m = _RE_USER_THREAD.match(line)
        if not m:
            unparsed_lines.append(line)
            continue

        markers = m.group("markers") or ""
        threads.append({
            "id": m.group("id"),
            "tid": m.group("tid").replace("`", ""),
            "suspend": m.group("suspend"),
            "teb": _canonical_hex(m.group("teb")),
            "state": m.group("state").strip() or "Running",
            "current": "." in markers,
            "event": "#" in markers,
        })

    return _parse_result(
        raw,
        {"threads": threads} if threads else {},
        unparsed_lines,
        recognized=bool(threads),
    )


# ---------------------------------------------------------------------------
# parse_breakpoints — 解析 "bl" 断点列表
# ---------------------------------------------------------------------------

_RE_BREAKPOINT = re.compile(
    r"^\s*(?P<id>\d+)\s+(?P<state>[ed])\s+(?P<rest>.+)$",
    re.IGNORECASE,
)
_RE_BREAKPOINT_ADDR = re.compile(r"(?P<address>[0-9a-f`]{8,})", re.IGNORECASE)


def parse_breakpoints(raw: str) -> ParseResult:
    """解析 'bl' 输出，返回 {breakpoints: [{id, enabled, address?, detail}]}。"""
    if not raw or not raw.strip():
        return _failed(raw)

    breakpoints: list[dict[str, Any]] = []
    unparsed_lines: list[str] = []
    prompt_seen = False

    for raw_line in raw.splitlines():
        prompt_match = _RE_DEBUGGER_PROMPT.match(raw_line)
        line = _clean_line(raw_line)
        if not line.strip():
            prompt_seen = prompt_seen or prompt_match is not None
            continue

        m = _RE_BREAKPOINT.match(line)
        if not m:
            unparsed_lines.append(line)
            continue

        detail = m.group("rest").strip()
        bp: dict[str, Any] = {
            "id": m.group("id"),
            "enabled": m.group("state").lower() == "e",
            "detail": detail,
        }
        ma = _RE_BREAKPOINT_ADDR.search(detail)
        if ma:
            bp["address"] = _canonical_hex(ma.group("address"))
        breakpoints.append(bp)

    valid_empty = prompt_seen and not unparsed_lines
    return _parse_result(
        raw,
        {"breakpoints": breakpoints},
        unparsed_lines,
        recognized=bool(breakpoints) or valid_empty,
    )


# ---------------------------------------------------------------------------
# parse_thread_list_kernel — 解析内核 "!running -ti" 输出
# ---------------------------------------------------------------------------

_RE_SYS_PROCESSORS = re.compile(
    r"System Processors:\s*\((?P<mask>[0-9a-f`]+)\)", re.IGNORECASE
)
_RE_IDLE_PROCESSORS = re.compile(
    r"Idle Processors:\s*\((?P<mask>[0-9a-f`]+)\)", re.IGNORECASE
)
_RE_PRCB_HEADER = re.compile(r"Prcbs\s+Current", re.IGNORECASE)
_RE_RUNNING_ROW = re.compile(
    r"^\s*(?P<proc>\d+)\s+(?P<prcb>[0-9a-f`]+)\s+"
    r"(?P<current>[0-9a-f`]+)\s*\(\s*(?P<curpri>\d+)\s*\)"
    r"(?:\s+(?P<next>[0-9a-f`]+)\s*\(\s*(?P<nextpri>\d+)\s*\))?"
    r"\s+(?P<idle>[0-9a-f`]+)",
    re.IGNORECASE,
)


def _hex0x(value: str) -> str:
    return _canonical_hex(value)


def parse_thread_list_kernel(raw: str) -> ParseResult:
    """解析内核 '!running -ti' 输出。

    返回 {system_processors?, idle_processors?, processors: [
        {processor, prcb, current_thread, current_pri, next_thread?, next_pri?,
         idle_thread, stack: [{index, child_sp, ret_addr, call_site}]}
    ]}
    """
    if not raw or not raw.strip():
        return _failed(raw)

    result: dict[str, Any] = {}
    processors: list[dict[str, Any]] = []
    current_proc: dict[str, Any] | None = None
    unparsed_lines: list[str] = []

    for raw_line in raw.splitlines():
        line = _clean_line(raw_line)
        if not line.strip():
            continue

        m = _RE_SYS_PROCESSORS.search(line)
        if m:
            result["system_processors"] = _hex0x(m.group("mask"))
            continue

        m = _RE_IDLE_PROCESSORS.search(line)
        if m:
            result["idle_processors"] = _hex0x(m.group("mask"))
            continue

        if _RE_PRCB_HEADER.search(line):
            continue

        if _RE_STACK_HEADER.search(line):
            continue

        m = _RE_RUNNING_ROW.match(line)
        if m:
            current_proc = {
                "processor": int(m.group("proc")),
                "prcb": _hex0x(m.group("prcb")),
                "current_thread": _hex0x(m.group("current")),
                "current_pri": int(m.group("curpri")),
                "idle_thread": _hex0x(m.group("idle")),
                "stack": [],
            }
            if m.group("next"):
                current_proc["next_thread"] = _hex0x(m.group("next"))
                current_proc["next_pri"] = int(m.group("nextpri"))
            processors.append(current_proc)
            continue

        if current_proc is not None:
            ms = _RE_STACK_LINE.match(line)
            if ms:
                frame: dict[str, str] = {
                    "child_sp": _canonical_hex(ms.group("child_sp")),
                    "ret_addr": _canonical_hex(ms.group("ret_addr")),
                    "call_site": ms.group("call_site").strip(),
                }
                if ms.group("index") is not None:
                    frame["index"] = ms.group("index")
                current_proc["stack"].append(frame)
                continue

        unparsed_lines.append(line)

    result["processors"] = processors
    return _parse_result(
        raw,
        result if processors else {},
        unparsed_lines,
        recognized=bool(processors),
    )
