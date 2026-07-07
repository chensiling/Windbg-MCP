"""解析器单元测试 — 使用 cdb.exe 真实输出样例。"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from tools._parser import (
    parse_registers,
    parse_stack_k,
    parse_stack_kp,
    parse_disassembly,
    parse_memory_dump,
    parse_modules,
    parse_symbol_list,
    parse_nearest_symbol,
    parse_type_info,
    parse_evaluate,
    parse_analyze,
    parse_process_list,
    parse_thread_list_user,
    parse_breakpoints,
)


# ---------------------------------------------------------------------------
# 真实输出样本（2026-07-07 从 cdb.exe 10.0.26100.6584 采集）
# ---------------------------------------------------------------------------

SAMPLE_REGISTERS = """rax=0000000000000000 rbx=00007ff98513a090 rcx=00007ff985100514
rdx=0000000000000000 rsi=00007ff985117700 rdi=000000837ea20000
rip=00007ff9850bd78d rsp=000000837ec7ed50 rbp=0000000000000000
 r8=000000837ec7ed48  r9=0000000000000000 r10=0000000000000000
r11=0000000000000246 r12=0000000000000001 r13=0000000000000000
r14=0000000000000040 r15=0000020c33d40000
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!LdrpDoDebuggerBreak+0x35:
00007ff9`850bd78d cc              int     3"""

SAMPLE_STACK_K = """Child-SP          RetAddr               Call Site
00000019`bd4bf280 00007ff9`8502d83a     ntdll!LdrpDoDebuggerBreak+0x35
00000019`bd4bf2c0 00007ff9`8502ba50     ntdll!LdrpInitializeProcess+0x1ae6
00000019`bd4bf6f0 00007ff9`8502b83a     ntdll!LdrpInitialize+0x16c"""

SAMPLE_STACK_KP = """Child-SP          RetAddr               Call Site
000000f7`c79fee90 00007ff9`8502d83a     ntdll!LdrpDoDebuggerBreak+0x35
000000f7`c79feed0 00007ff9`8502ba50     ntdll!LdrpInitializeProcess+0x1ae6
000000f7`c79ff300 00007ff9`8502b83a     ntdll!LdrpInitialize+0x16c
000000f7`c79ff380 00007ff9`8502b854e     ntdll!LdrpInitializeInternal+0x5a
000000f7`c79ff3d0 00000000`00000000     ntdll!LdrInitializeThunk+0xe"""

SAMPLE_STACK_KP_INDEXED = """0: kd>  # Child-SP          RetAddr               Call Site
00 ffff968b`f8207708 fffff805`2d9c18d0     nt!DbgBreakPointWithStatus
01 ffff968b`f8207710 fffff805`2d9c1718     kdnic!TXTransmitQueuedSends+0x180"""

SAMPLE_DISASM = """ntdll!LdrpDoDebuggerBreak+0x35:
00007ff9`850bd78d cc              int     3
00007ff9`850bd78e eb00            jmp     ntdll!LdrpDoDebuggerBreak+0x38 (00007ff9`850bd790)
00007ff9`850bd790 4883c438        add     rsp,38h"""

SAMPLE_DISASM_PROMPT = """0: kd> nt!DbgBreakPointWithStatus:
fffff805`990f90d0 cc              int     3
fffff805`990f90d1 c3              ret"""

SAMPLE_MEM_DD = """00007ff9`850bd78d  4800ebcc c338c483 cccccccc 48cccccc"""

SAMPLE_MEM_DQ = """0000008e`77e7f0f0  00007ff9`8513a090 00007ff9`85097191
0000008e`77e7f100  00000000`00000000 0000008e`77e7f180"""

SAMPLE_MEM_DB = """00007ff9`850bd78d  cc eb 00 48 83 c4 38 c3-cc cc cc cc cc cc cc 48  ...H..8........H
00007ff9`850bd79d  83 ec 28 65 48 8b 0c 25-60 00 00 00 33 d2 41 b8  ..(eH..%`...3.A."""

SAMPLE_MEM_DB_PROMPT = """0: kd> fffff805`990f90d0  cc c3 cc cc cc cc cc cc-0f 1f 84 00 00 00 00 00  ................"""

SAMPLE_MODULES = """start             end                 module name
00007ff9`84fa0000 00007ff9`85206000   ntdll      (pdb symbols)          C:\\ProgramData\\dbg\\sym\\ntdll.pdb\\23ADECD9479F123BF50906CE9B88193F1\\ntdll.pdb"""

SAMPLE_SYMBOLS = """00007ff9`84fb00f0 ntdll!LdrpDoPostSnapWork (void)
00007ff9`850bd758 ntdll!LdrpDoDebuggerBreak (LdrpDoDebuggerBreak)"""

SAMPLE_LN = """Browse module
Set bu breakpoint

(00007ff9`850bd758)   ntdll!LdrpDoDebuggerBreak+0x35   |  (00007ff9`850bd790)   ntdll!LdrpDoDebuggerBreak+0x68"""

SAMPLE_TYPE_INFO = """   +0x000 NtTib            : _NT_TIB
   +0x038 EnvironmentPointer : Ptr64 Void
   +0x040 ClientId         : _CLIENT_ID
   +0x050 ActiveRpcHandle  : Ptr64 Void"""

SAMPLE_EVALUATE = """Evaluate expression: 140709204350861 = 00007ff9`850bd78d"""

SAMPLE_ANALYZE_QUICK = """BUGCHECK_CODE:  1e

FAULTING_IP: 
ntdll!RtlpWaitOnCriticalSection+1a2
00007ff9`850bd78d cc              int     3

PROCESS_NAME:  notepad.exe

IMAGE_NAME:  ntdll.dll"""

SAMPLE_PROCESS_LIST = """PROCESS ffffcf8f9c5e4080
    SessionId: 1  Cid: 1234    Peb: 12a53e0000  ParentCid: 05678
    DirBase: 12a53e002  ObjectTable: ffffcf8f9c5e4080  HandleCount: 123.
    Image: notepad.exe


PROCESS ffffcf8f9c5e5080
    SessionId: 1  Cid: 5678    Peb: 12a54e0000  ParentCid: 01234
    DirBase: 12a54e002  ObjectTable: ffffcf8f9c5e5080  HandleCount: 456.
    Image: explorer.exe"""

SAMPLE_THREADS_USER = """.  0  Id: 1234.5678 Suspend: 1 Teb: 00000083`7ea20000 Unfrozen
#  1  Id: 1234.5679 Suspend: 0 Teb: 00000083`7ea30000 Unfrozen"""

SAMPLE_BREAKPOINTS = """ 0 e Disable Clear  00007ff9`850bd78d     0001 (0001)  0:**** ntdll!LdrpDoDebuggerBreak
 1 d Disable Clear  00007ff9`850bd790     0001 (0001)  0:**** ntdll!Other"""

SAMPLE_BREAKPOINTS_EMPTY = """0: kd> """


# ---------------------------------------------------------------------------
# 测试用例
# ---------------------------------------------------------------------------

class TestParseRegisters:
    def test_parse_all(self):
        result = parse_registers(SAMPLE_REGISTERS)
        regs = result["registers"]
        assert regs["rax"] == "0000000000000000"
        assert regs["rip"] == "00007ff9850bd78d"
        assert regs["rsp"] == "000000837ec7ed50"
        assert regs["r8"] == "000000837ec7ed48"
        assert regs["r15"] == "0000020c33d40000"
        assert result["flags"]["iopl"] == "0"
        assert "nv up ei pl zr na po nc" in result["flags"]["list"]
        assert result["current"]["symbol"] == "ntdll!LdrpDoDebuggerBreak+0x35"
        assert result["current"]["instruction"] == "int 3"

    def test_empty_input(self):
        result = parse_registers("")
        assert result["raw"] == ""

    def test_garbage_input(self):
        result = parse_registers("some random text")
        assert result["raw"] == "some random text"


class TestParseStack:
    def test_parse_k(self):
        result = parse_stack_k(SAMPLE_STACK_K)
        frames = result["frames"]
        assert len(frames) == 3
        assert frames[0]["call_site"] == "ntdll!LdrpDoDebuggerBreak+0x35"
        assert frames[0]["child_sp"].startswith("0x")

    def test_parse_kp(self):
        result = parse_stack_kp(SAMPLE_STACK_KP)
        frames = result["frames"]
        assert len(frames) == 5
        assert result["has_params"] is True

    def test_parse_kp_with_frame_index_and_prompt(self):
        result = parse_stack_kp(SAMPLE_STACK_KP_INDEXED)
        frames = result["frames"]
        assert len(frames) == 2
        assert frames[0]["index"] == "00"
        assert frames[0]["child_sp"] == "0xffff968bf8207708"
        assert frames[0]["ret_addr"] == "0xfffff8052d9c18d0"
        assert frames[0]["call_site"] == "nt!DbgBreakPointWithStatus"

    def test_parse_k_no_header(self):
        result = parse_stack_k("garbage text")
        assert result["raw"] == "garbage text"


class TestParseDisassembly:
    def test_parse(self):
        result = parse_disassembly(SAMPLE_DISASM)
        insns = result["instructions"]
        assert len(insns) == 3
        assert insns[0]["instruction"] == "int 3"
        assert insns[0]["symbol"] == "ntdll!LdrpDoDebuggerBreak+0x35"
        assert insns[1]["instruction"] == "jmp ntdll!LdrpDoDebuggerBreak+0x38"

    def test_parse_prompt_label(self):
        result = parse_disassembly(SAMPLE_DISASM_PROMPT)
        insns = result["instructions"]
        assert insns[0]["symbol"] == "nt!DbgBreakPointWithStatus"
        assert insns[1]["instruction"] == "ret"

    def test_empty(self):
        result = parse_disassembly("")
        assert result["raw"] == ""


class TestParseMemoryDump:
    def test_parse_dd(self):
        result = parse_memory_dump(SAMPLE_MEM_DD)
        assert result["format"] == "hex_dword"
        assert len(result["data"]) == 4
        assert result["data"][0]["value"] == "4800ebcc"

    def test_parse_dq(self):
        result = parse_memory_dump(SAMPLE_MEM_DQ)
        assert result["format"] == "hex_qword"
        assert len(result["data"]) >= 4

    def test_parse_db(self):
        result = parse_memory_dump(SAMPLE_MEM_DB)
        assert result["format"] == "hex_byte"
        assert len(result["data"]) >= 16
        assert result["data"][0]["value"] == "cc"

    def test_parse_db_with_prompt(self):
        result = parse_memory_dump(SAMPLE_MEM_DB_PROMPT)
        assert result["address"] == "0xfffff805990f90d0"
        assert result["format"] == "hex_byte"
        assert len(result["data"]) == 16
        assert result["data"][1]["value"] == "c3"


class TestParseModules:
    def test_parse(self):
        result = parse_modules(SAMPLE_MODULES)
        mods = result["modules"]
        assert len(mods) == 1
        assert mods[0]["name"] == "ntdll"

    def test_no_modules(self):
        result = parse_modules("no module here")
        assert result["raw"] == "no module here"


class TestParseSymbolList:
    def test_parse(self):
        result = parse_symbol_list(SAMPLE_SYMBOLS)
        syms = result["symbols"]
        assert len(syms) == 2
        assert syms[0]["name"] == "ntdll!LdrpDoPostSnapWork"

    def test_empty(self):
        result = parse_symbol_list("")
        assert result["raw"] == ""


class TestParseNearestSymbol:
    def test_parse(self):
        result = parse_nearest_symbol(SAMPLE_LN)
        assert result["symbol"]["address"] == "0x00007ff9850bd758"
        assert result["symbol"]["name"] == "ntdll!LdrpDoDebuggerBreak+0x35"

    def test_empty(self):
        result = parse_nearest_symbol("no symbol")
        assert result["raw"] == "no symbol"


class TestParseTypeInfo:
    def test_parse(self):
        result = parse_type_info(SAMPLE_TYPE_INFO)
        fields = result["fields"]
        assert len(fields) == 4
        assert fields[0]["name"] == "NtTib"
        assert fields[0]["type"] == "_NT_TIB"

    def test_empty(self):
        result = parse_type_info("random text")
        assert result["raw"] == "random text"


class TestParseEvaluate:
    def test_parse(self):
        result = parse_evaluate(SAMPLE_EVALUATE)
        assert result["decimal"] == 140709204350861
        assert result["hex"] == "0x00007ff9850bd78d"

    def test_empty(self):
        result = parse_evaluate("not an eval result")
        assert result["raw"] == "not an eval result"


class TestParseAnalyze:
    def test_parse(self):
        result = parse_analyze(SAMPLE_ANALYZE_QUICK)
        assert result["bugcheck_code"] == "1e"
        assert result["faulting_ip"]["module"] == "ntdll"
        assert result["process_name"] == "notepad.exe"
        assert result["image_name"] == "ntdll.dll"

    def test_empty(self):
        result = parse_analyze("nothing here")
        assert result["raw"] == "nothing here"


class TestParseProcessList:
    def test_parse(self):
        result = parse_process_list(SAMPLE_PROCESS_LIST)
        procs = result["processes"]
        assert len(procs) == 2
        assert procs[0]["pid"] == "1234"
        assert procs[0]["name"] == "notepad.exe"

    def test_empty(self):
        result = parse_process_list("garbage")
        assert result["raw"] == "garbage"


class TestParseThreadListUser:
    def test_parse(self):
        result = parse_thread_list_user(SAMPLE_THREADS_USER)
        threads = result["threads"]
        assert len(threads) == 2
        assert threads[0]["current"] is True
        assert threads[1]["event"] is True
        assert threads[0]["teb"] == "0x000000837ea20000"

    def test_empty(self):
        result = parse_thread_list_user("kernel mode output")
        assert result["raw"] == "kernel mode output"


class TestParseBreakpoints:
    def test_parse(self):
        result = parse_breakpoints(SAMPLE_BREAKPOINTS)
        breakpoints = result["breakpoints"]
        assert len(breakpoints) == 2
        assert breakpoints[0]["enabled"] is True
        assert breakpoints[1]["enabled"] is False
        assert breakpoints[0]["address"] == "0x00007ff9850bd78d"

    def test_empty(self):
        result = parse_breakpoints("no breakpoints")
        assert result["raw"] == "no breakpoints"

    def test_empty_prompt_means_no_breakpoints(self):
        result = parse_breakpoints(SAMPLE_BREAKPOINTS_EMPTY)
        assert result["breakpoints"] == []


class TestFailback:
    """所有解析器失败时必须返回 {"raw": ...} 而不是抛异常"""

    def test_all_return_raw_on_empty(self):
        parsers = [
            parse_registers, parse_stack_k, parse_stack_kp,
            parse_disassembly, parse_memory_dump, parse_modules,
            parse_symbol_list, parse_nearest_symbol, parse_type_info,
            parse_evaluate, parse_analyze, parse_process_list,
            parse_thread_list_user, parse_breakpoints,
        ]
        for parser in parsers:
            result = parser("")
            assert "raw" in result, f"{parser.__name__} failed on empty input"

    def test_all_no_exception_on_garbage(self):
        parsers = [
            parse_registers, parse_stack_k, parse_stack_kp,
            parse_disassembly, parse_memory_dump, parse_modules,
            parse_symbol_list, parse_nearest_symbol, parse_type_info,
            parse_evaluate, parse_analyze, parse_process_list,
            parse_thread_list_user, parse_breakpoints,
        ]
        garbage = "!@#$%^&*()_+\nnothing\n12345\n"
        for parser in parsers:
            try:
                result = parser(garbage)
                assert isinstance(result, dict), f"{parser.__name__} returned non-dict"
            except Exception as e:
                assert False, f"{parser.__name__} raised {e} on garbage input"
