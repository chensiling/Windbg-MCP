"""Parser unit tests using representative cdb.exe output."""

import json
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from tools._parser import (
    ParseResult,
    parse_frame_selection,
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
    parse_thread_list_kernel,
    parse_breakpoints,
    parse_target_info,
    parse_thread_info,
    parse_module_info,
    parse_pte,
    parse_pool,
    parse_blackbox,
    parse_image_verify,
    parse_function_info,
)
from tools import breakpoint_tool
from tools import _registry
from tools._models import ToolEnvelope
from tools._response import parsed_response, source_item
from debugger.engine import ExecutionResult


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

SAMPLE_STACK_KP_PARAMETERS = """Child-SP          RetAddr               Call Site
00 ffff968b`f8207708 fffff805`2d9c18d0     nt!ExampleFunction(
                         first = 0x0000000000000001,
                         second = ffff968b`f8207800
                         )"""

SAMPLE_STACK_KP_INLINE_PARAMETERS = """ChildEBP RetAddr Args to Child Call Site
0012f280 77ab1234 00000001 0012f2f0 ntdll!ExampleFunction+0x12"""

SAMPLE_FRAME_SELECTED = (
    "05 000000d1`47e7f400 00007fff`e5a4d83a     "
    "ntdll!LdrpDoDebuggerBreak+0x35"
)

SAMPLE_FRAME_REJECTED = """Cannot find frame 0x5, previous scope unchanged
00 000000d1`47e7f400 00007fff`e5a4d83a     ntdll!LdrpDoDebuggerBreak+0x35"""

SAMPLE_DISASM = """ntdll!LdrpDoDebuggerBreak+0x35:
00007ff9`850bd78d cc              int     3
00007ff9`850bd78e eb00            jmp     ntdll!LdrpDoDebuggerBreak+0x38 (00007ff9`850bd790)
00007ff9`850bd790 4883c438        add     rsp,38h"""

SAMPLE_DISASM_PROMPT = """0: kd> nt!DbgBreakPointWithStatus:
fffff805`990f90d0 cc              int     3
fffff805`990f90d1 c3              ret"""

SAMPLE_DISASM_LONG_BYTES = (
    "fffff805`99123456 f7451840000000 "
    "test dword ptr [rbp+18h],40000000h"
)

SAMPLE_DISASM_PARTIAL_MEMORY = """fffff805`99123456 cc int 3
Memory access error at 'fffff805`99123457'"""

SAMPLE_MEM_DD = """00007ff9`850bd78d  4800ebcc c338c483 cccccccc 48cccccc"""

SAMPLE_MEM_DQ = """0000008e`77e7f0f0  00007ff9`8513a090 00007ff9`85097191
0000008e`77e7f100  00000000`00000000 0000008e`77e7f180"""

SAMPLE_MEM_DB = """00007ff9`850bd78d  cc eb 00 48 83 c4 38 c3-cc cc cc cc cc cc cc 48  ...H..8........H
00007ff9`850bd79d  83 ec 28 65 48 8b 0c 25-60 00 00 00 33 d2 41 b8  ..(eH..%`...3.A."""

SAMPLE_MEM_DB_PROMPT = """0: kd> fffff805`990f90d0  cc c3 cc cc cc cc cc cc-0f 1f 84 00 00 00 00 00  ................"""

SAMPLE_MEM_DD_MULTILINE = """00007ff9`850bd780  11111111 22222222 33333333 44444444
00007ff9`850bd790  55555555 66666666 77777777 88888888"""

SAMPLE_MEM_WORD = """00000000`0012f000  1234 abcd 0000 ffff"""

SAMPLE_MEM_QWORD_NO_BACKTICK = """00000000`0012f000  0123456789abcdef 0000000000000000"""

SAMPLE_MEM_DB_NO_DASH = """00000000`0012f000  41 42 43 44 45 46 47 48  ABCDEFGH"""

SAMPLE_MEM_ASCII = '''00000000`0012f000  "Hello, w"
00000000`0012f008  "orld!"'''

SAMPLE_MEM_UNAVAILABLE = (
    "2: kd> 00000000`00000001  ?? ?? ?? ??"
    "                                      ????"
)

SAMPLE_MODULES = """start             end                 module name
00007ff9`84fa0000 00007ff9`85206000   ntdll      (pdb symbols)          C:\\ProgramData\\dbg\\sym\\ntdll.pdb\\23ADECD9479F123BF50906CE9B88193F1\\ntdll.pdb"""

SAMPLE_THREAD_INFO = """THREAD ffffda02`73eea040  Cid 0004.00d8  WAIT:
Owning Process            ffffda02`70004080       Image:         System
Priority 12  BasePriority 8
Child-SP          RetAddr               Call Site
ffff968b`f8207708 fffff805`2d9c18d0     nt!KeWaitForSingleObject"""

SAMPLE_MODULE_INFO = """start             end                 module name
fffff805`99000000 fffff805`9a200000   nt         (pdb symbols)
    Loaded symbol image file: ntkrnlmp.exe
    Image path: ntkrnlmp.exe
    Timestamp: 12345678"""

SAMPLE_PTE = """VA ffffda02`73eea040
PXE at FFFFF6FB`7DBEDDA0  PPE at FFFFF6FB`7DBB4050  PDE at FFFFF6FB`76809CF8  PTE at FFFFF6ED`0139F750
contains 0A000000`01234863  contains 0A000000`01235863  contains 0A000000`01236863  contains 80000000`12345963
pfn 12345 ---DA--KWEV"""

SAMPLE_POOL = """Pool page ffffda02`73eea000 region is Nonpaged pool
*ffffda02`73eea020 size: 40 previous size: 0 (Allocated) *Thre"""

SAMPLE_BLACKBOX = """PnpActivityId : {01234567-89ab-cdef-0123-456789abcdef}
PnpProblemCode : 24"""

SAMPLE_IMAGE_VERIFY = """fffff805`99100000-fffff805`99100004  5 bytes - nt!Example
    [ 0f 1f 44 00 00:cc cc cc cc cc ]
1 errors : nt!Example (fffff805`99100000-fffff805`99100004)"""

SAMPLE_FUNCTION_INFO = """Debugger function entry fffff805`99100000
BeginAddress = fffff805`99100000
EndAddress = fffff805`99100040
UnwindInfoAddress = fffff805`99200000"""

SAMPLE_MODULES_WITH_UNLOADED = """1: kd> start             end                 module name
fffff807`7de00000 fffff807`7f250000   nt         (pdb symbols)          C:\\ProgramData\\Dbg\\sym\\ntkrnlmp.pdb
fffff807`7f600000 fffff807`7f606000   hal        (deferred)

Unloaded modules:
fffff807`14a60000 fffff807`14a80000   NetworkPrivacyPolicy.sys
fffff807`12d20000 fffff807`12d3a000   dump_storport.sys"""

SAMPLE_SYMBOLS = """00007ff9`84fb00f0 ntdll!LdrpDoPostSnapWork (void)
00007ff9`850bd758 ntdll!LdrpDoDebuggerBreak (LdrpDoDebuggerBreak)"""

SAMPLE_LN = """Browse module
Set bu breakpoint

(00007ff9`850bd758)   ntdll!LdrpDoDebuggerBreak+0x35   |  (00007ff9`850bd790)   ntdll!LdrpDoDebuggerBreak+0x68"""

SAMPLE_LN_EXACT_MATCHES = """1: kd> Browse module
Set bu breakpoint

(fffff807`7e2f90d0)   nt!DbgBreakPointWithStatus   |  (fffff807`7e2f90d2)   nt!DbgBreakPointWithStatusEnd
Exact matches:"""

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

SAMPLE_RUNNING_TI = """0: kd> 
System Processors:  (000000000000000f)
  Idle Processors:  (0000000000000008)

       Prcbs             Current         (pri) Next            (pri) Idle
  0    fffff80526ad6180  ffffda0273eea040 ( 8) ffffda02746490c0 (14) fffff80599bd15c0  ................

 # Child-SP          RetAddr               Call Site
00 ffff968b`f8207708 fffff805`2d9c18d0     nt!DbgBreakPointWithStatus
01 ffff968b`f8207710 fffff805`2d9c1718     kdnic!TXTransmitQueuedSends+0x180
02 ffff968b`f82077a0 fffff805`2d9c20b7     kdnic!HandleSend+0x228

  1    ffffaa80efed1180  ffffda02717a4080 ( 0) ffffda0274f6b080 ( 8) ffffda02717a4080  ................

 # Child-SP          RetAddr               Call Site
00 ffff968b`f7a4f960 fffff805`992d9e48     nt!PpmIdleGuestExecute+0x15
01 ffff968b`f7a4f9a0 fffff805`990414a0     nt!PpmIdleExecuteTransition+0x36f7f4

  2    ffffaa80eff6d180  ffffda0274ec60c0 ( 8)                       ffffda0271844280  ................

 # Child-SP          RetAddr               Call Site
00 ffff968b`fa25f118 fffff805`98fe2dd6     nt!HalpApic1WriteIcr+0x39
01 ffff968b`fa25f120 fffff805`98e53761     nt!HalpApicRequestInterrupt+0x96

  3    ffffaa80efdc2180  ffffda0271853280 ( 0)                       ffffda0271853280  ................

 # Child-SP          RetAddr               Call Site
00 ffff968b`f7a8f960 fffff805`992d9e48     nt!PpmIdleGuestExecute+0x15
01 ffff968b`f7a8f9a0 fffff805`990414a0     nt!PpmIdleExecuteTransition+0x36f7f4
"""


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
        assert result["current"]["address"] == "0x00007ff9850bd78d"
        assert result["current"]["instruction"] == "int 3"

    def test_empty_input(self):
        result = parse_registers("")
        assert result["raw"] == ""

    def test_garbage_input(self):
        result = parse_registers("some random text")
        assert result["raw"] == "some random text"

    def test_prompted_command_echo_is_ignored(self):
        result = parse_registers("0:000> r\n" + SAMPLE_REGISTERS)

        assert result.status == "complete"
        assert result["registers"]["rip"] == "00007ff9850bd78d"


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

    def test_parse_kp_preserves_multiline_parameters(self):
        result = parse_stack_kp(SAMPLE_STACK_KP_PARAMETERS)

        assert result.status == "complete"
        assert result["frames"][0]["parameters"] == [
            "first = 0x0000000000000001,",
            "second = ffff968b`f8207800",
            ")",
        ]

    def test_parse_kp_preserves_inline_parameters(self):
        result = parse_stack_kp(SAMPLE_STACK_KP_INLINE_PARAMETERS)

        assert result.status == "complete"
        assert result["frames"][0]["parameters"] == [
            "0x00000001",
            "0x0012f2f0",
        ]
        assert result["frames"][0]["call_site"] == "ntdll!ExampleFunction+0x12"

    def test_parse_k_no_header(self):
        result = parse_stack_k("garbage text")
        assert result["raw"] == "garbage text"


class TestParseFrameSelection:
    def test_selected_frame(self):
        result = parse_frame_selection("0:000> .frame 0n5\n" + SAMPLE_FRAME_SELECTED)

        assert result.status == "complete"
        assert result["selected"] is True
        assert result["frame"] == 5
        assert result["child_sp"] == "0x000000d147e7f400"

    def test_rejected_frame_preserves_actual_current_frame(self):
        result = parse_frame_selection(SAMPLE_FRAME_REJECTED)

        assert result.status == "complete"
        assert result["selected"] is False
        assert result["current_frame"]["frame"] == 0

    def test_unrecognized_frame_output_fails(self):
        result = parse_frame_selection("unrecognized frame output")

        assert result.status == "failed"
        assert result["raw"] == "unrecognized frame output"


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

    def test_multiline_offsets_follow_dump_addresses(self):
        result = parse_memory_dump(SAMPLE_MEM_DD_MULTILINE)

        assert result.status == "complete"
        assert [entry["offset"] for entry in result["data"]] == [
            "0x0", "0x4", "0x8", "0xc",
            "0x10", "0x14", "0x18", "0x1c",
        ]

    def test_multiline_qword_offsets_do_not_reset(self):
        result = parse_memory_dump(SAMPLE_MEM_DQ)

        assert [entry["offset"] for entry in result["data"]] == [
            "0x0", "0x8", "0x10", "0x18",
        ]

    def test_detect_word_format(self):
        result = parse_memory_dump(SAMPLE_MEM_WORD)

        assert result.status == "complete"
        assert result["format"] == "hex_word"
        assert result["data"][3] == {"offset": "0x6", "value": "ffff"}

    def test_detect_qword_without_backticks(self):
        result = parse_memory_dump(SAMPLE_MEM_QWORD_NO_BACKTICK)

        assert result.status == "complete"
        assert result["format"] == "hex_qword"
        assert result["data"][1]["offset"] == "0x8"

    def test_detect_byte_ascii_without_separator_dash(self):
        result = parse_memory_dump(SAMPLE_MEM_DB_NO_DASH)

        assert result.status == "complete"
        assert result["format"] == "hex_byte"
        assert result["data"][0]["ascii"] == "A"
        assert result["data"][7]["ascii"] == "H"

    def test_detect_multiline_ascii_format(self):
        result = parse_memory_dump(SAMPLE_MEM_ASCII)

        assert result.status == "complete"
        assert result["format"] == "ascii"
        assert "".join(entry["ascii"] for entry in result["data"]) == "Hello, world!"
        assert result["data"][8] == {
            "offset": "0x8",
            "value": "6f",
            "ascii": "o",
        }

    def test_question_mark_placeholders_are_unavailable_memory(self):
        result = parse_memory_dump(SAMPLE_MEM_UNAVAILABLE)

        assert result.status == "partial"
        assert result.data["data"] == []
        assert result.data["available"] is False
        assert result.data["complete_range"] is False
        assert "memory_access_error" in result.warnings

    def test_values_before_question_mark_placeholders_are_preserved(self):
        result = parse_memory_dump(
            "00007ff9`850bd78d  cc eb ?? ??              ...."
        )

        assert result.status == "partial"
        assert [entry["value"] for entry in result.data["data"]] == [
            "cc",
            "eb",
        ]
        assert result.data["complete_range"] is False
        assert "memory_access_error" in result.warnings


class TestParseModules:
    def test_parse(self):
        result = parse_modules(SAMPLE_MODULES)
        mods = result["modules"]
        assert len(mods) == 1
        assert mods[0]["name"] == "ntdll"

    def test_no_modules(self):
        result = parse_modules("no module here")
        assert result["raw"] == "no module here"

    def test_unloaded_section_is_known_but_not_returned_as_loaded(self):
        result = parse_modules(SAMPLE_MODULES_WITH_UNLOADED)

        assert result.status == "complete"
        assert [module["name"] for module in result.data["modules"]] == [
            "nt",
            "hal",
        ]
        assert result.raw == SAMPLE_MODULES_WITH_UNLOADED


class TestParseModuleInfo:
    def test_valid_empty_module_detail_is_not_a_parse_failure(self):
        result = parse_module_info(
            "Browse full module list\nstart             end                 module name"
        )

        assert result.status == "complete"
        assert result.data == {"found": False, "module": {}}


class TestParseSymbolList:
    def test_parse(self):
        result = parse_symbol_list(SAMPLE_SYMBOLS)
        syms = result["symbols"]
        assert len(syms) == 2
        assert syms[0]["name"] == "ntdll!LdrpDoPostSnapWork"

    def test_empty(self):
        result = parse_symbol_list("")
        assert result.status == "complete"
        assert result.data == {"found": False, "symbols": []}

    def test_could_not_resolve_is_a_valid_empty_result(self):
        result = parse_symbol_list(
            "2: kd> ^ Couldn't resolve 'x DefinitelyMissingModule'"
        )

        assert result.status == "complete"
        assert result.data == {"found": False, "symbols": []}


class TestParseNearestSymbol:
    def test_parse(self):
        result = parse_nearest_symbol(SAMPLE_LN)
        assert result["symbol"]["address"] == "0x00007ff9850bd758"
        assert result["symbol"]["name"] == "ntdll!LdrpDoDebuggerBreak+0x35"
        assert result["symbols"] == [
            {
                "address": "0x00007ff9850bd758",
                "name": "ntdll!LdrpDoDebuggerBreak+0x35",
            },
            {
                "address": "0x00007ff9850bd790",
                "name": "ntdll!LdrpDoDebuggerBreak+0x68",
            },
        ]

    def test_empty(self):
        result = parse_nearest_symbol("no symbol")
        assert result["raw"] == "no symbol"

    def test_exact_matches_heading_is_known_output(self):
        result = parse_nearest_symbol(SAMPLE_LN_EXACT_MATCHES)

        assert result.status == "complete"
        assert [symbol["name"] for symbol in result.data["symbols"]] == [
            "nt!DbgBreakPointWithStatus",
            "nt!DbgBreakPointWithStatusEnd",
        ]
        assert result.raw == SAMPLE_LN_EXACT_MATCHES

    def test_same_line_unmatched_content_is_partial(self):
        raw = (
            "(00007ff9`850bd758) ntdll!First | "
            "(00007ff9`850bd790) ntdll!Second trailing"
        )
        result = parse_nearest_symbol(raw)

        assert result.status == "partial"
        assert [symbol["name"] for symbol in result.data["symbols"]] == [
            "ntdll!First",
            "ntdll!Second",
        ]
        assert result.unparsed_lines == ("trailing",)

    def test_completed_prompt_without_match_is_not_found(self):
        result = parse_nearest_symbol("0: kd> ln 1234\n0: kd>")

        assert result.status == "complete"
        assert result.data == {"found": False, "symbols": []}


class TestParserRegressions:
    def test_disassembly_accepts_long_machine_code_without_fixed_columns(self):
        result = parse_disassembly(SAMPLE_DISASM_LONG_BYTES)

        assert result.status == "complete"
        assert result.data["instructions"][0]["bytes"] == "f7451840000000"
        assert result.data["instructions"][0]["instruction"] == (
            "test dword ptr [rbp+18h],40000000h"
        )

    def test_disassembly_retains_instructions_before_missing_page(self):
        result = parse_disassembly(SAMPLE_DISASM_PARTIAL_MEMORY)

        assert result.status == "partial"
        assert len(result.data["instructions"]) == 1
        assert result.data["complete_range"] is False
        assert "memory_access_error" in result.warnings

    def test_memory_dump_classifies_missing_page_after_valid_data(self):
        raw = SAMPLE_MEM_DB_NO_DASH + "\nMemory access error at '0x0012f008'"
        result = parse_memory_dump(raw)

        assert result.status == "partial"
        assert len(result.data["data"]) == 8
        assert result.data["complete_range"] is False
        assert "memory_access_error" in result.warnings


class TestParseTargetInfo:
    @pytest.mark.parametrize(
        ("raw", "mode", "kind"),
        [
            (". 0 Live user mode: <Local>", "user", "live_user"),
            (". 0 Live kernel mode: NET:port=50000", "kernel", "live_kernel"),
            (". 0 64-bit User mini dump: a.dmp", "user", "user_dump"),
            (
                ". 0 64-bit Kernel triage dump: a.dmp",
                "kernel",
                "kernel_triage_dump",
            ),
            (
                ". 0 64-bit Kernel bitmap dump: a.dmp",
                "kernel",
                "kernel_memory_dump",
            ),
            (
                ". 0 64-bit Complete memory dump: a.dmp",
                "kernel",
                "complete_memory_dump",
            ),
        ],
    )
    def test_classifies_session_and_capabilities(self, raw, mode, kind):
        result = parse_target_info(raw)

        assert result.status == "complete"
        assert result.data["target_mode"] == mode
        assert result.data["session_kind"] == kind
        assert result.data["capabilities"]["is_dump"] is kind.endswith("_dump")

    def test_unknown_session_does_not_invent_negative_capabilities(self):
        result = parse_target_info(
            "Windows 11 Kernel Version 26100\nKernel base = fffff805`99000000"
        )

        assert result.status == "partial"
        assert result.data["target_mode"] == "kernel"
        assert result.data["session_kind"] == "unknown"
        assert all(
            value is None for value in result.data["capabilities"].values()
        )
        assert "session_kind_unknown" in result.warnings


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

    def test_malformed_nonempty_output_fails(self):
        result = parse_breakpoints("no breakpoints")
        assert result.status == "failed"
        assert result["raw"] == "no breakpoints"

    def test_real_empty_engine_output_is_complete(self):
        result = parse_breakpoints("")

        assert result.status == "complete"
        assert result["breakpoints"] == []

    def test_explicit_debugger_error_fails(self):
        raw = "error: No current process or thread"
        result = parse_breakpoints(raw)

        assert result.status == "failed"
        assert result.data == {}
        assert result["raw"] == raw

    def test_empty_prompt_means_no_breakpoints(self):
        result = parse_breakpoints(SAMPLE_BREAKPOINTS_EMPTY)
        assert result["breakpoints"] == []

    def test_standalone_prompt_and_command_mean_no_breakpoints(self):
        result = parse_breakpoints("kd> bl")

        assert result.status == "complete"
        assert result["breakpoints"] == []


class TestParseThreadListKernel:
    def test_parse(self):
        result = parse_thread_list_kernel(SAMPLE_RUNNING_TI)
        assert result["system_processors"] == "0x000000000000000f"
        assert result["idle_processors"] == "0x0000000000000008"
        procs = result["processors"]
        assert len(procs) == 4

        p0 = procs[0]
        assert p0["processor"] == 0
        assert p0["prcb"] == "0xfffff80526ad6180"
        assert p0["current_thread"] == "0xffffda0273eea040"
        assert p0["current_pri"] == 8
        assert p0["next_thread"] == "0xffffda02746490c0"
        assert p0["next_pri"] == 14
        assert p0["idle_thread"] == "0xfffff80599bd15c0"
        assert len(p0["stack"]) == 3
        assert p0["stack"][0]["index"] == "00"
        assert p0["stack"][0]["child_sp"] == "0xffff968bf8207708"
        assert p0["stack"][0]["call_site"] == "nt!DbgBreakPointWithStatus"

    def test_processor_without_next(self):
        result = parse_thread_list_kernel(SAMPLE_RUNNING_TI)
        p2 = result["processors"][2]
        assert "next_thread" not in p2
        assert "next_pri" not in p2
        assert p2["current_thread"] == "0xffffda0274ec60c0"
        assert p2["idle_thread"] == "0xffffda0271844280"

    def test_empty(self):
        result = parse_thread_list_kernel("user mode output")
        assert result["raw"] == "user mode output"


ALL_PARSERS = [
    parse_registers, parse_stack_k, parse_stack_kp, parse_frame_selection,
    parse_disassembly, parse_memory_dump, parse_modules,
    parse_symbol_list, parse_nearest_symbol, parse_type_info,
    parse_evaluate, parse_analyze, parse_process_list,
    parse_thread_list_user, parse_thread_list_kernel, parse_breakpoints,
    parse_thread_info, parse_module_info, parse_pte, parse_pool,
    parse_blackbox, parse_image_verify, parse_function_info,
]

COMPLETE_CASES = [
    (parse_registers, SAMPLE_REGISTERS),
    (parse_stack_k, SAMPLE_STACK_K),
    (parse_stack_kp, SAMPLE_STACK_KP),
    (parse_frame_selection, SAMPLE_FRAME_SELECTED),
    (parse_disassembly, SAMPLE_DISASM),
    (parse_memory_dump, SAMPLE_MEM_DD),
    (parse_modules, SAMPLE_MODULES),
    (parse_symbol_list, SAMPLE_SYMBOLS),
    (parse_nearest_symbol, SAMPLE_LN),
    (parse_type_info, SAMPLE_TYPE_INFO),
    (parse_evaluate, SAMPLE_EVALUATE),
    (parse_analyze, SAMPLE_ANALYZE_QUICK),
    (parse_process_list, SAMPLE_PROCESS_LIST),
    (parse_thread_list_user, SAMPLE_THREADS_USER),
    (parse_thread_list_kernel, SAMPLE_RUNNING_TI),
    (parse_breakpoints, SAMPLE_BREAKPOINTS),
    (parse_thread_info, SAMPLE_THREAD_INFO),
    (parse_module_info, SAMPLE_MODULE_INFO),
    (parse_pte, SAMPLE_PTE),
    (parse_pool, SAMPLE_POOL),
    (parse_blackbox, SAMPLE_BLACKBOX),
    (parse_image_verify, SAMPLE_IMAGE_VERIFY),
    (parse_function_info, SAMPLE_FUNCTION_INFO),
]


class TestParseResult:
    def test_complete_mapping_exposes_data(self):
        result = ParseResult(
            status="complete",
            data={"answer": 42},
            raw="original",
            unparsed_lines=[],
            warnings=[],
        )

        assert isinstance(result, Mapping)
        assert "answer" in result
        assert "raw" not in result
        assert result["answer"] == 42
        assert result.get("answer") == 42
        assert {**result} == {"answer": 42}
        assert json.loads(json.dumps(result)) == {"answer": 42}
        updated = {}
        updated.update(result)
        assert updated == {"answer": 42}

    @pytest.mark.parametrize("status", ["partial", "failed"])
    def test_incomplete_mapping_exposes_only_raw(self, status):
        result = ParseResult(
            status=status,
            data={"answer": 42} if status == "partial" else {},
            raw="original",
            unparsed_lines=["unexpected"],
            warnings=["unparsed_lines"],
        )

        assert "raw" in result
        assert "answer" not in result
        assert result.get("raw") == "original"
        assert result["raw"] == "original"
        assert {**result} == {"raw": "original"}
        assert json.loads(json.dumps(result)) == {"raw": "original"}

    def test_mapping_is_read_only(self):
        result = ParseResult("complete", {"answer": 42}, "", [], [])

        with pytest.raises(TypeError):
            result["answer"] = 0  # type: ignore[index]
        with pytest.raises(TypeError):
            result.update({"answer": 0})

    def test_invariant_collections_are_immutable(self):
        result = ParseResult("failed", {}, "raw", ["unparsed"], ["warning"])

        with pytest.raises(TypeError):
            result.data["answer"] = 42  # type: ignore[index]
        with pytest.raises(AttributeError):
            result.unparsed_lines.append("later")  # type: ignore[attr-defined]
        with pytest.raises(AttributeError):
            result.warnings.append("later")  # type: ignore[attr-defined]

    def test_constructor_copies_invariant_collections(self):
        data = {}
        unparsed_lines = ["unparsed"]
        warnings = ["warning"]
        result = ParseResult("failed", data, "raw", unparsed_lines, warnings)

        data["invented"] = True
        unparsed_lines.append("later")
        warnings.append("later")
        assert result.data == {}
        assert result.unparsed_lines == ("unparsed",)
        assert result.warnings == ("warning",)

    def test_failed_result_rejects_invented_data(self):
        with pytest.raises(ValueError):
            ParseResult("failed", {"answer": 42}, "", [], [])

    def test_complete_result_rejects_unparsed_lines(self):
        with pytest.raises(ValueError):
            ParseResult("complete", {"answer": 42}, "", ["lost"], [])

    def test_partial_result_requires_diagnostic(self):
        with pytest.raises(ValueError):
            ParseResult("partial", {"answer": 42}, "", [], [])


class TestTypedConsumers:
    @pytest.mark.parametrize(
        ("raw", "expected_count"),
        [(SAMPLE_BREAKPOINTS, 2), ("", 0)],
    )
    def test_registered_breakpoint_list_returns_typed_complete_result(
        self,
        monkeypatch,
        raw,
        expected_count,
    ):
        class CapturingMCP:
            registered = None

            def tool(self, *args, **kwargs):
                def register(function):
                    self.registered = function
                    return function

                return register

        mcp = CapturingMCP()

        class Executor:
            def execute(self, command, **policy):
                assert command == "bl"
                return ExecutionResult(
                    status="completed",
                    output=raw,
                    complete=True,
                )

        monkeypatch.setattr(_registry, "_executor", Executor())
        breakpoint_tool.register_breakpoint_tool(mcp)

        payload = mcp.registered("list")
        assert isinstance(payload, ToolEnvelope)
        assert len(payload.data["breakpoints"]) == expected_count
        assert payload.errors == []

    @pytest.mark.parametrize(
        ("raw", "expected_status"),
        [
            (SAMPLE_BREAKPOINTS + "\nUNEXPECTED", "partial"),
            ("malformed breakpoint output", "failed"),
        ],
    )
    def test_typed_response_path_preserves_incomplete_results(
        self,
        raw,
        expected_status,
    ):
        result = parse_breakpoints(raw)

        assert result.status == expected_status
        execution = ExecutionResult(
            status="completed",
            output=raw,
            complete=True,
        )
        source = source_item("bl", execution, result)
        payload = parsed_response("windbg_breakpoint", source, result)
        assert payload.data == dict(result.data)
        assert payload.raw == ""
        assert payload.sources[0].raw_size == len(raw)
        assert payload.sources[0].command_id
        if expected_status == "partial":
            assert payload.errors == []
            assert payload.warnings[0].code == "parse_partial"
            assert payload.ok is True
        else:
            assert payload.errors[0].code == f"parse_{expected_status}"


class TestParseCompleteness:
    @pytest.mark.parametrize(("parser", "sample"), COMPLETE_CASES)
    def test_real_samples_are_complete(self, parser, sample):
        result = parser(sample)

        assert result.status == "complete", parser.__name__
        assert result.unparsed_lines == ()
        assert "raw" not in result

    @pytest.mark.parametrize(("parser", "sample"), COMPLETE_CASES)
    def test_unmatched_meaningful_line_makes_result_partial(self, parser, sample):
        raw = sample + "\nUNEXPECTED MEANINGFUL OUTPUT"
        result = parser(raw)

        assert result.status == "partial", parser.__name__
        assert result.data
        assert result.unparsed_lines == ("UNEXPECTED MEANINGFUL OUTPUT",)
        assert "unparsed_lines" in result.warnings
        assert {**result} == {"raw": raw}


class TestFailback:
    """Failed parsers retain raw output and never raise on malformed text."""

    def test_all_return_raw_on_empty(self):
        valid_empty_parsers = {
            parse_breakpoints,
            parse_symbol_list,
            parse_nearest_symbol,
        }
        for parser in (
            parser for parser in ALL_PARSERS
            if parser not in valid_empty_parsers
        ):
            result = parser("")
            assert result.status == "failed", parser.__name__
            assert result.data == {}
            assert "raw" in result, f"{parser.__name__} failed on empty input"

    def test_all_no_exception_on_garbage(self):
        garbage = "!@#$%^&*()_+\nnothing\n12345\n"
        for parser in ALL_PARSERS:
            try:
                result = parser(garbage)
                assert isinstance(result, ParseResult)
                assert result.status == "failed", parser.__name__
                assert result.unparsed_lines == ("!@#$%^&*()_+", "nothing", "12345")
            except Exception as e:
                assert False, f"{parser.__name__} raised {e} on garbage input"
