import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from debugger.engine import ExecutionResult
from tools import _registry
from tools._models import ToolEnvelope
from tools.analyze_tool import register_analyze_tool
from tools.breakpoint_tool import register_breakpoint_tool
from tools.context_tool import _session_kind, register_context_tool
from tools.control_tool import register_control_tool
from tools.disasm_tool import register_disasm_tool
from tools.eval_tool import register_eval_tool
from tools.exec_tool import register_exec_tool
from tools.lookup_tool import register_lookup_tool
from tools.memory_tool import register_memory_tool
from tools.stack_tool import register_stack_tool
from tools.sympath_tool import register_sympath_tool


EVALUATE_RIP = "Evaluate expression: 140709204350861 = 00007ff9`850bd78d"
REGISTERS = "rip=00007ff9850bd78d rsp=000000837ec7ed50"
STACK = """Child-SP          RetAddr               Call Site
00000019`bd4bf280 00007ff9`8502d83a     ntdll!LdrpDoDebuggerBreak+0x35"""
DISASSEMBLY = """ntdll!LdrpDoDebuggerBreak+0x35:
00007ff9`850bd78d cc              int     3"""
MEMORY_BYTES = "00007ff9`850bd78d  90 91"
MODULE_DEFERRED = """start             end                 module name
00007ff9`84fa0000 00007ff9`85206000   ntdll      (deferred)"""
MODULE_LOADED = """start             end                 module name
00007ff9`84fa0000 00007ff9`85206000   ntdll      (pdb symbols) C:\\symbols\\ntdll.pdb"""
THREADS_USER = ".  0  Id: 1234.5678 Suspend: 1 Teb: 00000083`7ea20000 Unfrozen"
THREADS_KERNEL = """System Processors:  (0000000000000001)
  Idle Processors:  (0000000000000000)
       Prcbs             Current         (pri) Next            (pri) Idle
  0    fffff80526ad6180  ffffda0273eea040 ( 8) ffffda02746490c0 (14) fffff80599bd15c0"""
ANALYZE = """BUGCHECK_CODE:  1e
PROCESS_NAME:  notepad.exe"""
VERTARGET_USER = """Windows 10 Version 26200 MP (32 procs) Free x64
Product: WinNt, suite: SingleUserTS
Debug session time: Fri Jul 10 22:52:23.535 2026 (UTC + 8:00)
System Uptime: 0 days 5:28:06.213
Process Uptime: 0 days 0:00:00.036
  Kernel time: 0 days 0:00:00.000
  User time: 0 days 0:00:00.000"""
VERTARGET_KERNEL = """Windows 10 Kernel Version 26100 MP (4 procs) Free x64
Kernel base = 0xfffff805`99000000 PsLoadedModuleList = 0xfffff805`99e2f2b0
Debug session time: Fri Jul 10 22:52:23.535 2026 (UTC + 8:00)
System Uptime: 0 days 5:28:06.213"""
SYSTEM_USER_LIVE = ".  0 Live user mode: <Local>"
SYSTEM_USER_DUMP = ".  0 64-bit User mini dump: C:\\dumps\\notepad.dmp"
SYSTEM_KERNEL_LIVE = ".  0 Live kernel mode: NET:port=50000"
SYSTEM_KERNEL_DUMP = ".  0 64-bit Kernel bitmap dump: C:\\dumps\\memory.dmp"
SYSTEM_KERNEL_REMOTE = (
    "1: kd> .  0 Remote KD: KdSrv:Server=@{<Local>},"
    "Trans=@{NET:Port=50000,Key=1.2.3.4,Target}"
)
FRAME_SELECTED_5 = (
    "05 000000d1`47e7f400 00007fff`e5a4d83a     "
    "ntdll!LdrpDoDebuggerBreak+0x35"
)
BREAKPOINT = (
    " 0 e Disable Clear  00007ff9`850bd78d     "
    "0001 (0001)  0:**** ntdll!LdrpDoDebuggerBreak @rcx == 0"
)


def completed(output=""):
    return ExecutionResult(status="completed", output=output, complete=True)


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *args, **kwargs):
        def decorator(function):
            self.tools[function.__name__] = function
            return function
        return decorator


class ScriptedExecutor:
    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls = []

    def execute(self, command, *, read_only=False, retryable=False):
        self.calls.append({
            "command": command,
            "read_only": read_only,
            "retryable": retryable,
        })
        if not self.steps:
            raise AssertionError(f"unexpected command: {command}")
        expected_command, result = self.steps.pop(0)
        assert command == expected_command
        return result

    def assert_done(self):
        assert self.steps == []


@pytest.fixture
def toolset():
    mcp = FakeMCP()
    for register in (
        register_exec_tool,
        register_context_tool,
        register_control_tool,
        register_breakpoint_tool,
        register_memory_tool,
        register_disasm_tool,
        register_stack_tool,
        register_lookup_tool,
        register_analyze_tool,
        register_eval_tool,
        register_sympath_tool,
    ):
        register(mcp)
    return mcp.tools


def install_executor(monkeypatch, *steps):
    executor = ScriptedExecutor(*steps)
    monkeypatch.setattr(_registry, "_executor", executor)
    return executor


def test_registers_all_twelve_public_tools(toolset):
    assert set(toolset) == {
        "windbg_exec",
        "windbg_context",
        "windbg_control",
        "windbg_breakpoint",
        "windbg_read_memory",
        "windbg_write_memory",
        "windbg_disassemble",
        "windbg_backtrace",
        "windbg_lookup",
        "windbg_analyze",
        "windbg_evaluate",
        "windbg_sympath",
    }


def test_raw_exec_remains_open_world_string_escape_hatch(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        (".echo first; r", completed("raw debugger output")),
    )

    result = toolset["windbg_exec"](".echo first; r")

    assert result == "raw debugger output"
    assert executor.calls[0]["read_only"] is False
    assert executor.calls[0]["retryable"] is False


def test_evaluate_returns_hex_strings_in_typed_envelope(toolset, monkeypatch):
    executor = install_executor(monkeypatch, ("? @rip", completed(EVALUATE_RIP)))

    result = toolset["windbg_evaluate"]("@rip")

    assert isinstance(result, ToolEnvelope)
    assert result.data == {
        "input": "@rip",
        "value": "0x00007ff9850bd78d",
        "decimal": "140709204350861",
    }
    assert result.sources[0].parse_status == "complete"
    assert executor.calls[0]["read_only"] is True
    assert executor.calls[0]["retryable"] is True


def test_disassemble_resolves_address_and_uses_explicit_radix(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        ("? @rip", completed(EVALUATE_RIP)),
        ("u 0x00007ff9850bd78d L0n8", completed(DISASSEMBLY)),
    )

    result = toolset["windbg_disassemble"]("@rip", "8")

    assert result.ok is True
    assert result.data["resolved_address"] == "0x00007ff9850bd78d"
    assert result.data["instructions"][0]["address"] == "0x00007ff9850bd78d"
    assert len(result.sources) == 2
    executor.assert_done()


def test_backtrace_uses_explicit_decimal_depth(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        ("kP 0n20", completed(STACK)),
    )

    result = toolset["windbg_backtrace"]()

    assert result.ok is True
    assert result.data["frames"][0]["child_sp"].startswith("0x")
    assert result.sources[0].command == "kP 0n20"
    assert executor.calls[0]["read_only"] is True


def test_backtrace_verifies_frame_before_attributing_locals(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        (".frame 0n5", completed(FRAME_SELECTED_5)),
        ("dv /t /i", completed("int x = 1")),
    )

    result = toolset["windbg_backtrace"](frame="5")

    assert result.ok is True
    assert result.verification_status == "verified"
    assert result.data["requested_frame"] == 5
    assert result.data["frame"] == 5
    assert result.data["locals_raw"] == "int x = 1"
    executor.assert_done()


def test_backtrace_rejects_invalid_frame_without_collecting_locals(
    toolset,
    monkeypatch,
):
    executor = install_executor(
        monkeypatch,
        (
            ".frame 0n5",
            completed(
                "Cannot find frame 0x5, previous scope unchanged\n"
                "00 000000d1`47e7f400 00007fff`e5a4d83a     "
                "ntdll!LdrpDoDebuggerBreak+0x35"
            ),
        ),
    )

    result = toolset["windbg_backtrace"](frame="5")

    assert result.ok is False
    assert result.verification_status == "failed"
    assert result.data["requested_frame"] == 5
    assert result.data["current_frame"]["frame"] == 0
    assert "frame" not in result.data
    assert "locals_raw" not in result.data
    assert any(error.code == "frame_selection_failed" for error in result.errors)
    executor.assert_done()


def test_backtrace_rejects_selected_frame_mismatch(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        (".frame 0n5", completed(FRAME_SELECTED_5.replace("05 ", "04 ", 1))),
    )

    result = toolset["windbg_backtrace"](frame="5")

    assert result.ok is False
    assert result.verification_status == "failed"
    assert result.data["selected_frame"] == 4
    assert "frame" not in result.data
    assert "locals_raw" not in result.data
    assert any(error.code == "frame_selection_mismatch" for error in result.errors)
    executor.assert_done()


def test_lookup_explicit_kind_and_visible_auto_routing(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        (
            "dt ntdll!_TEB",
            completed("   +0x000 NtTib            : _NT_TIB"),
        ),
        (
            "x kernel32!CreateFileW",
            completed("00007ff9`84fb00f0 kernel32!CreateFileW (void)"),
        ),
    )

    explicit = toolset["windbg_lookup"]("ntdll!_TEB", "type")
    automatic = toolset["windbg_lookup"]("kernel32!CreateFileW")

    assert explicit.data["kind"] == "type"
    assert explicit.inferences == []
    assert automatic.data["kind"] == "symbol"
    assert automatic.inferences[0].name == "lookup_routing"
    assert automatic.inferences[0].value == "symbol"
    executor.assert_done()


def test_lookup_address_is_resolved_before_nearest_symbol_query(toolset, monkeypatch):
    nearest = (
        "(00007ff9`850bd758) ntdll!LdrpDoDebuggerBreak+0x35 | "
        "(00007ff9`850bd790) ntdll!LdrpDoDebuggerBreak+0x68"
    )
    executor = install_executor(
        monkeypatch,
        ("? 0x00007ff9850bd78d", completed(EVALUATE_RIP)),
        ("ln 0x00007ff9850bd78d", completed(nearest)),
    )

    result = toolset["windbg_lookup"]("00007ff9`850bd78d", "address")

    assert result.ok is True
    assert result.data["resolved_address"] == "0x00007ff9850bd78d"
    assert result.data["symbol"]["name"].startswith("ntdll!")
    assert len(result.sources) == 2
    executor.assert_done()


def test_read_memory_resolves_address_before_dump(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        ("? @rip", completed(EVALUATE_RIP)),
        ("db 0x00007ff9850bd78d L0n2", completed(MEMORY_BYTES)),
    )

    result = toolset["windbg_read_memory"]("@rip", "2", "byte")

    assert result.ok is True
    assert result.data["input"] == "@rip"
    assert result.data["resolved_address"] == "0x00007ff9850bd78d"
    assert [item["value"] for item in result.data["data"]] == ["90", "91"]
    assert len(result.sources) == 2


def test_compound_address_numbers_are_radix_independent(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        ("? poi(@rsp+0x8)+0x10", completed(EVALUATE_RIP)),
        ("db 0x00007ff9850bd78d L0n2", completed(MEMORY_BYTES)),
    )

    result = toolset["windbg_read_memory"]("poi(@rsp+8)+10", "2", "byte")

    assert result.ok is True
    assert executor.calls[0]["command"] == "? poi(@rsp+0x8)+0x10"


def test_write_memory_is_verified_by_readback(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        ("? @rip", completed(EVALUATE_RIP)),
        ("eb 0x00007ff9850bd78d 0x90 0x91", completed()),
        ("db 0x00007ff9850bd78d L0n2", completed(MEMORY_BYTES)),
    )

    result = toolset["windbg_write_memory"]("@rip", "90 91")

    assert result.ok is True
    assert result.verification_status == "verified"
    assert result.data["readback_address"] == "0x00007ff9850bd78d"
    assert result.data["readback_offsets"] == ["0x0", "0x1"]
    assert result.data["readback_values"] == ["0x90", "0x91"]
    assert len(result.sources) == 3
    assert executor.calls[1]["read_only"] is False
    assert executor.calls[1]["retryable"] is False


@pytest.mark.parametrize(
    ("readback", "expected_verification"),
    [
        ("00007ff9`850bd78d  90 92", "failed"),
        ("00007ff9`850bd790  90 91", "failed"),
        (
            "00007ff9`850bd78d  90\n00007ff9`850bd78f  91",
            "failed",
        ),
        (MEMORY_BYTES + "\nUNEXPECTED", "indeterminate"),
    ],
)
def test_write_memory_never_verifies_incomplete_or_mismatched_readback(
    toolset,
    monkeypatch,
    readback,
    expected_verification,
):
    install_executor(
        monkeypatch,
        ("? @rip", completed(EVALUATE_RIP)),
        ("eb 0x00007ff9850bd78d 0x90 0x91", completed()),
        ("db 0x00007ff9850bd78d L0n2", completed(readback)),
    )

    result = toolset["windbg_write_memory"]("@rip", "90 91")

    assert result.ok is False
    assert result.verification_status == expected_verification
    assert any(error.stage == "verification" for error in result.errors)


def test_conditional_breakpoint_uses_w_syntax_and_post_list(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        ("? @rip", completed(EVALUATE_RIP)),
        ("bl", completed("0:000> ")),
        ('bp /w "@rcx == 0" 0x00007ff9850bd78d', completed()),
        ("bl", completed(BREAKPOINT)),
    )

    result = toolset["windbg_breakpoint"](
        "set",
        target="@rip",
        condition="@rcx == 0",
    )

    assert result.ok is True
    assert result.verification_status == "verified"
    assert len(result.sources) == 4
    assert executor.calls[2]["retryable"] is False


def test_breakpoint_wildcard_enable_verifies_every_breakpoint(toolset, monkeypatch):
    before = BREAKPOINT.replace(" 0 e ", " 0 d ") + "\n" + BREAKPOINT.replace(
        " 0 e ",
        " 1 d ",
    ).replace("00007ff9`850bd78d", "00007ff9`850bd790")
    after = before.replace(" 0 d ", " 0 e ").replace(" 1 d ", " 1 e ")
    install_executor(
        monkeypatch,
        ("bl", completed(before)),
        ("be *", completed()),
        ("bl", completed(after)),
    )

    result = toolset["windbg_breakpoint"]("enable", id="*")

    assert result.ok is True
    assert result.verification_status == "verified"
    assert result.data["affected_ids"] == ["0", "1"]


def test_step_out_count_runs_gu_once_per_frame(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        ("gu", completed()),
        ("gu", completed()),
        ("gu", completed()),
    )

    result = toolset["windbg_control"]("step_out", "3")

    assert result.data["target_state"] == "broken"
    assert result.verification_status == "verified"
    assert [source.command for source in result.sources] == ["gu", "gu", "gu"]
    assert all(call["retryable"] is False for call in executor.calls)


@pytest.mark.parametrize(
    ("execution", "expected_state", "expected_verification"),
    [
        (
            ExecutionResult(status="timeout", error="target did not break"),
            "running",
            "indeterminate",
        ),
        (
            ExecutionResult(
                status="disconnected",
                error="debugger disconnected",
                attempts=0,
            ),
            "indeterminate",
            "indeterminate",
        ),
    ],
)
def test_control_reports_non_completed_target_state(
    toolset,
    monkeypatch,
    execution,
    expected_state,
    expected_verification,
):
    install_executor(monkeypatch, ("g", execution))

    result = toolset["windbg_control"]("go")

    assert result.data["target_state"] == expected_state
    assert result.verification_status == expected_verification
    assert result.ok is False


def test_sympath_set_and_reload_state_are_verified(toolset, monkeypatch):
    path = "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols;C:\\private"
    executor = install_executor(
        monkeypatch,
        (f".sympath {path}", completed()),
        (".sympath", completed(f"Symbol search path is: {path}")),
    )

    result = toolset["windbg_sympath"]("set", path=path)

    assert result.ok is True
    assert result.verification_status == "verified"
    assert len(result.sources) == 2
    assert executor.calls[0]["retryable"] is False


def test_sympath_set_does_not_verify_partial_timeout_output(toolset, monkeypatch):
    path = "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
    install_executor(
        monkeypatch,
        (f".sympath {path}", completed()),
        (
            ".sympath",
            ExecutionResult(
                status="timeout",
                output=f"Symbol search path is: {path}",
                error="query timed out",
            ),
        ),
    )

    result = toolset["windbg_sympath"]("set", path=path)

    assert result.ok is False
    assert result.verification_status == "indeterminate"


def test_deferred_symbols_are_not_classified_as_missing(toolset, monkeypatch):
    install_executor(monkeypatch, ("lm", completed(MODULE_DEFERRED)))

    result = toolset["windbg_sympath"]("check")

    health = result.inferences[0].value
    assert health["status"] == "deferred"
    assert health["missing_modules"] == []
    assert health["deferred_modules"] == ["ntdll"]
    assert "symbol_health" not in result.data


def test_symbol_reload_verifies_by_querying_module_state(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        (".reload /f ntdll", completed("reload requested")),
        ("lm m ntdll", completed(MODULE_LOADED)),
    )

    result = toolset["windbg_sympath"]("reload", module="ntdll")

    assert result.ok is True
    assert result.verification_status == "verified"
    assert [source.command for source in result.sources] == [
        ".reload /f ntdll",
        "lm m ntdll",
    ]
    assert executor.calls[0]["retryable"] is False


@pytest.mark.parametrize(
    ("module_output", "expected_verification"),
    [
        (MODULE_DEFERRED, "failed"),
        ("start             end                 module name", "indeterminate"),
    ],
)
def test_symbol_reload_never_verifies_deferred_or_missing_module_state(
    toolset,
    monkeypatch,
    module_output,
    expected_verification,
):
    install_executor(
        monkeypatch,
        (".reload /f ntdll", completed("reload requested")),
        ("lm m ntdll", completed(module_output)),
    )

    result = toolset["windbg_sympath"]("reload", module="ntdll")

    assert result.ok is False
    assert result.verification_status == expected_verification
    assert any(error.stage == "verification" for error in result.errors)


@pytest.mark.parametrize(
    (
        "vertarget",
        "debug_systems",
        "expected_mode",
        "expected_session",
        "thread_command",
        "thread_output",
        "expected_route",
    ),
    [
        (
            VERTARGET_USER,
            SYSTEM_USER_LIVE,
            "user",
            "live",
            "~",
            THREADS_USER,
            "user_threads",
        ),
        (
            VERTARGET_USER,
            SYSTEM_USER_DUMP,
            "user",
            "dump",
            "~",
            THREADS_USER,
            "user_threads",
        ),
        (
            VERTARGET_KERNEL,
            SYSTEM_KERNEL_LIVE,
            "kernel",
            "live",
            "!running -ti",
            THREADS_KERNEL,
            "kernel_running",
        ),
        (
            VERTARGET_KERNEL,
            SYSTEM_KERNEL_REMOTE,
            "kernel",
            "live",
            "!running -ti",
            THREADS_KERNEL,
            "kernel_running",
        ),
        (
            VERTARGET_KERNEL,
            SYSTEM_KERNEL_DUMP,
            "kernel",
            "dump",
            "!running -ti",
            THREADS_KERNEL,
            "kernel_running",
        ),
    ],
)
def test_context_routes_real_user_kernel_and_live_dump_forms(
    toolset,
    monkeypatch,
    vertarget,
    debug_systems,
    expected_mode,
    expected_session,
    thread_command,
    thread_output,
    expected_route,
):
    executor = install_executor(
        monkeypatch,
        ("vertarget", completed(vertarget)),
        ("||", completed(debug_systems)),
        ("r", completed(REGISTERS)),
        ("kP 0n1", completed(STACK)),
        (".lastevent", completed("Last event: breakpoint")),
        ("lm", completed(MODULE_DEFERRED)),
        (thread_command, completed(thread_output)),
    )

    result = toolset["windbg_context"]("threads")

    assert result.ok is True
    assert result.data["target_mode"] == expected_mode
    assert result.data["session_kind"] == expected_session
    assert result.data["target_state"] == "broken"
    assert len(result.sources) == 7
    assert result.inferences[0].name == "symbol_health"
    assert result.inferences[1].value == expected_route
    assert executor.calls[-1]["command"] == thread_command
    executor.assert_done()


def test_session_kind_recognizes_remote_kd_target_as_live():
    assert _session_kind(SYSTEM_KERNEL_REMOTE) == "live"


def test_session_kind_keeps_dump_priority_over_remote_live_evidence():
    assert _session_kind(SYSTEM_KERNEL_REMOTE, SYSTEM_KERNEL_DUMP) == "dump"


def test_crash_analysis_uses_exception_context_only_for_user_dump(toolset, monkeypatch):
    executor = install_executor(
        monkeypatch,
        ("vertarget", completed(VERTARGET_USER)),
        ("||", completed(SYSTEM_USER_DUMP)),
        ("!analyze -v", completed(ANALYZE)),
        (".ecxr", completed(REGISTERS)),
        ("r", completed(REGISTERS)),
        ("kP 0n30", completed(STACK)),
    )

    result = toolset["windbg_analyze"]("crash")

    assert result.data["target_mode"] == "user"
    assert result.data["session_kind"] == "dump"
    assert result.data["context_kind"] == "exception_context"
    assert [source.command for source in result.sources] == [
        "vertarget", "||", "!analyze -v", ".ecxr", "r", "kP 0n30",
    ]
    assert executor.calls[3]["retryable"] is False
    assert executor.calls[4]["retryable"] is False
    assert executor.calls[5]["retryable"] is False


def test_crash_analysis_does_not_invent_exception_context(toolset, monkeypatch):
    install_executor(
        monkeypatch,
        ("vertarget", completed(VERTARGET_USER)),
        ("||", completed(SYSTEM_USER_DUMP)),
        ("!analyze -v", completed(ANALYZE)),
        (".ecxr", completed("Unable to get exception context, NTSTATUS 0xc0000001")),
        ("r", completed(REGISTERS)),
        ("kP 0n30", completed(STACK)),
    )

    result = toolset["windbg_analyze"]("crash")

    assert result.ok is False
    assert result.data["context_kind"] == "current_context"
    assert any(error.code == "exception_context_unavailable" for error in result.errors)


@pytest.mark.parametrize(
    ("vertarget", "debug_systems", "expected_mode", "expected_session"),
    [
        (VERTARGET_USER, SYSTEM_USER_LIVE, "user", "live"),
        (VERTARGET_KERNEL, SYSTEM_KERNEL_LIVE, "kernel", "live"),
        (VERTARGET_KERNEL, SYSTEM_KERNEL_DUMP, "kernel", "dump"),
    ],
)
def test_crash_analysis_does_not_select_ecxr_outside_user_dumps(
    toolset,
    monkeypatch,
    vertarget,
    debug_systems,
    expected_mode,
    expected_session,
):
    executor = install_executor(
        monkeypatch,
        ("vertarget", completed(vertarget)),
        ("||", completed(debug_systems)),
        ("!analyze -v", completed(ANALYZE)),
        ("r", completed(REGISTERS)),
        ("kP 0n30", completed(STACK)),
    )

    result = toolset["windbg_analyze"]("crash")

    assert result.ok is True
    assert result.data["target_mode"] == expected_mode
    assert result.data["session_kind"] == expected_session
    assert result.data["context_kind"] == "current_context"
    assert [call["command"] for call in executor.calls] == [
        "vertarget", "||", "!analyze -v", "r", "kP 0n30",
    ]
    executor.assert_done()


@pytest.mark.parametrize(
    ("tool_name", "args", "kwargs"),
    [
        ("windbg_evaluate", ("@rip; g",), {}),
        ("windbg_disassemble", ("@rip\ng",), {}),
        ("windbg_lookup", ("ntdll!*; g",), {"kind": "symbol"}),
        ("windbg_read_memory", ("@rip; g",), {}),
        ("windbg_write_memory", ("@rip", "90; g"), {}),
        ("windbg_breakpoint", ("set",), {"target": "@rip; g"}),
        (
            "windbg_sympath",
            ("set",),
            {"path": "srv*C:\\symbols*https://example.invalid;.echo injected"},
        ),
        ("windbg_backtrace", (), {"frame": "0; g"}),
        ("windbg_context", ("default; g",), {}),
        ("windbg_analyze", ("crash; g",), {}),
        ("windbg_control", ("go; g",), {}),
    ],
)
def test_business_tools_reject_command_composition(
    toolset,
    monkeypatch,
    tool_name,
    args,
    kwargs,
):
    executor = install_executor(monkeypatch)

    result = toolset[tool_name](*args, **kwargs)

    assert isinstance(result, ToolEnvelope)
    assert result.ok is False
    assert result.errors
    assert executor.calls == []
