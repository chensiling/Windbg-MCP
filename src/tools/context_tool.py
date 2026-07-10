"""Aggregate debugger context with per-command evidence."""

import re
from typing import Literal

from ._annotations import READ_ONLY_TOOL
from ._evidence import run_read
from ._models import ToolEnvelope
from ._parser import (
    parse_modules,
    parse_process_list,
    parse_registers,
    parse_stack_kp,
    parse_thread_list_kernel,
    parse_thread_list_user,
)
from ._response import (
    error_item,
    inference_item,
    make_response,
    next_action,
)
from .sympath_tool import _symbol_health


_MODULE_LIMIT = 60
ContextScope = Literal["default", "threads", "processes", "all"]


_KERNEL_SYSTEM = re.compile(
    r"(?im)^\s*[.#]\s+\d+\s+[^:\r\n]*\bkernel\b[^:\r\n]*(?:mode|dump)\s*:"
)
_USER_SYSTEM = re.compile(
    r"(?im)^\s*[.#]\s+\d+\s+[^:\r\n]*\buser\b[^:\r\n]*(?:mode|dump)\s*:"
)
_KERNEL_PROMPT = re.compile(r"(?im)^\s*(?:\d+:\s*)?kd>\s*")
_USER_PROMPT = re.compile(
    r"(?im)^\s*\d+:[0-9a-f]+(?::(?:x86|amd64|arm|arm64))?>\s*"
)
_SYSTEM_DUMP = re.compile(
    r"(?im)^\s*[.#]\s+\d+\s+[^:\r\n]*\bdump\b[^:\r\n]*:"
)
_SYSTEM_LIVE = re.compile(
    r"(?im)^\s*[.#]\s+\d+\s+live\b[^\r\n]*:"
)


def _target_mode(*raw_values: str) -> str:
    text = "\n".join(raw_values)
    if _KERNEL_SYSTEM.search(text):
        return "kernel"
    if _USER_SYSTEM.search(text):
        return "user"
    if (
        _KERNEL_PROMPT.search(text)
        or re.search(r"(?im)^\s*kernel base\s*=", text)
        or re.search(r"(?im)^\s*psloadedmodulelist\s*=", text)
    ):
        return "kernel"
    if (
        _USER_PROMPT.search(text)
        or re.search(r"(?im)^\s*process uptime\s*:", text)
        or re.search(r"(?i)\buser mode (?:target|dump)\b", text)
    ):
        return "user"
    return "unknown"


def _session_kind(*raw_values: str) -> str:
    text = "\n".join(raw_values)
    if _SYSTEM_DUMP.search(text) or re.search(
        r"(?i)\b(?:dump file|dump target|mini dump|memory dump)\b",
        text,
    ):
        return "dump"
    if _SYSTEM_LIVE.search(text) or re.search(
        r"(?i)\blive\s+(?:user|kernel)\s+mode\b",
        text,
    ):
        return "live"
    return "unknown"


def register_context_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_context(
        scope: ContextScope = "default",
        include_raw: bool = False,
    ) -> ToolEnvelope:
        """Collect target, register, stack, event, module, and optional routing context."""

        normalized_scope = scope.lower().strip()
        if normalized_scope not in ("default", "threads", "processes", "all"):
            return make_response(
                "windbg_context",
                errors=[error_item("invalid_argument", "Unknown context scope.")],
            )

        target = run_read("vertarget")
        debug_systems = run_read("||")
        registers = run_read("r", parse_registers)
        stack = run_read("kP 0n1", parse_stack_kp)
        event = run_read(".lastevent")
        modules_evidence = run_read("lm", parse_modules)
        sources = [
            target.source,
            debug_systems.source,
            registers.source,
            stack.source,
            event.source,
            modules_evidence.source,
        ]

        target_mode = _target_mode(
            target.execution.output,
            debug_systems.execution.output,
        )
        session_kind = _session_kind(
            target.execution.output,
            debug_systems.execution.output,
        )
        data: dict[str, object] = {
            "debugger_connected": target.execution.status == "completed",
            "target_mode": target_mode,
            "session_kind": session_kind,
            "target_state": "unknown",
            "target": target.execution.output.strip(),
            "last_event": event.execution.output.strip(),
        }
        actions = []
        errors = []
        inferences = []

        if registers.parsed is not None:
            register_data = dict(registers.parsed.data)
            data.update(register_data)
            if register_data.get("registers"):
                data["target_state"] = "broken"
                actions.append(next_action(
                    "windbg_disassemble",
                    {"at": "@rip", "count": "8"},
                    "Inspect instructions near the current instruction.",
                ))
        if stack.parsed is not None and stack.parsed.data.get("frames"):
            data["stack_frame"] = stack.parsed.data["frames"][0]
            actions.append(next_action(
                "windbg_backtrace",
                {"depth": "30"},
                "Collect a deeper call stack.",
            ))

        modules = []
        if modules_evidence.parsed is not None:
            modules = list(modules_evidence.parsed.data.get("modules", []))
        data["module_count"] = len(modules)
        if include_raw or len(modules) <= _MODULE_LIMIT:
            data["modules"] = modules
        else:
            data["modules"] = modules[:_MODULE_LIMIT]
            data["modules_truncated"] = True
        inferences.append(inference_item(
            "symbol_health",
            _symbol_health(modules),
            "derived from module symbol-state text; deferred is not missing",
        ))

        if normalized_scope in ("threads", "all"):
            if target_mode == "kernel":
                thread_evidence = run_read("!running -ti", parse_thread_list_kernel)
                route = "kernel_running"
                if thread_evidence.parsed is not None:
                    data.update(dict(thread_evidence.parsed.data))
            elif target_mode == "user":
                thread_evidence = run_read("~", parse_thread_list_user)
                route = "user_threads"
                if thread_evidence.parsed is not None:
                    data.update(dict(thread_evidence.parsed.data))
            else:
                thread_evidence = None
                route = "not_run"
                errors.append(error_item(
                    "routing_unknown",
                    "Thread collection was not routed because target_mode is unknown.",
                    stage="parsing",
                ))
            if thread_evidence is not None:
                sources.append(thread_evidence.source)
            inferences.append(inference_item(
                "thread_routing",
                route,
                f"selected from target_mode={target_mode}",
            ))

        if normalized_scope in ("processes", "all"):
            if target_mode == "kernel":
                processes = run_read("!process 0x0 0x0", parse_process_list)
                sources.append(processes.source)
                if processes.parsed is not None:
                    data.update(dict(processes.parsed.data))
            else:
                errors.append(error_item(
                    "kernel_command_not_routed",
                    "Process enumeration requires target_mode=kernel.",
                    stage="parsing",
                ))

        if data["target_state"] != "broken":
            actions.append(next_action(
                "windbg_context",
                {"scope": "default"},
                "Refresh context after the target breaks.",
            ))
        return make_response(
            "windbg_context",
            sources,
            data,
            inferences=inferences,
            errors=errors,
            next_actions=actions,
        )
