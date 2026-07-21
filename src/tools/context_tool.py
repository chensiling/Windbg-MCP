"""Aggregate debugger context with per-command evidence."""

from typing import Literal

from ._annotations import READ_ONLY_TOOL
from ._evidence import run_read
from ._models import ToolEnvelope
from ._parser import (
    parse_modules,
    parse_process_list,
    parse_registers,
    parse_stack_kp,
    parse_target_info,
    parse_thread_list_kernel,
    parse_thread_list_user,
)
from ._response import (
    error_item,
    inference_item,
    limitation_item,
    make_response,
    next_action,
    parse_int_arg,
)
from .sympath_tool import _symbol_health


ContextScope = Literal["default", "threads", "processes", "all"]


def _target_info(*raw_values: str) -> dict[str, object]:
    parsed = parse_target_info("\n".join(raw_values))
    if parsed.status == "failed":
        return {
            "target_mode": "unknown",
            "session_kind": "unknown",
            "capabilities": {},
        }
    return dict(parsed.data)


def _target_mode(*raw_values: str) -> str:
    return str(_target_info(*raw_values)["target_mode"])


def _session_kind(*raw_values: str) -> str:
    return str(_target_info(*raw_values)["session_kind"])


def register_context_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_context(
        scope: ContextScope = "default",
        include_modules: bool = False,
        module_limit: str = "20",
        list_limit: str = "50",
        include_raw: bool = False,
    ) -> ToolEnvelope:
        """Collect target, register, stack, event, module, and optional routing context."""

        normalized_scope = scope.lower().strip()
        if normalized_scope not in ("default", "threads", "processes", "all"):
            return make_response(
                "windbg_context",
                errors=[error_item("invalid_argument", "Unknown context scope.")],
            )
        module_limit_value, module_limit_error = parse_int_arg(
            module_limit,
            "module_limit",
            default=20,
            min_value=1,
            max_value=500,
        )
        list_limit_value, list_limit_error = parse_int_arg(
            list_limit,
            "list_limit",
            default=50,
            min_value=1,
            max_value=500,
        )
        if module_limit_error or list_limit_error:
            return make_response(
                "windbg_context",
                errors=[
                    error for error in (module_limit_error, list_limit_error)
                    if error is not None
                ],
            )

        target = run_read("vertarget", include_raw=include_raw)
        debug_systems = run_read("||", include_raw=include_raw)
        registers = run_read("r", parse_registers, include_raw=include_raw)
        stack = run_read("kP 0n1", parse_stack_kp, include_raw=include_raw)
        event = run_read(".lastevent", include_raw=include_raw)
        sources = [
            target.source,
            debug_systems.source,
            registers.source,
            stack.source,
            event.source,
        ]

        target_info = _target_info(
            target.execution.output,
            debug_systems.execution.output,
        )
        target_mode = str(target_info["target_mode"])
        session_kind = str(target_info["session_kind"])
        data: dict[str, object] = {
            "debugger_connected": target.execution.status == "completed",
            "target_mode": target_mode,
            "session_kind": session_kind,
            "capabilities": target_info["capabilities"],
            "target_state": "unknown",
            "target": target.execution.output.strip(),
            "last_event": event.execution.output.strip(),
        }
        actions = []
        errors = []
        inferences = []
        limitations = []

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

        data["modules_included"] = include_modules
        if include_modules:
            modules_evidence = run_read(
                "lm",
                parse_modules,
                include_raw=include_raw,
            )
            sources.append(modules_evidence.source)
            modules = []
            if modules_evidence.parsed is not None:
                modules = list(modules_evidence.parsed.data.get("modules", []))
            data["module_count"] = len(modules)
            data["modules"] = modules[:module_limit_value]
            if len(modules) > module_limit_value:
                data["modules_truncated"] = True
                limitations.append(limitation_item(
                    "output_truncated",
                    f"Returned {module_limit_value} of {len(modules)} modules.",
                    path="data.modules",
                ))
            inferences.append(inference_item(
                "symbol_health",
                _symbol_health(modules),
                "derived from module symbol-state text; deferred is not missing",
            ))

        if normalized_scope in ("threads", "all"):
            if target_mode == "kernel":
                thread_evidence = run_read(
                    "!running -ti",
                    parse_thread_list_kernel,
                    include_raw=include_raw,
                )
                route = "kernel_running"
                if thread_evidence.parsed is not None:
                    data.update(dict(thread_evidence.parsed.data))
            elif target_mode == "user":
                thread_evidence = run_read(
                    "~",
                    parse_thread_list_user,
                    include_raw=include_raw,
                )
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
                key = "processors" if target_mode == "kernel" else "threads"
                records = data.get(key)
                if isinstance(records, list):
                    data[f"{key}_count"] = len(records)
                    if len(records) > list_limit_value:
                        data[key] = records[:list_limit_value]
                        data[f"{key}_truncated"] = True
                        limitations.append(limitation_item(
                            "output_truncated",
                            f"Returned {list_limit_value} of {len(records)} {key}.",
                            path=f"data.{key}",
                        ))
            inferences.append(inference_item(
                "thread_routing",
                route,
                f"selected from target_mode={target_mode}",
            ))

        if normalized_scope in ("processes", "all"):
            if target_mode == "kernel":
                processes = run_read(
                    "!process 0x0 0x0",
                    parse_process_list,
                    include_raw=include_raw,
                )
                sources.append(processes.source)
                if processes.parsed is not None:
                    data.update(dict(processes.parsed.data))
                    records = data.get("processes")
                    if isinstance(records, list):
                        data["process_count"] = len(records)
                        if len(records) > list_limit_value:
                            data["processes"] = records[:list_limit_value]
                            data["processes_truncated"] = True
                            limitations.append(limitation_item(
                                "output_truncated",
                                (
                                    f"Returned {list_limit_value} of "
                                    f"{len(records)} processes."
                                ),
                                path="data.processes",
                            ))
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
            limitations=limitations,
            next_actions=actions,
        )
