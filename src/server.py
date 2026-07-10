import argparse
from dataclasses import asdict
import json
import logging
import sys

from mcp.server.fastmcp import FastMCP

from .config import Config
from .debugger.engine import ExecutionContractError, ExecutionResult
from .tools._registry import set_executor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SERVER_INSTRUCTIONS = (
    "Use the typed windbg_* business tools whenever they can express the "
    "debugging intent. Treat execution_status, parse_status, and "
    "verification_status as independent stages; ok is true only when every "
    "required stage succeeds. sources are the authoritative per-command "
    "evidence, while raw is only a compatibility field. data contains "
    "observations. inferences are explicitly inferred, and next_actions are "
    "optional suggestions that must not be executed automatically. "
    "windbg_exec is a raw, open-world escape hatch that can execute "
    "destructive WinDbg commands; use it only when no business tool covers "
    "the required operation."
)


def _build_parser():
    p = argparse.ArgumentParser(prog="windbg-mcp", description="Windbg-MCP Server")
    p.add_argument("--connect", type=str, default=None,
                   help="Connect to existing Windbg: tcp:HOST:PORT or tcp:PORT")
    p.add_argument("--standalone", action="store_true",
                   help="Start standalone debugging session (no Windbg GUI)")
    p.add_argument("--pid", type=str, default=None,
                   help="Process ID to attach (standalone)")
    p.add_argument("--exe", type=str, default=None,
                   help="Executable to launch (standalone)")
    p.add_argument("--dump", type=str, default=None,
                   help="Dump file to load (standalone)")
    p.add_argument("--args", type=str, default="",
                   help="Arguments for --exe (standalone)")
    p.add_argument("--http-port", type=int, default=None,
                   help="HTTP server port (default: 8080)")
    p.add_argument("--debug-json", action="store_true", default=None,
                   help="Log raw request/response JSON")
    return p


def _parse_connect(connect_str: str, default_port: int) -> tuple[str, int]:
    s = connect_str.strip()
    if s.lower().startswith("tcp:"):
        s = s[4:]

    if not s:
        raise ValueError("connect string must include a host or port")

    if ":" not in s:
        if s.isdecimal():
            host, port = "127.0.0.1", int(s)
        else:
            host, port = s, default_port
    else:
        host_text, port_text = s.rsplit(":", 1)
        host = host_text or "127.0.0.1"
        port = int(port_text) if port_text else default_port

    if not 1 <= port <= 65535:
        raise ValueError("connect port must be between 1 and 65535")
    return host, port


class _DebugExecutor:
    def __init__(self, executor):
        self._e = executor

    def execute(
        self,
        command: str,
        *,
        read_only: bool = False,
        retryable: bool = False,
    ) -> ExecutionResult:
        print("=== REQUEST ===", flush=True)
        print(
            json.dumps(
                {
                    "command": command,
                    "read_only": read_only,
                    "retryable": retryable,
                },
                indent=2,
            ),
            flush=True,
        )
        result = self._e.execute(
            command,
            read_only=read_only,
            retryable=retryable,
        )
        if not isinstance(result, ExecutionResult):
            raise ExecutionContractError("wrapped executor must return ExecutionResult")
        try:
            result.validate()
        except (TypeError, ValueError) as e:
            raise ExecutionContractError(
                "wrapped executor returned an invalid ExecutionResult"
            ) from e
        response = asdict(result)
        response["output"] = result.output[:2000]
        response["async_output"] = result.async_output[:2000]
        print("=== RESPONSE ===", flush=True)
        print(json.dumps(response, indent=2), flush=True)
        return result


def create_mcp_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> FastMCP:
    """Create the configured FastMCP surface without starting a transport."""
    mcp = FastMCP(
        "windbg-mcp",
        instructions=SERVER_INSTRUCTIONS,
        host=host,
        port=port,
    )

    from .tools.exec_tool import register_exec_tool
    from .tools.control_tool import register_control_tool
    from .tools.breakpoint_tool import register_breakpoint_tool
    from .tools.memory_tool import register_memory_tool
    from .tools.disasm_tool import register_disasm_tool
    from .tools.stack_tool import register_stack_tool
    from .tools.lookup_tool import register_lookup_tool
    from .tools.analyze_tool import register_analyze_tool
    from .tools.eval_tool import register_eval_tool
    from .tools.context_tool import register_context_tool
    from .tools.sympath_tool import register_sympath_tool

    for register in (
        register_exec_tool,
        register_control_tool,
        register_breakpoint_tool,
        register_memory_tool,
        register_disasm_tool,
        register_stack_tool,
        register_lookup_tool,
        register_analyze_tool,
        register_eval_tool,
        register_context_tool,
        register_sympath_tool,
    ):
        register(mcp)
    return mcp


def main():
    parser = _build_parser()
    args = parser.parse_args()

    config = Config.from_env()
    config.apply_cli(
        http_port=args.http_port,
        debug_json=args.debug_json,
    )

    host, port = config.connect_host, config.connect_port
    if args.connect:
        host, port = _parse_connect(args.connect, config.connect_port)

    if args.standalone:
        from .debugger.native_engine import SubprocessEngine
        engine = SubprocessEngine(
            pid=int(args.pid) if args.pid else None,
            exe=args.exe or None,
            dump=args.dump or None,
            cmd_args=args.args or "",
        )
    else:
        from .debugger.native_engine import SubprocessEngine
        engine = SubprocessEngine(remote_host=host, remote_port=port)

    from .debugger.executor import CommandExecutor
    executor_base = CommandExecutor(engine, timeout=config.command_timeout, max_retries=config.max_retries)
    executor = _DebugExecutor(executor_base) if config.debug_json else executor_base
    set_executor(executor)

    mcp = create_mcp_server(port=config.http_port)

    try:
        engine.connect()
        logger.info("connected to debug target")
    except Exception as e:
        logger.warning("could not connect to debug target: %s", e)
        logger.warning("MCP server will start; tools will fail until connection is restored")

    logger.info("starting MCP server on http://127.0.0.1:%d", config.http_port)
    try:
        mcp.run(transport="streamable-http")
    except (KeyboardInterrupt, SystemExit):
        logger.info("server stopped")
    finally:
        engine.disconnect()


if __name__ == "__main__":
    main()
