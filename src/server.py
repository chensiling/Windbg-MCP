import argparse
import json
import logging
import sys

from mcp.server.fastmcp import FastMCP

from .config import Config
from .tools._registry import set_executor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


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


def _parse_connect(connect_str: str, default_port: int):
    s = connect_str
    if s.startswith("tcp:"):
        s = s[4:]
    host, _, port = s.partition(":")
    return host or "127.0.0.1", int(port) if port else default_port


class _DebugExecutor:
    def __init__(self, executor):
        self._e = executor

    def execute(self, command: str) -> str:
        print("=== REQUEST ===", flush=True)
        print(json.dumps({"command": command}, indent=2), flush=True)
        result = self._e.execute(command)
        print("=== RESPONSE ===", flush=True)
        print(json.dumps({"output": result[:2000]}, indent=2), flush=True)
        return result


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

    mcp = FastMCP("windbg-mcp", host="127.0.0.1", port=config.http_port)

    from .tools.exec_tool import register_exec_tool
    from .tools.control_tools import register_control_tools
    from .tools.breakpoint_tools import register_breakpoint_tools
    from .tools.memory_tools import register_memory_tools
    from .tools.register_tools import register_register_tools
    from .tools.disasm_tools import register_disasm_tools
    from .tools.stack_tools import register_stack_tools
    from .tools.symbol_tools import register_symbol_tools
    from .tools.analyze_tools import register_analyze_tools
    from .tools.kernel_tools import register_kernel_tools
    from .tools.type_tools import register_type_tools

    for reg in [
        register_exec_tool, register_control_tools, register_breakpoint_tools,
        register_memory_tools, register_register_tools, register_disasm_tools,
        register_stack_tools, register_symbol_tools, register_analyze_tools,
        register_kernel_tools, register_type_tools,
    ]:
        reg(mcp)

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
