# Windbg-MCP

MCP (Model Context Protocol) server for WinDbg — AI 驱动的内核和用户态调试。

## 架构

```
MCP Client ──HTTP──► FastMCP ──► 9 个意图驱动工具 ──► CommandExecutor ──► cdb.exe (stdin/stdout)
```

- **意图驱动**: LLM 表达*想要什么*，工具判断*怎么做*。无需记忆 WinDbg 命令语法。
- **结构化输出**: 各工具返回 JSON 或 Markdown，原始文本仅作兜底。
- **兜底通道**: `windbg_exec` 保留，可执行任意 WinDbg 命令。

## 快速开始

### 环境

- Windows 10/11 x64 + Windows SDK (含 Debugging Tools) + Python 3.10+

### 安装

```bash
cd Windbg-MCP
pip install -e .
```

### 远程模式（连接已有 WinDbg 会话）

```bash
# 1. Windbg GUI 中连上目标后，中断目标，然后：
.server tcp:port=50000

# 2. 启动 MCP Server
python -m src.server --connect tcp:localhost:50000
```

### 独立模式（无需 WinDbg GUI）

```bash
python -m src.server --standalone --exe notepad.exe        # 启动程序调试
python -m src.server --standalone --pid 1234               # 附加进程
python -m src.server --standalone --dump crash.dmp         # 加载 dump
```

### MCP Client 配置

```json
{
  "mcpServers": {
    "windbg": {
      "type": "remote",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

## 工具列表（10 个）

| 工具 | 用途 | 说明 |
|---|---|---|
| `windbg_context(scope?)` | 当前状态快照 | `default`: 寄存器+指令+栈+模块+事件；`threads`: 含线程列表（用户态用 `~`，内核态 fallback 到 raw）；`processes`: 含内核进程列表；`all`: 全部。**调试时的第一个工具。** |
| `windbg_sympath(action, path?, module?)` | 符号路径管理 | `show`/`set`/`reload`/`check`。不必记忆 WinDbg 符号语法。 |
| `windbg_control(action, count?)` | 执行控制 | `go` / `step_into` / `step_over` / `step_out` |
| `windbg_backtrace(depth?, show_params?, frame?)` | 调用栈 | 解析为结构化帧列表；指定 frame 可看局部变量 |
| `windbg_read_memory(address, size?, format?)` | 读内存 | 自动格式检测，返回结构化数据 |
| `windbg_write_memory(address, values)` | 写内存 | 空格分隔的十六进制值 |
| `windbg_breakpoint(action, ...)` | 断点管理 | `set` / `list` / `clear` / `enable` / `disable` |
| `windbg_disassemble(at, count?)` | 反汇编 | 返回含符号注解的结构化指令列表 |
| `windbg_lookup(what)` | 符号/类型解析 | 自动识别地址/符号模式/类型名 |
| `windbg_analyze(scope?)` | 崩溃分析 | `crash` (完整分析+寄存器+栈) / `quick` / `hang` |
| `windbg_evaluate(expression)` | 表达式求值 | `@rcx+0x10`、`poi(@rsp+8)`、`sizeof(nt!_EPROCESS)` |
| `windbg_exec(command)` | 万能兜底 | 执行任意 WinDbg 命令 |

## CLI

```
--connect tcp:HOST:PORT  → 连接已有 WinDbg
--standalone             → 独立模式
--pid PID / --exe PATH / --dump PATH
--http-port PORT         → HTTP 端口 (默认 8080)
--debug-json             → 打印原始 JSON
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `WINDBG_MCP_HTTP_PORT` | 8080 | HTTP 端口 |
| `WINDBG_MCP_DEBUG_HOST` | 127.0.0.1 | WinDbg TCP 地址 |
| `WINDBG_MCP_DEBUG_PORT` | 50000 | WinDbg TCP 端口 |
| `WINDBG_MCP_TIMEOUT` | 30 | 命令超时(秒) |
| `WINDBG_MCP_RETRIES` | 3 | 重试次数 |
| `WINDBG_MCP_DEBUG_JSON` | — | 设为 1 开启 JSON 调试输出 |

## 开发

```bash
pip install -e ".[dev]"
pytest
```

## 许可证

MIT
