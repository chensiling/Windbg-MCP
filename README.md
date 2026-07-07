# Windbg-MCP

面向 WinDbg 目标的 MCP（Model Context Protocol）服务器，通过 `cdb.exe` 子进程与调试器通信，并以 streamable HTTP 方式向 LLM 暴露调试工具。

## 架构

```text
MCP Client -> FastMCP streamable HTTP -> 11 个意图工具 + windbg_exec -> CommandExecutor -> cdb.exe 子进程
```

- **意图驱动**：LLM 只需要表达调试意图，例如获取上下文、查看调用栈、解析符号或分析崩溃；工具负责选择实际 WinDbg 命令。
- **结构化输出**：除 `windbg_exec` 外，所有业务工具都返回统一 JSON 包装结构。
- **解析失败兜底**：解析器遇到未知 WinDbg 输出格式时不会抛异常，会把原始文本放入 `raw` 字段。
- **Windows 专用**：依赖 Windows SDK 中的 Debugging Tools。

## 快速开始

### 环境要求

- Windows 10/11 x64
- Windows SDK，需包含 Debugging Tools
- Python 3.10+

### 安装

```powershell
cd Windbg-MCP
pip install -e .
```

开发和测试依赖：

```powershell
pip install -e ".[dev]"
python -m pytest tests/ -v
```

### 远程模式

适用于已经打开 WinDbg GUI 并连接目标的场景。

```text
# 在 WinDbg 中连接目标并 break in 后执行：
.server tcp:port=50000
```

然后启动 MCP Server：

```powershell
python -m src.server --connect tcp:localhost:50000
```

### 独立模式

```powershell
python -m src.server --standalone --exe notepad.exe
python -m src.server --standalone --pid 1234
python -m src.server --standalone --dump crash.dmp
```

默认 MCP HTTP 地址：

```text
http://127.0.0.1:8080/mcp
```

## Codex MCP 配置

在全局 Codex 配置 `%USERPROFILE%\.codex\config.toml` 中加入：

```toml
[mcp_servers.windbg]
url = "http://127.0.0.1:8080/mcp"
```

修改 MCP 配置后需要重启 Codex。调用工具前，Windbg-MCP 服务本身也必须已经启动。

## 返回格式

除 `windbg_exec` 外，所有业务工具都会返回 JSON 字符串，格式如下：

```json
{
  "ok": true,
  "tool": "windbg_context",
  "command": "r",
  "mode": "kernel",
  "data": {},
  "raw": "",
  "errors": [],
  "next_actions": []
}
```

使用时优先读取 `data`。只有解析失败或需要更多细节时，再查看 `raw`。`next_actions` 是工具根据当前状态给出的建议后续调用。

## 推荐 LLM 调用流程

```text
1. windbg_context()
2. 如果是崩溃或 dump：windbg_analyze("quick" 或 "crash")
3. 如果调用链是关键线索：windbg_backtrace(30)
4. 如果当前指令是关键线索：windbg_disassemble("@rip", 8)
5. 如果需要解析符号、类型或地址：windbg_lookup(...)
6. 如果需要验证指针或内存：windbg_evaluate(...) + windbg_read_memory(...)
7. 只有意图工具覆盖不了时，才使用 windbg_exec(...)
```

多数检查命令要求目标已经 break in。除非明确需要改变目标状态，否则不要默认调用执行控制、写内存或设置/清除断点类工具。

## 工具列表

当前暴露 12 个 MCP 工具：11 个业务工具 + 1 个原始命令兜底工具。

| 工具 | 用途 | 说明 |
|---|---|---|
| `windbg_context(scope?)` | 当前调试状态 | 调试入口工具。`scope` 支持 `default`、`threads`、`processes`、`all`。返回寄存器、当前指令、栈顶帧、最近事件、模块、符号健康状态和调试模式。内核模式下 `threads` 使用 `!running -ti`，目前返回 `threads_raw`。 |
| `windbg_analyze(scope?)` | 崩溃/挂起分析 | `scope` 支持 `quick`、`crash`、`hang`。`crash` 会额外收集寄存器和调用栈。 |
| `windbg_backtrace(depth?, show_params?, frame?)` | 调用栈 | 解析 `kP`/`k` 输出，支持带帧号的内核调用栈。 |
| `windbg_disassemble(at, count?)` | 反汇编 | 解析 `u` 输出和符号标签。`count` 支持十进制、`0x` 十六进制和 `10h` 形式。 |
| `windbg_evaluate(expression)` | 表达式求值 | 解析 `? expression` 输出，返回十进制和十六进制结果。 |
| `windbg_lookup(what)` | 符号/类型/地址解析 | 根据输入自动选择 `ln`、`x` 或 `dt`。 |
| `windbg_read_memory(address, size?, format?)` | 读取内存 | `format` 支持 `auto`、`byte`、`word`、`dword`、`qword`、`ascii`。 |
| `windbg_write_memory(address, values)` | 写入字节 | 使用 `eb address values`。会改变目标内存，必须谨慎使用。 |
| `windbg_breakpoint(action, ...)` | 断点管理 | `action` 支持 `set`、`list`、`clear`、`enable`、`disable`。无断点时 `list` 返回 `breakpoints: []`。 |
| `windbg_control(action, count?)` | 执行控制 | `action` 支持 `go`、`step_into`、`step_over`、`step_out`。会改变目标运行状态。 |
| `windbg_sympath(action, path?, module?)` | 符号路径管理 | `action` 支持 `show`、`set`、`reload`、`check`。`check` 会返回符号健康状态。 |
| `windbg_exec(command)` | 原始 WinDbg 命令 | 万能兜底通道，直接透传 WinDbg 命令，返回值不包 JSON 包装结构。 |

## CLI

```text
--connect tcp:HOST:PORT  连接已有 WinDbg remote server
--standalone             启动独立调试会话
--pid PID                独立模式下附加进程
--exe PATH               独立模式下启动可执行文件
--dump PATH              独立模式下加载 dump
--args ARGS              传给 --exe 的参数
--http-port PORT         HTTP 端口，默认 8080
--debug-json             打印请求/响应 JSON 片段
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---:|---|
| `WINDBG_MCP_HTTP_PORT` | `8080` | HTTP 服务端口 |
| `WINDBG_MCP_DEBUG_HOST` | `127.0.0.1` | WinDbg remote host |
| `WINDBG_MCP_DEBUG_PORT` | `50000` | WinDbg remote port |
| `WINDBG_MCP_TIMEOUT` | `30` | 命令超时时间，单位秒 |
| `WINDBG_MCP_RETRIES` | `3` | 命令自动重试次数 |
| `WINDBG_MCP_DEBUG_JSON` | 未设置 | 设为 `1`、`true` 或 `yes` 时启用 JSON 调试日志 |

## 测试

```powershell
python -m pytest tests/ -v
```

解析器测试使用真实 cdb/kd 输出样例。修改解析器时应保留并更新测试。

## 许可证

MIT
