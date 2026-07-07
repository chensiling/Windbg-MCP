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

## 接入 AGENT 工具（MCP 客户端）

本服务通过 streamable HTTP 暴露标准 MCP 接口，任何支持 MCP 的 AGENT 工具（如 Codex、Claude、Cline、Continue 等）都可以接入，方式取决于各自的配置格式。核心只有一个：把 MCP 客户端指向服务的 HTTP 端点。

默认端点：

```text
http://127.0.0.1:8080/mcp
```

不同客户端的配置示例：

- Codex（`%USERPROFILE%\.codex\config.toml`）：

  ```toml
  [mcp_servers.windbg]
  url = "http://127.0.0.1:8080/mcp"
  ```

- 通用 JSON 风格客户端（`mcpServers` 字段，字段名以各工具文档为准）：

  ```json
  {
    "mcpServers": {
      "windbg": {
        "url": "http://127.0.0.1:8080/mcp"
      }
    }
  }
  ```

注意事项：

- 端口可通过 `--http-port` 或环境变量 `WINDBG_MCP_HTTP_PORT` 修改，配置中的 URL 需同步更新。
- 修改 MCP 配置后通常需要重启对应的 AGENT 工具，使其重新发现工具列表。
- 调用工具前，Windbg-MCP 服务本身必须已经启动并连接到调试目标。

## 返回格式

除 `windbg_exec` 外，所有业务工具都返回统一的 JSON envelope 字符串，字段结构一致，与具体工具无关：

```json
{
  "ok": true,
  "tool": "<工具名>",
  "command": "<实际发送给 cdb.exe 的命令，可为字符串或字符串数组>",
  "mode": "kernel | user | dump | unknown",
  "data": {},
  "raw": "",
  "errors": [],
  "next_actions": []
}
```

字段说明：

- `ok`：命令是否成功执行。解析失败但 `raw` 可用时仍可为 `true`，并在 `errors` 中记录解析警告。
- `tool`：产生该结果的工具名，便于在长上下文里追踪来源。
- `command`：实际执行的 WinDbg 命令；组合工具（如 `windbg_context`、`windbg_analyze`）可能返回命令数组。
- `mode`：调试模式，至少区分 `kernel` / `user` / `dump` / `unknown`。
- `data`：结构化主结果，不同工具字段不同——例如寄存器、调用栈帧、内存、符号、断点列表等。**优先读取这个字段。**
- `raw`：原始输出兜底。解析失败、部分失败或显式请求（如 `include_raw`）时保留。
- `errors`：结构化错误数组，形如 `{code, message, recoverable}`。
- `next_actions`：工具基于当前状态给出的推荐后续调用，形如 `{tool, args, reason}`。

只有解析失败或需要更多细节时才查看 `raw`。`next_actions` 是建议而非强制，供 LLM 参考。

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
| `windbg_context(scope?, include_raw?)` | 当前调试状态 | 调试入口工具。`scope` 支持 `default`、`threads`、`processes`、`all`。返回寄存器、当前指令、栈顶帧、最近事件、模块摘要、符号健康状态和调试模式。内核模式下 `threads` 使用 `!running -ti` 并解析为 `processors`（含每处理器 `current_thread`/`next_thread`/`idle_thread`/`stack`）；用户态使用 `~` 解析线程列表。`include_raw=false`（默认）时模块列表按 top-N 截断且不返回完整原始输出，`include_raw=true` 返回完整模块列表和原始输出。 |
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
