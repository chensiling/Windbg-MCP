# Windbg-MCP

面向 WinDbg 目标的 MCP（Model Context Protocol）服务器，通过 `cdb.exe` 子进程与调试器通信，并以 streamable HTTP 方式向 LLM 暴露调试工具。

## 架构

```text
MCP Client -> FastMCP -> 意图工具 -> CommandExecutor -> SubprocessEngine -> cdb.exe
                               |              |
                               v              v
                          ParseResult    ExecutionResult
                               \              /
                                v            v
                         ToolEnvelope structuredContent
```

- **意图驱动**：LLM 只需要表达调试意图，例如获取上下文、查看调用栈、解析符号或分析崩溃；工具负责选择实际 WinDbg 命令。
- **结构化输出**：11 个业务工具直接返回带字段级 MCP schema 的 `ToolEnvelope`；`windbg_exec` 保留原始文本通道。
- **证据优先**：执行、解析和变更验证分别报告状态；每条实际命令及其原始输出保留在 `sources`。
- **解析失败兜底**：解析器遇到未知 WinDbg 输出格式时不会抛异常，会把原始文本放入 `raw` 字段。
- **Windows 专用**：依赖 Windows SDK 中的 Debugging Tools。

## 快速开始

### 环境要求

- Windows 10/11 x64
- Windows SDK，需包含 Debugging Tools
- Python 3.10+
- 支持的依赖约束：MCP Python SDK 1.28+ 与 Pydantic 2.12+（均限制在下一个主版本之前）

本次合同验证实际运行 MCP 1.28.0 与 Pydantic 2.13.4。Pydantic 2.12+ 是支持约束；没有单独在精确的 2.12.0 边界版本运行测试。

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

除 `windbg_exec` 外，所有业务工具都在 MCP `structuredContent` 中直接返回统一的 `ToolEnvelope` 对象，而不是 JSON 编码字符串：

```json
{
  "ok": true,
  "tool": "<工具名>",
  "execution_status": "completed",
  "parse_status": "complete",
  "verification_status": "verified | not_required",
  "data": {},
  "inferences": [],
  "sources": [
    {
      "command": "<实际 WinDbg 命令>",
      "execution_status": "completed",
      "parse_status": "complete | not_run",
      "complete": true,
      "raw": "<该命令的原始输出>"
    }
  ],
  "errors": [],
  "next_actions": [],
  "raw": ""
}
```

字段说明：

- `ok`：只有本次调用要求的执行、解析和验证阶段全部成功且没有错误时才为 `true`。
- `tool`：产生该结果的工具名，便于在长上下文里追踪来源。
- `execution_status`：`completed`、`timeout`、`disconnected`、`failed`、`indeterminate` 或 `not_run`。
- `parse_status`：`complete`、`partial`、`failed` 或 `not_run`。部分输出不会被伪装成完整结果。
- `verification_status`：变更后置条件的 `verified`、`failed`、`indeterminate`、`not_required` 或 `not_run`。
- `data`：结构化主结果，不同工具字段不同——例如寄存器、调用栈帧、内存、符号、断点列表等。**优先读取这个字段。**
- `inferences`：规则推导结果，带 `basis` 和 `certainty="inferred"`；它们不是直接观测事实。
- `sources`：权威的逐命令证据，保留命令、完成状态、解析状态、原始输出、重试次数和异步输出。
- `errors`：带 `stage` 和 `recoverable` 的结构化错误。
- `next_actions`：工具基于当前状态给出的推荐后续调用，形如 `{tool, args, reason}`。
- `raw`：单命令兼容字段；组合工具应始终以 `sources` 为准。

`inferences` 和 `next_actions` 都不是强制步骤，服务器不会自动执行建议。`windbg_exec` 不返回 `ToolEnvelope` 或 output schema，只返回原始文本内容。

### 地址与进制

地址输入始终是字符串，可以是寄存器、符号、指针解引用或算术表达式。工具先通过 WinDbg 求值，并同时返回原始 `input` 和规范化的 `resolved_address`。跨 MCP/JSON 边界的地址使用 `0x` 十六进制字符串，不使用可能丢失精度的 JSON 数字。

命令中的数量使用显式 `0n` 十进制，地址和字节使用显式 `0x` 十六进制；复合地址表达式中的裸数字也会规范化，结果不依赖当前 `.radix`。

## 推荐 LLM 调用流程

```text
1. windbg_context()
2. 如果是崩溃或 dump：windbg_analyze("quick" 或 "crash")
3. 如果调用链是关键线索：windbg_backtrace("30")
4. 如果当前指令是关键线索：windbg_disassemble("@rip", "8")
5. 如果需要解析符号、类型或地址：windbg_lookup(...)
6. 如果需要验证指针或内存：windbg_evaluate(...) + windbg_read_memory(...)
7. 只有意图工具覆盖不了时，才使用 windbg_exec(...)
```

多数检查命令要求目标已经 break in。除非明确需要改变目标状态，否则不要默认调用执行控制、写内存或设置/清除断点类工具。

## 安全与访问边界

- 读取工具不会自动重放状态变更；超时不等于成功的空响应。
- 写内存、断点、符号路径和执行控制工具在变更后查询后置条件，证据不足时返回 `failed` 或 `indeterminate`，不会声称 `verified`。
- `windbg_control` 可能恢复任意目标代码；`windbg_sympath` 可能替换配置并访问 HTTP 符号服务器；两者标注为 open-world。
- `windbg_exec` 是唯一允许任意 WinDbg 命令的通道，标注为 destructive、non-idempotent、open-world。它可能写内存、改变断点或恢复执行。
- 服务默认仅绑定 `127.0.0.1`，当前**没有认证实现**，也不支持 `WINDBG_MCP_TOKEN`。不要直接暴露到不可信网络；远程使用时应增加经过验证的认证代理或其他访问控制层。
- `--debug-json` 会记录调试器命令和目标数据，应按敏感信息处理。

## 工具列表

当前暴露 12 个 MCP 工具：11 个业务工具 + 1 个原始命令兜底工具。

| 工具 | 用途 | 说明 |
|---|---|---|
| `windbg_context(scope?, include_raw?)` | 当前调试状态 | 区分 `target_mode`（user/kernel）和 `session_kind`（live/dump），按模式路由线程/进程查询；`include_raw` 控制模块列表是否截断，逐命令原始证据始终在 `sources`。 |
| `windbg_analyze(scope?)` | 崩溃/挂起分析 | `scope` 支持 `quick`、`crash`、`hang`；仅 user dump 在验证 `.ecxr` 后归因异常上下文。 |
| `windbg_backtrace(depth?, show_params?, frame?)` | 调用栈 | 解析 `kP`/`k`；指定 `frame` 时先验证实际选中帧，再读取并归因局部变量。 |
| `windbg_disassemble(at, count?)` | 反汇编 | 解析 `u` 输出和符号标签。`count` 支持十进制、`0x` 十六进制和 `10h` 形式。 |
| `windbg_evaluate(expression)` | 表达式求值 | 解析 `? expression` 输出，返回十进制和十六进制结果。 |
| `windbg_lookup(what, kind?)` | 符号/类型/地址解析 | `kind` 可显式选择 `address`、`symbol` 或 `type`；`auto` 路由会作为 inference 返回。 |
| `windbg_read_memory(address, size?, format?)` | 读取内存 | `format` 支持 `auto`、`byte`、`word`、`dword`、`qword`、`ascii`。`size` 是所选 `format` 的元素数量，不是字节数；例如 `size="4", format="qword"` 读取 4 个 qword（共 32 字节）。 |
| `windbg_write_memory(address, values)` | 写入字节 | 使用 `eb` 写入，并将读回地址、连续范围和字节全部绑定后才报告 verified。 |
| `windbg_breakpoint(action, ...)` | 断点管理 | `action` 支持 `set`、`list`、`clear`、`enable`、`disable`；所有变更通过 `bl` 前后状态验证。 |
| `windbg_control(action, count?)` | 执行控制 | `action` 支持 `go`、`step_into`、`step_over`、`step_out`。会改变目标运行状态。 |
| `windbg_sympath(action, path?, module?)` | 符号路径管理 | `action` 支持 `show`、`set`、`reload`、`check`；set/reload 必须查询实际路径或模块符号状态。 |
| `windbg_exec(command)` | 原始 WinDbg 命令 | 唯一的 open-world 原始兜底通道；无 output schema，直接返回文本，可能产生任意副作用。 |

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

没有 token 环境变量。HTTP 端点仅依赖 loopback 绑定，不提供认证保证。

## 测试

```powershell
python -m pytest tests/ -v
```

解析器测试使用真实 cdb/kd 输出样例。修改解析器时应保留并更新测试。

## 许可证

MIT
