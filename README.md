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
- **结构化输出**：19 个业务工具直接返回带字段级 MCP schema 的 `ToolEnvelope`；`windbg_exec` 保留原始文本通道。
- **证据优先**：执行、核心结果、解析和变更验证分别报告状态；每条命令都有独立 `command_id`。
- **渐进式证据**：默认响应不内联大段原始输出；使用 `windbg_output` 按 `command_id` 分页读取短期内存缓存。
- **解析失败兜底**：解析器遇到未知格式时不会抛异常；已解析事实继续可用，未知文本可通过原始证据读取。
- **会话隔离**：超时命令在旧 marker 排空前不会接受新命令，避免残留输出污染后续结果。
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
  "schema_version": "2.0",
  "ok": true,
  "tool": "<工具名>",
  "execution_status": "completed",
  "core_result_status": "usable",
  "parse_status": "complete | partial",
  "verification_status": "verified | not_required",
  "data": {},
  "inferences": [],
  "sources": [
    {
      "command_id": "<命令 ID>",
      "command": "<实际 WinDbg 命令>",
      "execution_status": "completed",
      "parse_status": "complete | not_run",
      "complete": true,
      "session_state": "idle",
      "raw_size": 1234,
      "raw_included": false,
      "raw": ""
    }
  ],
  "errors": [],
  "warnings": [],
  "limitations": [],
  "next_actions": [],
  "raw": ""
}
```

字段说明：

- `ok`：执行完成、核心结果为 `usable`/`empty`、验证满足要求且没有致命错误时为 `true`；非关键文本未解析可以同时出现 `ok=true` 与 `parse_status=partial`。
- `schema_version`：当前 envelope 合同版本，现为 `2.0`。
- `tool`：产生该结果的工具名，便于在长上下文里追踪来源。
- `execution_status`：`completed`、`cancelled`、`busy`、`timeout`、`disconnected`、`failed`、`indeterminate` 或 `not_run`。
- `core_result_status`：`usable`、`empty`、`unavailable` 或 `not_run`，独立表达核心结果是否可消费。
- `parse_status`：`complete`、`partial`、`failed` 或 `not_run`。部分输出不会被伪装成完整结果。
- `verification_status`：变更后置条件的 `verified`、`failed`、`indeterminate`、`not_required` 或 `not_run`。
- `data`：结构化主结果，不同工具字段不同——例如寄存器、调用栈帧、内存、符号、断点列表等。**优先读取这个字段。**
- `inferences`：规则推导结果，带 `basis` 和 `certainty="inferred"`；它们不是直接观测事实。
- `sources`：逐命令来源、完成边界、会话/取消状态、重试次数、`command_id` 和原始输出大小；默认不内联 raw。
- `errors`：带 `stage` 和 `recoverable` 的结构化错误。
- `warnings`：非致命诊断，例如核心字段可用但附加文本解析不完整。
- `limitations`：Dump 缺页、目标能力限制和字段级截断等客观限制。
- `next_actions`：工具基于当前状态给出的推荐后续调用，形如 `{tool, args, reason}`。
- `raw`：兼容字段，v2 默认留空；使用 `windbg_output(command_id, offset, limit)` 获取原始证据。

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
7. 如果响应提示缺页/映射问题：windbg_memory_mapping(...)、windbg_pool(...)
8. 如果命令通道 busy/draining：windbg_session("status" 或 "interrupt")
9. 需要查看未解析文本时：windbg_output(command_id, ...)
10. 只有意图工具覆盖不了时，才使用 windbg_exec(...)
```

多数检查命令要求目标已经 break in。除非明确需要改变目标状态，否则不要默认调用执行控制、写内存或设置/清除断点类工具。

## 安全与访问边界

- 已提交的命令不会自动重放；仅在确认命令尚未提交的断连场景允许只读重试。
- 普通命令超时会请求 Ctrl+Break 并确认旧 marker；无法确认时会话保持 `draining` 并拒绝新命令。
- `windbg_control("go")` 超时表示目标仍在运行，不会自动打断；使用 `windbg_session("interrupt")` 显式 break in。
- 写内存、断点、符号路径和执行控制工具在变更后查询后置条件，证据不足时返回 `failed` 或 `indeterminate`，不会声称 `verified`。
- `windbg_control` 可能恢复任意目标代码；`windbg_sympath` 可能替换配置并访问 HTTP 符号服务器；两者标注为 open-world。
- `windbg_exec` 是唯一允许任意 WinDbg 命令的通道，标注为 destructive、non-idempotent、open-world。它可能写内存、改变断点或恢复执行。
- 服务默认仅绑定 `127.0.0.1`，当前**没有认证实现**，也不支持 `WINDBG_MCP_TOKEN`。不要直接暴露到不可信网络；远程使用时应增加经过验证的认证代理或其他访问控制层。
- `--debug-json` 会记录调试器命令和目标数据，应按敏感信息处理。

## 工具列表

当前暴露 20 个 MCP 工具：19 个结构化业务/会话工具 + 1 个原始命令兜底工具。

| 工具 | 用途 | 说明 |
|---|---|---|
| `windbg_context(scope?, include_modules?, module_limit?, list_limit?, include_raw?)` | 当前调试状态 | 精确区分 live/user/kernel 与多种 dump；默认不执行 `lm`，列表带数量和字段级截断标记。 |
| `windbg_analyze(scope?, include_raw?)` | 崩溃/挂起分析 | `scope` 支持 `quick`、`crash`、`hang`；核心结果可用时允许非关键文本 partial。 |
| `windbg_backtrace(depth?, show_params?, frame?)` | 调用栈 | 解析 `kP`/`k`；指定 `frame` 时先验证实际选中帧，再读取并归因局部变量。 |
| `windbg_disassemble(at, count?)` | 反汇编 | 解析 `u` 输出和符号标签。`count` 支持十进制、`0x` 十六进制和 `10h` 形式。 |
| `windbg_evaluate(expression)` | 表达式求值 | 解析 `? expression` 输出，返回十进制和十六进制结果。 |
| `windbg_lookup(what, kind?)` | 符号/类型/地址/函数解析 | `kind` 支持 `address`、`symbol`、`type`、`function`；无匹配返回 `found=false`。 |
| `windbg_read_memory(address, size?, format?)` | 读取内存 | `format` 支持 `auto`、`byte`、`word`、`dword`、`qword`、`ascii`。`size` 是所选 `format` 的元素数量，不是字节数；例如 `size="4", format="qword"` 读取 4 个 qword（共 32 字节）。 |
| `windbg_write_memory(address, values)` | 写入字节 | 使用 `eb` 写入，并将读回地址、连续范围和字节全部绑定后才报告 verified。 |
| `windbg_breakpoint(action, ...)` | 断点管理 | `action` 支持 `set`、`list`、`clear`、`enable`、`disable`；所有变更通过 `bl` 前后状态验证。 |
| `windbg_control(action, count?)` | 执行控制 | `action` 支持 `go`、`step_into`、`step_over`、`step_out`。会改变目标运行状态。 |
| `windbg_sympath(action, path?, module?)` | 符号路径管理 | `action` 支持 `show`、`set`、`reload`、`check`；set/reload 必须查询实际路径或模块符号状态。 |
| `windbg_session(action, command_id?)` | 命令通道控制 | 查询 `idle/executing/interrupting/draining/poisoned/disconnected` 状态，或从队列外中断、显式恢复会话。 |
| `windbg_output(command_id, offset?, limit?)` | 原始证据分页 | 从有界、15 分钟 TTL 的内存缓存读取原始命令输出，单次最多 32 KiB。 |
| `windbg_thread(thread?, include_raw?)` | 内核线程 | 先规范化可选线程地址表达式，再结构化 `!thread` 核心字段与可用栈。 |
| `windbg_module(module, include_raw?)` | 模块详情 | 结构化 `lmvm` 地址、符号状态和映像字段。 |
| `windbg_memory_mapping(address, include_raw?)` | 内存映射 | 解析 `!pte` 层级、表项地址和值；缺页返回准确 limitation。 |
| `windbg_pool(address, force?, include_raw?)` | Pool 检查 | 默认按 dump 能力阻止不可靠查询，`force=true` 保留显式尝试路径。 |
| `windbg_blackbox(kind?, include_raw?)` | 黑盒记录 | 读取 PnP、NTFS、Winlogon 或全部黑盒记录。 |
| `windbg_image_verify(module, include_raw?)` | 映像校验 | 只接受单个模块名，结构化 `!chkimg -d` 不一致范围，使用 120 秒命令预算且不自动重放。 |
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
| `WINDBG_MCP_INTERRUPT_TIMEOUT` | `3` | 超时后等待中断与旧命令边界恢复的秒数 |
| `WINDBG_MCP_RETRIES` | `3` | 仅用于提交前断连的最大恢复尝试次数 |
| `WINDBG_MCP_DEBUG_JSON` | 未设置 | 设为 `1`、`true` 或 `yes` 时启用 JSON 调试日志 |

没有 token 环境变量。HTTP 端点仅依赖 loopback 绑定，不提供认证保证。

## 测试

```powershell
python -m pytest tests/ -v
```

当前重构基线于 2026-07-21 完成以下验证：

- 完整测试集：`278 passed`。
- MCP 合同测试：通过真实工具发现检查 20 个工具的 input/output schema、注解、`structuredContent` 和精简文本响应。
- Streamable HTTP：通过 `initialize -> list_tools -> call_tool` 实际连接 `http://127.0.0.1:8080/mcp`，验证 `windbg_evaluate`、`windbg_context`、`windbg_disassemble`、`windbg_read_memory`、`windbg_analyze`、`windbg_output` 和 `windbg_session`。
- 真实 Kernel Triage Dump：验证启动输出隔离、唯一 `command_id`、超时 Ctrl+Break、旧输出排空，以及后续命令不受污染。
- 失败语义：未捕获内存返回 `dump_data_unavailable`，无匹配符号返回 `core_result_status=empty`，命令分隔符和选项注入在进入 WinDbg 前被拒绝。

解析器测试使用真实 cdb/kd 输出样例。修改解析器时应保留并更新测试；涉及命令边界或 MCP 传输的改动还应使用独立 dump 或只读目标执行实际协议测试。

## 许可证

MIT
