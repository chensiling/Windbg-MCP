# Windbg-MCP

MCP (Model Context Protocol) server for WinDbg — 让 AI 驱动内核调试。

## 工作原理

```
MCP Client ──HTTP(MCP)──► Windbg-MCP Server ──TCP──► WinDbg (手动主控)
                                                       .server tcp:port=50000
                                                       双机内核已连VM、已断下
```

- **用户** 在 Windbg 中手动中断目标
- **Windbg** 通过 `.server tcp:port=XXXX` 暴露调试会话
- **Windbg-MCP** 作为远程客户端 (cdb.exe) 连入，收发命令
- **AI Agent** 通过 MCP 协议发送调试指令，获取结果

## 架构

```
Server 层 (HTTP/MCP)          ← MCP 协议，不变
     │
Command 层 (25 个工具)        ← 不关心底层引擎，统一调用 execute()
     │
Engine 层                     ← 定义 execute(command) → str
     └── SubprocessEngine      ← 拉起 cdb.exe，管道通信，UTF-8 容错
```

- **新增调试模式**：实现 Engine 接口即可
- **新增工具**：在 `tools/` 下添加文件，注册到 Command 层
- **更换传输**：Server 层可独立替换，不影响调试引擎

## 快速开始

### 环境要求

- Windows 10/11 x64
- [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) (含 Debugging Tools)
- Python 3.10+

### 安装

```bash
cd Windbg-MCP
pip install -e .
```

### 1. 目标 VM 配置

**KDNET (推荐):**

```bash
# VM 内管理员执行
bcdedit /debug on
bcdedit /dbgsettings net hostip:<宿主机IP> port:50005 key:1.2.3.4
```

VM 网络设 Host-Only，确保宿主机与 VM 互通。

**串口/Pipe:**

```bash
# VM 内管理员执行
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

VM 添加串口 → 命名管道 `\\.\pipe\com_1`。

### 2. Windbg 连接目标

```
WinDbg → File → Kernel Debug → Net (或 COM)
```

连上后手动中断 (Ctrl+Break)，然后暴露 TCP：

```
.server tcp:port=50000
```

### 3. 启动 MCP Server

```bash
python -m src.server --connect tcp:localhost:50000
```

### 4. 配置 MCP Client

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

### 本地用户态调试

先启动 Windbg GUI → Open Executable / Attach Process / Open Dump → 中断后：

```
.server tcp:port=50000
```

另开终端：

```bash
python -m src.server --connect tcp:localhost:50000
```

Windbg GUI 和 AI Agent 共享同一调试会话，互不干扰。

## 数据传输约定

- **AI ↔ Server**：所有参数均为字符串，`0x` 十六进制、寄存器名、符号名均可直接传入
- **Server ↔ Windbg**：Server 将字符串转为合法 Windbg 命令后执行
- **输出**：文本原样返回 Agent

## 可用工具

### 执行控制

| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_go` | — | 继续运行 (g) |
| `windbg_step_into` | count (可选) | 单步进入 (t)，默认 1 步 |
| `windbg_step_over` | count (可选) | 单步跳过 (p)，默认 1 步 |
| `windbg_step_out` | — | 跳出函数 (gu) |

### 断点

| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_bp_set` | address, condition (可选) | 设置断点，符号/地址/条件表达式 |
| `windbg_bp_list` | — | 列出所有断点及命中次数 |
| `windbg_bp_clear` | id | 按 ID 清除，`*` 清除全部 |
| `windbg_bp_enable` | id | 启用断点 |
| `windbg_bp_disable` | id | 禁用断点 |

### 内存 & 寄存器

| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_mem_read` | address, size (可选), format (可选) | 读内存，format: byte/word/dword/qword/ascii |
| `windbg_mem_write` | address, bytes | 写内存，空格分隔十六进制 |
| `windbg_mem_search` | start, end, pattern | 搜索内存模式 |
| `windbg_reg_read` | reg (可选) | 读寄存器，空则返回全部 |
| `windbg_reg_write` | reg, value | 写寄存器 |

### 反汇编 & 栈帧

| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_disasm` | address, count (可选) | 反汇编，默认 8 条指令 |
| `windbg_stack` | count (可选), params (可选) | 调用栈，Markdown 表格 (Frame / Call Site / Child-SP / RetAddr) |
| `windbg_stack_frame` | frame | 查看指定栈帧局部变量/参数 |

### 蓝屏 & 符号 & 类型

| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_analyze` | — | 自动化崩溃分析 (!analyze -v) |
| `windbg_bugcheck` | — | 获取 BugCheck 码及参数 |
| `windbg_sym_lookup` | pattern, type (可选) | 按通配符搜索符号 |
| `windbg_sym_name` | address | 地址 → 符号名 (ln) |
| `windbg_dt` | type, address (可选), depth (可选) | 显示类型结构 (dt) |
| `windbg_eval` | expression | 求值表达式 (? 或 ??) |

### 内核信息

| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_process_list` | — | 枚举所有进程 |
| `windbg_process_info` | address | 进程详细信息 (_EPROCESS 地址) |
| `windbg_module_list` | — | 枚举内核模块/驱动 |
| `windbg_status` | — | 调试器连接状态 |

### 透传

| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_exec` | command | 执行任意 Windbg 命令，支持所有指令 |

## CLI 参数

```
python -m src.server [options]

--connect tcp:HOST:PORT    连接到已有 Windbg (默认 localhost:50000)
--standalone               独立调试 (无 Windbg GUI)
--pid PID                  附加进程 (--standalone)
--exe PATH                 启动可执行文件 (--standalone)
--dump PATH                加载 dump (--standalone)
--http-port PORT           HTTP 端口 (默认 8080)
--debug-json               打印原始 JSON 传输
```

## 配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `WINDBG_MCP_HTTP_PORT` | 8080 | HTTP 服务端口 |
| `WINDBG_MCP_DEBUG_PORT` | 50000 | Windbg TCP 端口 |
| `WINDBG_MCP_DEBUG_HOST` | 127.0.0.1 | Windbg TCP 地址 |
| `WINDBG_MCP_TIMEOUT` | 30 | 命令超时 (秒) |
| `WINDBG_MCP_RETRIES` | 3 | 自动重试次数 |
| `WINDBG_MCP_DEBUG_JSON` | — | 设为 1 开启 JSON 调试输出 |

## 常见问题

### 工具返回空 / 超时？

1. 确认 Windbg 中目标已中断 (Ctrl+Break)
2. 确认 `.server tcp:port=50000` 仍在监听，可用 `.server` 查看
3. 换端口重开：`.server tcp:port=50001`，然后 `--connect tcp:localhost:50001`

### 编码错误 (read_loop died)？

cdb.exe 输出含非 GBK 字符时可能触发。引擎已内置 `encoding="utf-8"` + `errors="replace"` 容错。

### 端口被占用？

```
.endsrv 0       # 先关旧服务
.server tcp:port=50002  # 换端口重开
```

### 多 VM 同时调试？

启动多个 MCP Server 实例，绑定不同端口。

## 开发

```bash
pip install -e ".[dev]"
pytest
```

### 调试原始 JSON

```bash
python -m src.server --debug-json
# 或
WINDBG_MCP_DEBUG_JSON=1 python -m src.server
```

输出格式：

```
=== REQUEST ===
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "tools/call",
  "params": {
    "name": "windbg_mem_read",
    "arguments": { "address": "0xfffff80012345678", "size": "0x40" }
  }
}

=== RESPONSE ===
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "content": [{"type": "text", "text": "fffff800`12345678  00000000 ..."}]
  }
}
```

## 许可证

MIT
