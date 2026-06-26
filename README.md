# Windbg-MCP

MCP (Model Context Protocol) server for WinDbg — 让 AI 驱动内核调试。

## 工作原理

```
 MCP Client ──HTTP(MCP)──► Windbg-MCP Server ──TCP──► WinDbg(手动主控)
                                                           .server tcp:port=50000
                                                           双机内核已连VM、已断下
```

- **用户**在 WinDbg 中手动中断目标
- **WinDbg** 通过 `.server tcp:port=XXXX` 暴露调试会话
- **Windbg-MCP** 作为远程客户端连入，收发命令
- **AI Agent** 通过 MCP 协议发送调试指令，获取结果

## 架构（可扩展）

```
Server 层 (HTTP/MCP)         ← MCP 协议，不变
     │
Command 层 (25个工具)        ← 不关心底层引擎，统一调用 execute()
     │
Engine 接口 (抽象)            ← 定义 execute(command) → str
     ├── SubprocessEngine       ← 拉起 cdb.exe，通过管道通信，UTF-8 容错
    
- **新增调试模式**：实现 Engine 接口即可，不影响上下层
- **新增工具**：在 tools/ 下添加文件，注册到 Command 层即可
- **更换传输**：Server 层可独立替换，不影响调试引擎

## 快速开始

### 0. 前置条件

- Windows 10/11 x64
- [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) (含 Debugging Tools: `kd.exe`, `cdb.exe`)
- Python 3.10+

无需额外安装 pykd 或其他调试扩展。

### 1. 目标机准备（VMware）

**方式A：网络调试（KDNET，推荐）**

```
# 目标 VM 内执行（管理员）
bcdedit /debug on
bcdedit /dbgsettings net hostip:<宿主机IP> port:50005 key:1.2.3.4
```

VM 网络设 Host-Only，确保宿主机与 VM 互通。

**方式B：串口/Pipe 调试**

```
# 目标 VM 内执行（管理员）
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

VM 设置：添加串口 → 使用命名管道 `\\.\pipe\com_1`。

### 2. WinDbg 连接目标并暴露 TCP

**对应方式A（Net）：**

```
WinDbg → File → Kernel Debug → Net
Host: <宿主机IP>, Port: 50005, Key: 1.2.3.4
```

**对应方式B（COM/Pipe）：**

```
WinDbg → File → Kernel Debug → COM
Port: \\.\pipe\com_1, Baud: 115200
```

**中断后暴露 TCP 给 MCP Server：**

```
.server tcp:port=50000
```

### 3. 启动 MCP Server

```
git clone <this-repo>
cd Windbg-MCP
pip install -e .

# 双机内核调试
windbg-mcp --connect tcp:localhost:50000

# 本地用户态调试（Windbg GUI 已 open/attach 后 .server tcp:port=50000）
windbg-mcp --connect tcp:localhost:50000

# 无 GUI，MCP 自行启动调试会话
windbg-mcp --standalone --pid 1234
windbg-mcp --standalone --dump C:\memory.dmp
```

### 4. 配置 MCP Client

以 Claude Desktop 为例，在配置文件中添加：

```json
{
  "mcpServers": {
    "windbg": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### 5. 本地调试模式

除双机内核调试外，也支持本地用户态调试。流程是：**先启动 Windbg UI，在 UI 里操作，再拉起 MCP**。

```
# 1. 启动 Windbg GUI
# 2. Windbg 中：File → Open Executable / Attach to Process / Open Dump
# 3. 中断后在 Windbg 命令行执行：
.server tcp:port=50000

# 4. 另开终端启动 MCP Server 接入：
windbg-mcp --connect tcp:localhost:50000
```

MCP Server 接入后，Windbg GUI 和 AI Agent 共享同一个调试会话，双方都可以发命令、设断点、查看状态，互不干扰。

## 数据传输约定

- **AI ↔ Server**：所有参数均为字符串，`0x` 前缀十六进制、寄存器名、符号名均可直接传入
- **Server ↔ Windbg**：Server 负责将字符串解析为数值/地址/符号，构造合法 Windbg 命令后执行
- **输出**：文本原样返回给 Agent，不做结构化

## 可用工具

### 执行控制
| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_go` | — | 继续运行 (g) |
| `windbg_step_into` | count (可选) | 单步进入 (t)，默认1步 |
| `windbg_step_over` | count (可选) | 单步跳过 (p)，默认1步 |
| `windbg_step_out` | — | 跳出函数 (gu) |

### 断点
| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_bp_set` | address, condition (可选) | 设置断点，支持符号/地址/条件表达式 |
| `windbg_bp_list` | — | 列出所有断点及命中次数 |
| `windbg_bp_clear` | id | 按 ID 清除断点 |
| `windbg_bp_enable` | id | 启用断点 |
| `windbg_bp_disable` | id | 禁用断点 |

### 内存 & 寄存器
| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_mem_read` | address, size (可选), format (可选) | 读内存，format: byte/word/dword/qword/ascii |
| `windbg_mem_write` | address, bytes | 写内存，bytes 为空格分隔十六进制 |
| `windbg_mem_search` | start, end, pattern | 搜索内存模式 |
| `windbg_reg_read` | reg (可选) | 读寄存器，空则返回全部 |
| `windbg_reg_write` | reg, value | 写寄存器 |

### 反汇编 & 栈帧
| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_disasm` | address, count (可选) | 反汇编，默认8条指令 |
| `windbg_stack` | count (可选), params (可选) | 调用栈，Markdown 表格 (Frame/Call Site/Child-SP/RetAddr)，默认20帧 |
| `windbg_stack_frame` | frame | 查看指定栈帧局部变量/参数 |

### 蓝屏 & 符号 & 类型
| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_analyze` | — | 自动化崩溃分析 (!analyze -v) |
| `windbg_bugcheck` | — | 获取 BugCheck 码及参数 |
| `windbg_sym_lookup` | pattern, type (可选) | 按通配符搜索符号 |
| `windbg_sym_name` | address | 地址转符号名 (ln) |
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

## 配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `WINDBG_MCP_HTTP_PORT` | 8080 | MCP HTTP 服务端口 |
| `WINDBG_MCP_DEBUG_PORT` | 50000 | Windbg TCP 调试端口 |
| `WINDBG_MCP_DEBUG_HOST` | 127.0.0.1 | Windbg TCP 地址 |
| `WINDBG_MCP_TOKEN` | — | 可选，API 认证 Token |

## 常见问题

### 目标在运行中怎么办？
AI 会收到 `target is running` 提示。需手动在 Windbg 中 Break (Ctrl+Break)，或使用 `windbg_go` 让目标继续（如果只是路过）。

### Windbg TCP 端口断连？
MCP Server 自动重试 3 次，仍失败则返回错误，不会崩溃。

### 命令超时？
内核态某些命令可能耗时较长，默认 30 秒超时，可通过环境变量调整。

### 工具返回空 / 编码错误？
cdb.exe 输出含非 ASCII 字符时可能触发编码错误。确认引擎使用 `encoding="utf-8"` + `errors="replace"`，MCP 终端应无 `read_loop died` 日志。

### 多个 VM 同时调试？
启动多个 MCP Server 实例，绑定不同端口，Windbg 侧分别 `.server tcp:port=50001`、`.server tcp:port=50002`。

## 开发

```
pip install -e ".[dev]"
pytest
```

### 调试原始 JSON

开发调试时，需要查看 Agent ↔ MCP Server 之间的原始 JSON 传输，以确认数据格式是否正确。

启动 MCP Server 时开启调试日志：

```
windbg-mcp --windbg-port 50000 --http-port 8080 --debug-json
```

开启后，每次 JSON 请求/响应都会以格式化形式打印到终端：

```
=== REQUEST ===
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "tools/call",
  "params": {
    "name": "windbg_mem_read",
    "arguments": {
      "address": "0xfffff80012345678",
      "size": "0x40",
      "format": "dword"
    }
  }
}

=== RESPONSE ===
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "fffff800`12345678  00000000 ..."
      }
    ]
  }
}
```

也可通过环境变量开启：

```
WINDBG_MCP_DEBUG_JSON=1 windbg-mcp --windbg-port 50000
```

打出来的 JSON 可直接复制到 `jq`、VS Code 等工具中校验格式。

## 许可证

MIT
