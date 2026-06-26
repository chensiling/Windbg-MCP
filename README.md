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

`windbg_exec` 透传覆盖所有 WinDbg 命令，以下列出全部功能及对应工具。

### 一、执行控制

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `g` Go | 继续运行 | `windbg_go` |
| `p` Step | 单步跳过 | `windbg_step_over` |
| `t` Trace | 单步进入 | `windbg_step_into` |
| `gu` Go Up | 跳出函数 | `windbg_step_out` |
| `pa` Step to Address | 单步到地址 | `windbg_exec` |
| `pc` Step to Next Call | 单步到调用 | `windbg_exec` |
| `pt` Step to Return | 单步到返回 | `windbg_exec` |
| `gc/gh/gn/gN` | 条件/异常继续 | `windbg_exec` |

### 二、断点

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `bp/bu/bm` Set Breakpoint | 设置断点 | `windbg_bp_set` |
| `bl` Breakpoint List | 列出断点 | `windbg_bp_list` |
| `bc` Breakpoint Clear | 清除断点 | `windbg_bp_clear` |
| `bd` Breakpoint Disable | 禁用断点 | `windbg_bp_disable` |
| `be` Breakpoint Enable | 启用断点 | `windbg_bp_enable` |
| `ba` Break on Access | 内存访问断点 | `windbg_exec` |
| `br` Breakpoint Renumber | 重编号 | `windbg_exec` |
| `bs` Update Breakpoint Command | 更新断点命令 | `windbg_exec` |
| `bsc` Update Conditional BP | 更新条件断点 | `windbg_exec` |

### 三、内存操作

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `db/dd/dq/du/da...` Display Memory | 读内存 | `windbg_mem_read` |
| `eb/ed/eq...` Enter Values | 写内存 | `windbg_mem_write` |
| `s` Search Memory | 搜索内存 | `windbg_mem_search` |
| `c` Compare Memory | 比较内存 | `windbg_exec` |
| `f` Fill Memory | 填充内存 | `windbg_exec` |
| `m` Move Memory | 移动内存 | `windbg_exec` |
| `dds/dps/dqs` Words & Symbols | 符号化显示 | `windbg_exec` |
| `dl` Display Linked List | 显示链表 | `windbg_exec` |
| `ds` Display String | 显示字符串 | `windbg_exec` |

### 四、寄存器

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `r` Registers | 读/写寄存器 | `windbg_reg_read` / `windbg_reg_write` |
| `rm` Register Mask | 寄存器掩码 | `windbg_exec` |
| `rdmsr/wrmsr` | 读/写 MSR | `windbg_exec` |

### 五、反汇编

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `u` Unassemble | 反汇编 | `windbg_disasm` |
| `uf` Unassemble Function | 反汇编整个函数 | `windbg_exec` |
| `up` Unassemble Physical | 物理地址反汇编 | `windbg_exec` |
| `a` Assemble | 汇编写入 | `windbg_exec` |
| `#` Search Disasm Pattern | 反汇编模式搜索 | `windbg_exec` |

### 六、栈帧

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `k/kb/kp/kP/kv` Stack Backtrace | 调用栈 (Markdown 表格) | `windbg_stack` |
| `.frame` Set Current Frame | 切换帧 | `windbg_exec` |
| `dv` Display Local Variables | 局部变量 | `windbg_stack_frame` |
| `wt` Trace and Watch Data | 跟踪监视 | `windbg_exec` |

### 七、符号

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `x` Examine Symbols | 搜索符号 | `windbg_sym_lookup` |
| `ln` List Nearest Symbols | 地址 → 符号名 | `windbg_sym_name` |
| `ld` Load Symbols | 加载符号 | `windbg_exec` |
| `.sympath` Set Symbol Path | 符号路径 | `windbg_exec` |
| `.reload` Reload Module | 重载模块 | `windbg_exec` |

### 八、类型 & 表达式

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `dt` Display Type | 显示类型结构 | `windbg_dt` |
| `?` Evaluate Expression | MASM 表达式求值 | `windbg_eval` |
| `??` Evaluate C++ Expression | C++ 表达式求值 | `windbg_eval` |

### 九、进程 & 线程

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `!process` | 进程枚举/详情 | `windbg_process_list` / `windbg_process_info` |
| `|` Process Status | 进程状态 | `windbg_exec` |
| `|s` Set Current Process | 切换进程 | `windbg_exec` |
| `~` Thread Status | 线程状态 | `windbg_exec` |
| `~s` Set Current Thread | 切换线程 | `windbg_exec` |
| `~f/~u` Freeze/Unfreeze | 冻结/解冻线程 | `windbg_exec` |
| `~n/~m` Suspend/Resume | 挂起/恢复线程 | `windbg_exec` |
| `!thread` | 线程详情 | `windbg_exec` |
| `!peb` / `!teb` | PEB/TEB 信息 | `windbg_exec` |

### 十、模块 & 驱动

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `lm` List Loaded Modules | 列出模块 | `windbg_module_list` |
| `!drvobj` | 驱动对象信息 | `windbg_exec` |
| `!devnode` / `!devstack` | 设备节点/栈 | `windbg_exec` |
| `!devobj` | 设备对象 | `windbg_exec` |

### 十一、崩溃分析

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `!analyze -v` | 自动化崩溃分析 | `windbg_analyze` |
| `.bugcheck` | BugCheck 码及参数 | `windbg_bugcheck` |
| `.dump` Create Dump | 创建转储文件 | `windbg_exec` |
| `.crash` Force Crash | 强制崩溃 | `windbg_exec` |
| `.ecxr` Exception Context | 异常上下文记录 | `windbg_exec` |
| `.exr` Exception Record | 异常记录 | `windbg_exec` |
| `sx/sxd/sxe/sxi` | 异常控制 | `windbg_exec` |

### 十二、内核专用

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `!irql` | 查看 IRQL 等级 | `windbg_exec` |
| `!locks` | 锁信息 | `windbg_exec` |
| `!handle` | 句柄信息 | `windbg_exec` |
| `!vm` | 虚拟内存统计 | `windbg_exec` |
| `!memusage` | 物理内存统计 | `windbg_exec` |
| `!poolused` / `!poolfind` | 内存池统计 | `windbg_exec` |
| `!object` | 内核对象 | `windbg_exec` |
| `!idt` / `!gdt` / `!tss` | 描述符表 | `windbg_exec` |
| `!sysinfo` / `!cpuid` | 系统/CPU 信息 | `windbg_exec` |
| `!pcr` / `!prcb` | 处理器控制区 | `windbg_exec` |
| `!cs` / `!dpcs` / `!apc` | 临界区/DPC/APC | `windbg_exec` |
| `!ioapic` / `!pic` | APIC/PIC 信息 | `windbg_exec` |
| `!pfn` | PFN 数据库 | `windbg_exec` |

### 十三、会话 & 状态

| WinDbg 命令 | 功能 | MCP 工具 |
|-------------|------|----------|
| `.lastevent` | 最后事件 | `windbg_status` |
| `||` System Status | 系统状态 | `windbg_exec` |
| `.server` / `.endsrv` | 调试服务器 | `windbg_exec` |
| `q/qd` Quit/Detach | 退出/分离 | `windbg_exec` |
| `version` / `vertarget` | 版本信息 | `windbg_exec` |
| `n` Set Number Base | 设置基数 | `windbg_exec` |

### 透传

| 工具 | 参数 | 说明 |
|------|------|------|
| `windbg_exec` | command | 执行任意 Windbg 命令，以上 `windbg_exec` 项均通过此工具完成 |

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
