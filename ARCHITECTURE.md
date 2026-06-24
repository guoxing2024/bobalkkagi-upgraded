# ARCHITECTURE.md

# Bobalkkagi-Upgraded Next Generation Architecture

Version: 3.0 (P2)

Author: Architecture Design Document

---

# Executive Summary

目标不是开发一个 Dump Tool，而是开发一个 **Automated Protected Binary Analysis Platform**。

支持: Themida, WinLicense, VMProtect(未来), Enigma(未来)

架构必须保证: 脱壳 → 重建 → 分析 → 反虚拟化 在同一框架内完成。

---

# System Architecture (P2: Multi-Backend)

```
                         +------------------+
                         |      CLI/UI      |
                         +---------+--------+
                                   |
                                   v
+---------------------------------------------------------+
|                    Analysis Pipeline                    |
+---------------------------------------------------------+
                                   |
                    +--------------+--------------+
                    |              |              |
                    v              v              v
             +-----------+ +-----------+ +-----------+
             |  Unicorn  | | Debugger  | |  Hybrid   |
             |  Backend  | |  Backend  | |  Backend  |
             +-----------+ +-----------+ +-----------+
                    |              |              |
                    +--------------+--------------+
                                   |
                                   v
+---------------------------------------------------------+
|               IExecutionBackend (ABC)                    |
|  initialize → load_target → install_hooks → execute    |
|  → dump_memory → get_oep → cleanup                     |
+---------------------------------------------------------+
                                   |
                                   v
+---------------------------------------------------------+
|                    Unpack Context                       |
+---------------------------------------------------------+

      |              |              |              |
      v              v              v              v

+-----------+ +-----------+ +-----------+ +-----------+
|  Loader   | | Emulator  | |  Tracker  | | Detector  |
+-----------+ +-----------+ +-----------+ +-----------+

                                   |
                                   v

+---------------------------------------------------------+
|                    Rebuilder Layer                      |
+---------------------------------------------------------+

                                   |
                                   v

+---------------------------------------------------------+
|                     Output Engine                       |
+---------------------------------------------------------+
```

---

# Core Design Principle

禁止全局变量。统一使用 `UnpackContext`。所有状态进入 Context。

任何模块签名: `def process(ctx): pass` — 禁止共享全局状态。

---

# Project Layout

```
project/
├── core/
│   ├── context.py        # UnpackContext 中心状态容器
│   ├── events.py         # 6种事件类型定义
│   ├── plugin.py         # EventBus + Detector/Rebuilder 接口
│   └── backend.py        # IExecutionBackend 抽象接口 (P2)
├── engine/               # 执行引擎层 (P2)
│   ├── unicorn_backend.py   # Unicorn CPU模拟
│   ├── debugger_backend.py  # Win32 Debug API真实进程
│   └── hybrid_backend.py    # Unicorn→进程注入→Debugger
├── loader/
│   └── loader.py         # PE/DLL 加载器
├── emulator/
│   └── (unicorn)
├── hook/
│   ├── api_hook.py       # 84个API钩子
│   └── hookFuncs.py      # 钩子索引表
├── tracker/
│   ├── memory_tracker.py # 内存页追踪(RW→RX检测)
│   ├── memory_tracker_v2.py # EventBus集成版
│   └── import_scanner.py # Scylla-style thunk扫描
├── detector/
│   └── (OEPDetectorBase in core/plugin.py)
├── rebuild/
│   ├── pe_rebuilder.py   # PE section header 重建
│   ├── iat_rebuilder.py  # IAT 重建 (运行时+原始PE合并)
│   └── tls_rebuilder.py  # TLS 目录恢复
├── exception_engine.py   # SEH/VEH 异常拦截
├── pipeline.py           # 5阶段集成流水线 (多后端调度)
├── api_recorder.py       # 运行时API调用记录
├── crc_bypass.py         # CRC校验绕过(安全/激进模式)
├── agent_interface.py    # AI Agent JSON接口 + RETRY_STRATEGIES
├── diagnostic.py         # 失败原因诊断引擎
├── peb.py + kuserSharedData.py + teb.py  # 环境模拟
└── unpacking.py          # Unicorn 模拟解包 (向后兼容)
```

---

# OEP Detection Algorithm

综合评分公式:

```
score = return_to_main_module * 30
      + rw_to_rx_transition * 25
      + call_stack_collapse * 25
      + api_sequence_match * 20
```

OEP 状态机: START → UNPACKING → DECRYPTING → STABILIZING → OEP_FOUND

---

# Event System

所有模块通过 EventBus 解耦:

```
Emulator → EventBus → Trackers → Detectors
```

6种事件类型: ApiEvent, MemoryEvent, CallEvent, ExceptionEvent, OEPEvent, ModuleLoadEvent

---

# Plugin Interface

```python
class DetectorPlugin(ABC):
    initialize(ctx) -> bool
    process(event, ctx) -> Optional[BaseEvent]
    finalize(ctx) -> list

class RebuilderPlugin(ABC):
    rebuild(ctx) -> bool
```

---

# Backend Interface (P2)

```python
class IExecutionBackend(ABC):
    backend_type: BackendType
    display_name: str
    capabilities: Dict

    initialize(ctx) -> bool
    load_target(ctx) -> bool
    install_hooks(ctx) -> bool
    execute(ctx) -> ExecutionResult
    dump_memory(ctx) -> Optional[bytes]
    get_oep(ctx) -> int
    cleanup(ctx) -> None
```

Three backends:
- **UnicornBackend**: CPU emulation, fast (~9s), no hardware anti-debug
- **DebuggerBackend**: Win32 Debug API, real CPU, ScyllaHide, ~30-60s
- **HybridBackend**: Unicorn decrypt → CreateProcess(SUSPENDED) → WriteProcessMemory → Debugger takeover

---

# Auto-Retry Engine (P1)

```
agent_unpack() failure
    → map error_code to RETRY_STRATEGIES
    → iterate strategies (adjust mode/crc/backend/force_runtime_iat)
    → on success: return result with "auto-retry succeeded" diagnosis
    → on exhaustion: return last error with "auto-retry exhausted" diagnosis
```

7 strategies: oep_not_found, iat_no_imports, emulation_crash, crc_crash,
               low_import_count, debugger_failed, debugger_access_denied

---

# Core Principle

```
Track Everything
Store Everything
Analyze Later
Rebuild Last
```

这是整个框架长期可扩展的核心原则。
