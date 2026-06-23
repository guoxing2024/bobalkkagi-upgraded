# ARCHITECTURE.md

# Bobalkkagi-Upgraded Next Generation Architecture

Version: 2.0

Author: Architecture Design Document

---

# Executive Summary

目标不是开发一个 Dump Tool，而是开发一个 **Automated Protected Binary Analysis Platform**。

支持: Themida, WinLicense, VMProtect(未来), Enigma(未来)

架构必须保证: 脱壳 → 重建 → 分析 → 反虚拟化 在同一框架内完成。

---

# System Architecture

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
│   └── plugin.py         # EventBus + Detector/Rebuilder 接口
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
├── pipeline.py           # 5阶段集成流水线
├── api_recorder.py       # 运行时API调用记录
├── crc_bypass.py         # CRC校验绕过(安全/激进模式)
├── peb.py + kuserSharedData.py + teb.py  # 环境模拟
└── unpacking.py          # Unicorn 模拟解包
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

# Core Principle

```
Track Everything
Store Everything
Analyze Later
Rebuild Last
```

这是整个框架长期可扩展的核心原则。
