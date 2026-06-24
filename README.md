# TEAM Bobalkkagi — Upgraded 🚀

BOB11 project — **Upgraded by Hermes Agent**

Unpacking & Unwrapping & Devirtualization(Not yet) of Themida 3.x packed programs.

## Upgraded Features

Compared to the original version (35 API hooks, no PE reconstruction):

| Feature | Original | Upgraded |
|---------|----------|----------|
| API Hooks | 35 | **84** (+49) |
| PE Rebuilder | ❌ | ✅ Section headers fix for memory dumps |
| IAT Reconstructor | ❌ | ✅ Import table rebuild (runtime + original PE merge) |
| force_runtime_iat | ❌ | ✅ Runtime-only IAT mode (solves obfuscated imports) |
| CRC Bypass | ❌ | ✅ Capstone-based integrity check patch + safe/aggressive modes |
| Auto-Retry Engine | ❌ | ✅ RETRY_STRATEGIES with 5 error code strategies |
| Structured Diagnosis | ❌ | ✅ JSON diagnosis with root cause analysis + next steps |
| PEB/KUSER Environment | Minimal | Full Win10 1903 simulation |
| Full Pipeline | ❌ | ✅ `unpack_full()` — 5-stage (Unpack → Emulate → Analyze → Detect → Rebuild) |
| AI Agent Interface | ❌ | ✅ JSON I/O + unified error codes + auto-retry |
| P2: Multi-Backend | ❌ | ✅ Unicorn + Debugger dual backend + cross-backend failover |

## Installation

```bash
# Python 3.10+ required
git clone https://github.com/guoxing2024/bobalkkagi-upgraded.git
cd bobalkkagi-upgraded

# Dependencies
pip install unicorn pefile capstone fire distorm3 lief

# Or use the provided win10_v1903 DLLs
```

## Quick Start

### Method 1: Full Pipeline (Recommended)

```python
from bobalkkagi.pipeline import unpack_full

# 5-stage: Unpack → Emulate → Analyze → Detect → Rebuild
dump_path, exe_path, oep = unpack_full(
    "protected.exe",
    mode="f",                    # f=fast, c=hook_code (deep), b=hook_block
    dll_path="win10_v1903"       # DLL directory
)

print(f"OEP: 0x{oep:x}")
print(f"Output: {exe_path}")
```

### Method 1b: Pipeline with Runtime IAT (Solving Low Import Count)

```python
from bobalkkagi.pipeline import Pipeline

pipe = Pipeline(
    "protected.exe",
    dll_path="win10_v1903",
    force_runtime_iat=True,      # Ignore obfuscated original imports
    crc_mode="safe"
)
result = pipe.run()
print(f"OEP: 0x{result.oep:x}")
print(f"Output: {result.output_path}")
```

### Method 1c: Debugger Backend (P2 — Hardware Anti-Debug)

```python
from bobalkkagi.agent_interface import agent_unpack
import json

result = json.loads(agent_unpack(
    "protected.exe",
    backend="debugger",          # Win32 Debug API + ScyllaHide
    timeout=120
))
print(f"OEP: {result['oep']}")
```

| Backend | Unicorn | Debugger |
|---------|---------|----------|
| Hardware anti-debug | ❌ | ✅ ScyllaHide |
| Timing detection | ❌ | ✅ Real CPU |
| Auto-failover | →debugger on crash | →unicorn on failure |

Output:
- `protected_unpacked.exe` — Fully reconstructed PE with:
  - ✅ Fixed section headers (ROff=VA, RSize=VSize)
  - ✅ Corrected Entry Point (OEP)
  - ✅ Reconstructed Import Table
- `protected.dump` — Raw Unicorn memory dump

### Method 2: Original CLI

```bash
bobalkkagi protected.exe --dllPath win10_v1903
```

### Manual PE+ IAT Repair (if using original output)

```python
from bobalkkagi.pe_rebuilder import rebuild_dump
from bobalkkagi.iat_rebuilder import rebuild_iat

# Step 1: Fix sections
rebuild_dump("original.dump", "fixed.exe", oep=0x1404ed393)

# Step 2: Rebuild imports  
rebuild_iat("fixed.exe", "original_protected.exe", "final.exe")
```

## Architecture

```
application.py ──┐
                 ├─ unpacking.py ─── loader.py (PE/DLL mapping)
                 │                  ├─ api_hook.py (84 hooks)
                 │                  ├─ crc_bypass.py [NEW]
                 │                  └─ peb/teb/kuser (environment)
                 │
                 ├─ pe_rebuilder.py [NEW]
                 │   └─ Section header + OEP + SizeOfImage fix
                 │
                 ├─ iat_rebuilder.py [NEW]
                 │   ├─ Import descriptors + thunk table rebuild
                 │   └─ Runtime API merge (api_recorder.py) [NEW]
                 │
                 ├─ pipeline.py [NEW]
                 │   ├─ unpack_full() — 5-stage automated pipeline
                 │   ├─ force_runtime_iat support
                 │   └─ CRC mode passthrough
                 │
                 └─ agent_interface.py [NEW]
                     ├─ JSON I/O (AI Agent ready)
                     ├─ RETRY_STRATEGIES auto-retry engine
                     └─ Structured diagnosis with root cause analysis
```

## API Hook 策略文档 (84 hooks)

每个Unicorn钩子必须正确伪装为"未调试/未模拟"状态，否则Themida会检测到异常。

### 关键反调试钩子返回策略

| Hook | Themida检测手段 | 返回策略 |
|------|----------------|----------|
| `ZwQueryInformationProcess(ProcessDebugPort=0x7)` | 检查调试端口 | 返回0（未调试） |
| `ZwQueryInformationProcess(ProcessDebugFlags=0x1F)` | 检查EPROCESS.DebugFlags | 返回1（已禁用） |
| `ZwSetInformationThread(ThreadHideFromDebugger=0x11)` | 隐藏线程 | 返回STATUS_SUCCESS |
| `ZwQuerySystemInformation(SystemKernelDebuggerInfo=0x23)` | 检查内核调试器 | 返回STATUS_INFO_LENGTH_MISMATCH |
| `ZwQueryObject` | 检查对象句柄信息 | 返回STATUS_INFO_LENGTH_MISMATCH |
| `ZwRaiseHardError` | 触发硬错误 | 忽略并返回成功 |
| `ZwTerminateProcess` | 自杀（CRC校验失败时） | **阻止**，返回STATUS_ACCESS_DENIED |
| `RtlGetVersion` | 系统版本不匹配 | 返回Win10 1903 (10.0.18362) |
| `QueryPerformanceCounter` | RDTSC延迟检测 | 返回递增计数值 |
| `GetTickCount/GetTickCount64` | 时间检测 | 返回递增值 |
| `KUSER_SHARED_DATA.KdDebuggerEnabled` | 直接读取KUSER | **设为0**（原代码错误设为1！） |
| `PEB.BeingDebugged` | 直接读取PEB | 设为0 |
| `PEB.NtGlobalFlag` | 检查堆标志 | 设为0 |
| `ZwYieldExecution` | CPU yield检测 | 返回STATUS_NO_YIELD_PERFORMED |

### CRC Bypass 模式

```python
# 安全模式（默认）：只patch附近有ROL/ROR/CRC32指令的CMP+Jcc
# 激进模式：所有CMP+Jcc都NOP掉
crc_bypass_post_load(uc, themida, boot, image_base, mode='safe')
```

## 兼容性测试矩阵

| Themida版本 | 保护级别 | 脱壳 | OEP检测 | PE重建 | IAT重建 | VM代码 | 测试样本 |
|-------------|----------|------|---------|--------|---------|--------|----------|
| 3.1.3 | Tiger red64 | ✅ | ✅ | ✅ | ✅ runtime-merge | ❌ | Sample.exe(测试样本) |
| 3.1.x | 未知 | ✅ | ✅ | ✅ | ✅ runtime-merge | ❌ | 伦伦软件.exe |
| 3.1.8+ | 反调试增强 | ⚠ 未测试 | ⚠ | ⚠ | ⚠ | ❌ | 需要样本 |
| 3.x VM | VM Enabled | ❌ Devirt未实现 | - | - | - | ❌ | - |

### 限制说明

1. **VM代码不可运行**: Themida的VM保护段(.themida)虽然被dump出来，但原始控制流经过VM化后无法直接执行。标注"Devirtualization(Not yet)"
2. **IAT恢复**: 默认模式合并原始PE导入表+运行时API记录，但原始PE导入表被Themida隐藏。启用 `force_runtime_iat=True` 可使用运行时记录的完整API调用集重建IAT
3. **API记录深度**: fast模式（默认）仅捕获~9个调用；deep模式（hook_code）可捕获800+。对于完整IAT恢复，建议先跑deep模式获取完整记录，再force_runtime_iat重建
4. **CRC绕过**: 启发式绕过，safe模式（仅patch CRC上下文）和aggressive模式（patch所有CMP+Jcc），提供 `rollback_crc_patches()` 回滚接口。RETRY_STRATEGIES 自动处理CRC崩溃
5. **单线程模型**: Unicorn只模拟单线程，Themida多线程保护（反调试线程等）未被处理
6. **Windows版本依赖**: 需要win10_v1903 DLL目录，其他Windows版本可能不完全兼容
7. **网络验证**: Themida的网络验证/注册机制未模拟，联网保护的程序需额外处理
8. **非线程安全**: 使用全局状态(GLOBAL_VAR通过proxy代理到UnpackContext)，仅支持单进程单样本。不支持并发多实例
9. **OEP检测**: fast模式模拟可能终止于DLL地址而错过真实OEP，建议使用hook_code模式提高准确率

```
ntdll:
  Registration: ZwOpenKey, ZwCreateKey, ZwQueryValueKey, ZwDeleteKey
  File/Section: ZwCreateFile, ZwOpenFile, ZwCreateSection, ZwMapViewOfSection
  Sync: ZwDelayExecution, ZwCreateMutant, ZwCreateEvent, ZwOpenEvent
  Process: ZwCreateThreadEx, ZwTerminateProcess, ZwRaiseHardError, ZwQueryInformationThread
  Misc: ZwQueryObject, ZwYieldExecution, LdrLoadDll, RtlGetVersion
  Anti-debug: ZwQueryInformationProcess, ZwSetInformationThread, ZwSetInformationProcess

kernel32:
  Thread: CreateThread, WaitForSingleObject, WaitForMultipleObjects
  System Info: GetSystemInfo, GetNativeSystemInfo, QueryPerformanceCounter, GetTickCount, GetTickCount64
  Misc: IsProcessorFeaturePresent, GetACP, GetOEMCP, TlsGetValue, TlsSetValue,
        EncodePointer, DecodePointer, InitializeCriticalSection, GetUserDefaultLCID

kernelbase:
  LCMapStringEx, GetStringTypeW, FindResourceW, SizeofResource, LoadResource
```

## Emulation Modes

- **`f` (fast)**: Compare RIP with hooked API function area (size 0x20) — **default**
- **`c` (hook_code)**: Per-opcode comparison with all DLL memory — for analysis
- **`b` (hook_block)**: Per-block comparison — balance of speed and detail

## Files Changed

```
NEW:  bobalkkagi/pe_rebuilder.py    — PE section header reconstruction
NEW:  bobalkkagi/agent_interface.py   — AI Agent JSON interface + RETRY_STRATEGIES (P1) + backend param (P2)
NEW:  bobalkkagi/core/backend.py        — IExecutionBackend abstract interface (P2)
NEW:  bobalkkagi/engine/__init__.py      — create_backend factory (P2)
NEW:  bobalkkagi/engine/unicorn_backend.py — UnicornBackend implementation (P2)
NEW:  bobalkkagi/engine/debugger_backend.py — DebuggerBackend — Win32 Debug API (P2)
MOD:  bobalkkagi/pipeline.py        — 5-stage pipeline + multi-backend scheduling (P2)
NEW:  bobalkkagi/crc_bypass.py      — CRC integrity check bypass (safe/aggressive)
NEW:  bobalkkagi/api_recorder.py    — Runtime API call recording for IAT
NEW:  bobalkkagi/diagnostic.py      — Structured failure diagnosis engine
NEW:  bobalkkagi/exception_engine.py — SEH/VEH exception interception
NEW:  bobalkkagi/core/context.py    — UnpackContext central state container
NEW:  bobalkkagi/core/events.py     — 6 event types + EventBus
NEW:  bobalkkagi/core/plugin.py     — Detector/Rebuilder plugin interfaces
NEW:  bobalkkagi/tracker/memory_tracker_v2.py — EventBus-integrated memory tracker
NEW:  bobalkkagi/tracker/import_scanner.py    — Scylla-style thunk scanner
NEW:  bobalkkagi/detector/oep_detector.py     — Multi-signal OEP detection
NEW:  bobalkkagi/detector/memory_analyzer.py  — RegionClassifier (6 types)
NEW:  bobalkkagi/rebuild/tls_rebuilder.py     — TLS directory restoration
NEW:  bobalkkagi/agent_interface.py   — AI Agent JSON interface + RETRY_STRATEGIES (P1) + backend param (P2)
NEW:  bobalkkagi/core/backend.py        — IExecutionBackend abstract interface (P2)
NEW:  bobalkkagi/engine/__init__.py      — create_backend factory (P2)
NEW:  bobalkkagi/engine/unicorn_backend.py — UnicornBackend implementation (P2)
NEW:  bobalkkagi/engine/debugger_backend.py — DebuggerBackend — Win32 Debug API (P2)
MOD:  bobalkkagi/pipeline.py        — 5-stage pipeline + multi-backend scheduling (P2)
MOD:  bobalkkagi/hookFuncs.py       — Hook index table (35→84)
MOD:  bobalkkagi/kuserSharedData.py — Fixed KdDebuggerEnabled=0
MOD:  bobalkkagi/peb.py             — OS version fields in PEB
MOD:  bobalkkagi/loader.py          — Boot section tracking
MOD:  bobalkkagi/globalValue.py     — Context bridge + _GlobalVarProxy
MOD:  bobalkkagi/unpacking.py       — CRC bypass integration
```

## Known Issues

1. **CRC bypass**: capstone scan on .boot section may return empty buffer for some samples
2. **OEP detection**: fast-mode emulation may terminate at DLL address instead of real OEP
3. **API recording depth**: fast mode only captures ~9 API calls; deep (hook_code) mode captures 800+
4. **reflector.py**: Missing `ext-ms-win-*` API set redirects for newer Windows
5. **Hook naming convention**: Hook system dispatches by function name (`.dll_` prefix stripped). kernelbase hooks share handlers with kernel32

## Original Credits

- [hackerhoon](https://github.com/hackerhoon)
- [SSH9753](https://github.com/SSH9753)
- [P4P3R-HAK](https://github.com/P4P3R-HAK)
