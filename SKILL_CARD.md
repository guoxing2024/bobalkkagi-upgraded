# themida_auto_unpack — AI Agent Skill Card v3 (P2)

## Skill Name
themida_auto_unpack

## Description
Automatically unpacks and rebuilds Themida 3.x protected executables using dual execution backends — Unicorn emulation (for standard samples) or Win32 Debug API (for hardware/timing anti-debug). PE reconstruction and IAT rebuilding included.

**New in v3 (P2)**: Multi-backend execution with automatic cross-backend failover.

## Inputs
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Path to the protected binary |
| `backend` | string | No | Execution backend: "unicorn" (default), "debugger" |
| `mode` | string | No | Emulation mode: "fast" (default), "deep" (hook_code) |
| `dll_path` | string | No | DLL directory. Default: "win10_v1903" |
| `crc_mode` | string | No | CRC bypass: "safe" (default), "aggressive", "off" |
| `force_runtime_iat` | boolean | No | Runtime-only IAT mode. Default: false |
| `timeout` | integer | No | Max execution time in seconds. Default: 600 |

## Outputs (JSON)
```json
{
  "status": "success",
  "stage": "complete",
  "error_code": null,
  "backend_used": "unicorn",
  "diagnosis": "Full IAT rebuilt: 842 imports across 17 DLLs.",
  "output_path": "/path/to/unpacked.exe",
  "dump_path": "/path/to/unpacked.dump",
  "oep": "0x1404ed393",
  "metrics": {
    "api_calls": 842, "crc_patches": 15,
    "dll_count": 17, "runtime_apis": 824,
    "elapsed_seconds": 8.5
  },
  "warnings": [],
  "suggested_next_step": null
}
```

## Error Codes
| Code | Meaning | Auto-Retry |
|------|---------|------------|
| `file_not_found` | Target binary missing | — |
| `emulation_crash` | Unicorn crashed | off→safe+hook_code→debugger |
| `oep_not_found` | Could not find OEP | hook_code→aggressive→debugger |
| `iat_no_imports` | No imports recovered | force_runtime_iat=True |
| `crc_crash` | CRC bypass crash | safe→off |
| `debugger_failed` | Debugger failed | fallback→unicorn+aggressive |
| `debugger_access_denied` | Needs admin | fallback→unicorn+safe |
| `timeout` | Pipeline timed out | — |

## RETRY_STRATEGIES (P1+P2 Cross-Backend)
| Error | Strategy 1 | Strategy 2 | P2: Backend Failover |
|-------|-----------|------------|----------------------|
| `oep_not_found` | hook_code | aggressive | → debugger |
| `emulation_crash` | crc=off | safe+hook_code | → debugger |
| `iat_no_imports` | force_runtime_iat | — | — |
| `crc_crash` | safe | off | — |
| `debugger_failed` | — | — | → unicorn+aggressive |
| `debugger_access_denied` | — | — | → unicorn+safe |

## Backend Comparison
| Feature | Unicorn | Debugger |
|---------|---------|----------|
| Hardware anti-debug | ❌ | ✅ |
| Timing detection | ❌ | ✅ |
| Multi-threading | ❌ | ✅ |
| Speed | ~9s | ~30-60s |
| Requires admin | No | Yes (for ScyllaHide) |
| CRC bypass | Capstone patch | NOP (real exec) |

## Usage (Python)
```python
from bobalkkagi.agent_interface import agent_unpack
import json

# Standard unicorn unpack
result = json.loads(agent_unpack(file_path="protected.exe"))

# Debugger backend for hardware-protected samples
result = json.loads(agent_unpack(file_path="protected.exe", backend="debugger"))

# Full options
result = json.loads(agent_unpack(
    file_path="protected.exe",
    backend="unicorn",         # or "debugger"
    mode="fast",               # or "deep" (hook_code)
    crc_mode="safe",           # or "aggressive", "off"
    force_runtime_iat=True     # for obfuscated imports
))
```
