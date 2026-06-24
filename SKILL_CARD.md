# themida_auto_unpack — AI Agent Skill Card v4 (P3)

## Skill Name
themida_auto_unpack

## Description
**v4 (P3)**: Unpacks, rebuilds, AND analyzes Themida/VMProtect 3.x protected binaries. Introduces VTIL intermediate representation lifting for VM handler analysis, stub identification and repair, and structured VM analysis output for AI Agent decision-making.

Three execution backends (Unicorn/Debugger/Hybrid) + four VM analysis modes (off/detect/lift/devirt).

## Inputs

| Parameter | Type | Req | Description |
|-----------|------|-----|-------------|
| `file_path` | string | Yes | Path to protected binary |
| `backend` | string | No | "unicorn" (default), "debugger", "hybrid" |
| `mode` | string | No | "fast" (default), "deep" (hook_code) |
| `dll_path` | string | No | DLL directory. Default: "win10_v1903" |
| `crc_mode` | string | No | "safe" (default), "aggressive", "off" |
| `force_runtime_iat` | boolean | No | Runtime-only IAT. Default: false |
| `vm_mode` | string | No | **P3**: "off" (default), "detect", "lift", "devirt" |
| `vtil_target` | string | No | **P3**: "auto" (default), "themida", "vmprotect" |
| `timeout` | integer | No | Max seconds. Default: 600 |

## Outputs (JSON)

```json
{
  "status": "success",
  "stage": "complete",
  "oep": "0x1404ed393",
  "output_path": "/path/to/unpacked.exe",
  "diagnosis": "...",
  "metrics": {
    "elapsed_seconds": 12.0,
    "dll_count": 17,
    "runtime_apis": 824,
    "vm_analysis": {
      "detected": true,
      "engine": "themida",
      "entry_points": ["0x14001A300"],
      "handler_count": 45,
      "bytecode_size": 2048
    },
    "vtil_summary": {
      "lifted_handlers": 42,
      "simplified_handlers": 38,
      "api_calls_in_vm": ["VirtualAlloc", "VirtualProtect"]
    }
  },
  "warnings": [],
  "suggested_next_step": null
}
```

## vm_mode Levels

| Mode | Behavior | When |
|------|----------|------|
| `off` | No VM analysis (default) | Standard unpacking |
| `detect` | Scan for VM entries + extract handlers | Quick survey |
| `lift` | VTIL lift + simplify handlers + scan stubs | Deep analysis |
| `devirt` | Attempt semantic recovery (control flow, API calls) | Full devirtualization |

## Error Codes

| Code | Auto-Retry |
|------|------------|
| `oep_not_found` | hook_code → aggressive → debugger |
| `emulation_crash` | crc=off → safe+hookcode → debugger |
| `iat_no_imports` | force_runtime_iat=True |
| `crc_crash` | safe → off |
| `debugger_failed` | → unicorn+aggressive |
| `debugger_access_denied` | → unicorn+safe |
| `vm_stub_incomplete` | → deep-scan or manual IAT |

## Usage (Python)

```python
from bobalkkagi.agent_interface import agent_unpack
import json

# VM detect mode
r = json.loads(agent_unpack(file_path="sample.exe", vm_mode="detect"))

# Full VM analysis
r = json.loads(agent_unpack(
    file_path="sample.exe",
    backend="hybrid",
    vm_mode="lift",
    vtil_target="auto",
    force_runtime_iat=True
))
```
