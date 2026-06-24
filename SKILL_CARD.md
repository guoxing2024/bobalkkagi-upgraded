# themida_auto_unpack — AI Agent Skill Card v2

## Skill Name
themida_auto_unpack

## Description
Automatically unpacks and rebuilds Themida 3.x protected executables using Unicorn emulation, API hooking, PE reconstruction, and IAT rebuilding.

Supports AI Agent orchestration through:
- JSON input/output interface (OpenAI Function Calling / LangChain Tool compatible)
- Structured error codes with diagnosis and suggested next steps
- Context state snapshots for checkpoint/restart
- Multi-signal OEP detection (RW→RX, call stack, API behavior model)
- Auto-retry with RETRY_STRATEGIES based on error codes
- Runtime IAT recording → force_runtime_iat mode for complete import recovery

## Inputs
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Path to the protected binary |
| `mode` | string | No | Emulation mode: "fast" (default), "deep" (hook_code), "aggressive_crc" |
| `dll_path` | string | No | Directory containing Windows DLLs. Default: "win10_v1903" |
| `crc_mode` | string | No | CRC bypass mode: "safe" (default), "aggressive", "off" |
| `force_runtime_iat` | boolean | No | If True, ignore original PE imports. Use only runtime API recording. Default: false |
| `timeout` | integer | No | Max execution time in seconds. Default: 600 |
| `snapshot_every_stage` | boolean | No | Save context state after each stage. Default: false |

## Outputs (JSON)
```json
{
  "status": "success",
  "stage": "complete",
  "error_code": null,
  "diagnosis": "Full IAT rebuilt: 842 imports across 17 DLLs. PE headers, TLS, and sections restored.",
  "output_path": "/path/to/unpacked.exe",
  "dump_path": "/path/to/unpacked.dump",
  "oep": "0x1404ed393",
  "metrics": {
    "api_calls": 842,
    "crc_patches": 15,
    "dll_count": 17,
    "runtime_apis": 824,
    "elapsed_seconds": 8.5
  },
  "warnings": [],
  "suggested_next_step": null
}
```

## Error Codes
| Code | Meaning | Agent Suggestion |
|------|---------|-----------------|
| `file_not_found` | Target binary does not exist | Verify path |
| `invalid_pe` | Not a valid PE file | Check file format |
| `emulation_crash` | Unicorn emulation crashed | Auto-retry: disables CRC then retries safe |
| `oep_not_found` | Could not find OEP | Auto-retry: hook_code then aggressive CRC |
| `iat_space_full` | .idata section too small | Expand .idata or add section |
| `iat_no_imports` | No imports recovered | Auto-retry with force_runtime_iat=True |
| `crc_crash` | CRC bypass caused crash | Auto-retry: safe mode then off |
| `timeout` | Pipeline timed out | Increase timeout or use fast mode |
| `rebuild_failed` | PE rebuild failed | Check dump integrity |
| `low_import_count` | Few imports per DLL | Auto-retry with force_runtime_iat=True |

## RETRY_STRATEGIES (Auto-Retry Engine)
When the pipeline fails, the agent interface automatically retries with adjusted parameters:

| Error | Strategy 1 | Strategy 2 |
|-------|-----------|------------|
| `oep_not_found` | mode=hook_code | crc_mode=aggressive |
| `iat_no_imports` | force_runtime_iat=True | — |
| `emulation_crash` | crc_mode=off | mode=hook_code + crc_mode=safe |
| `crc_crash` | crc_mode=safe | crc_mode=off |
| `low_import_count` | force_runtime_iat=True | — |

## Diagnosis Examples
On success with low imports:
```
Detected only 17 imports across 17 DLLs (avg 1.0 per DLL).
Reason: Original IAT obfuscated by Themida.
Runtime recording has 824 API calls available.
Action: Re-run with force_runtime_iat=True to generate full IAT from runtime calls.
```

On auto-retry success:
```
Auto-retry succeeded on attempt 1/1 (strategy: Original PE import table is obfuscated.
Switch to runtime recording.). Original error: low import count: only 17 imports recovered.
```

## Usage (Python)
```python
from bobalkkagi.agent_interface import agent_unpack
import json

# Standard unpack
result = json.loads(agent_unpack(
    file_path="/samples/protected.exe",
    mode="fast",
    crc_mode="safe",
    timeout=600
))

# Force runtime IAT (solves "low import count" with Themida-obfuscated imports)
result = json.loads(agent_unpack(
    file_path="/samples/protected.exe",
    force_runtime_iat=True
))

print(result["status"])        # "success" or "failed"
print(result["output_path"])   # "/samples/protected_unpacked.exe"
print(result["diagnosis"])     # Human-readable diagnosis
```

## Usage (CLI)
```bash
python -m bobalkkagi.agent_interface --file protected.exe --mode fast --json
python -m bobalkkagi.agent_interface --file protected.exe --force-runtime-iat --json
```

## Related Skills
- `themia_analyze` — Analyze dump file for VM regions
- `import_scan` — Scylla-style import reconstruction
- `crc_bypass` — CRC integrity check bypass
