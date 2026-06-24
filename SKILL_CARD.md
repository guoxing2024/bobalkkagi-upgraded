# themida_auto_unpack — AI Agent Skill Card

## Skill Name
themida_auto_unpack

## Description
Automatically unpacks and rebuilds Themida 3.x protected executables using Unicorn emulation, API hooking, PE reconstruction, and IAT rebuilding.

Supports AI Agent orchestration through:
- JSON input/output interface (OpenAI Function Calling / LangChain Tool compatible)
- Structured error codes with diagnosis and suggested next steps
- Context state snapshots for checkpoint/restart
- Multi-signal OEP detection (RW→RX, call stack, API behavior model)

## Inputs
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Path to the protected binary |
| `mode` | string | No | Emulation mode: "fast" (default), "deep" (hook_code), "aggressive_crc" |
| `dll_path` | string | No | Directory containing Windows DLLs. Default: "win10_v1903" |
| `crc_mode` | string | No | CRC bypass mode: "safe" (default), "aggressive", "off" |
| `timeout` | integer | No | Max execution time in seconds. Default: 600 |
| `snapshot_every_stage` | boolean | No | Save context state after each stage. Default: false |

## Outputs (JSON)
```json
{
  "status": "success",
  "stage": "complete",
  "error_code": null,
  "diagnosis": "Detected Themida 3.x with moderate virtualisation",
  "output_path": "/path/to/unpacked.exe",
  "dump_path": "/path/to/unpacked.dump",
  "oep": "0x1404ed393",
  "metrics": {
    "api_calls": 842,
    "crc_patches": 15,
    "dll_count": 17,
    "runtime_apis": 24,
    "elapsed_seconds": 8.5
  },
  "warnings": ["low_import_count"],
  "suggested_next_step": "Use Scylla to manually scan the dump for additional imports"
}
```

## Error Codes
| Code | Meaning | Agent Suggestion |
|------|---------|-----------------|
| `file_not_found` | Target binary does not exist | Verify path |
| `invalid_pe` | Not a valid PE file | Check file format |
| `emulation_crash` | Unicorn emulation crashed | Try different emulation mode |
| `oep_not_found` | Could not find OEP | Try aggressive CRC bypass |
| `iat_space_full` | .idata section too small | Expand .idata or add section |
| `iat_no_imports` | No imports recovered | Use Scylla for manual scan |
| `timeout` | Pipeline timed out | Increase timeout or use fast mode |
| `rebuild_failed` | PE rebuild failed | Check dump integrity |

## Usage (Python)
```python
from bobalkkagi.agent_interface import agent_unpack
import json

result = json.loads(agent_unpack(
    file_path="/samples/protected.exe",
    mode="fast",
    crc_mode="safe",
    timeout=600
))

print(result["status"])        # "success" or "failed"
print(result["output_path"])   # "/samples/protected_unpacked.exe"
print(result["diagnosis"])     # Human-readable diagnosis
```

## Usage (CLI)
```bash
python -m bobalkkagi.agent_interface --file protected.exe --mode fast --json
```

## Related Skills
- `themia_analyze` — Analyze dump file for VM regions
- `import_scan` — Scylla-style import reconstruction
- `crc_bypass` — CRC integrity check bypass
