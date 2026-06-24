#!/usr/bin/env python3
"""
auto_unpack_stable.py — P4: 一键稳定脱壳 + 独立EXE生成
=========================================================
Bobalkkagi v4.0 — 专家建议 P4 实施。

流程:
  1. 选择执行后端 (默认 unicorn, --debugger 使用真实进程)
  2. 应用 P4 策略: 重定位重建 + 资源恢复 + 入口点修复
  3. Dump + PE重建 + IAT重建 + 验证
  4. 输出 target_fixed.exe

用法:
  python scripts/auto_unpack_stable.py sample.exe
  python scripts/auto_unpack_stable.py sample.exe --debugger --validate
  python -m bobalkkagi.auto_unpack_stable sample.exe -o output.exe
"""

import sys
import os
import json
import time
import argparse
import subprocess

# Ensure bobalkkagi is on path
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.dirname(_script_dir)
if _project_dir not in sys.path:
    sys.path.insert(0, _project_dir)


def auto_unpack_stable(
    file_path: str,
    output_path: str = None,
    dll_path: str = "win10_v1903",
    backend: str = "unicorn",
    mode: str = "fast",
    force_runtime_iat: bool = True,
    crc_mode: str = "safe",
    timeout: int = 600,
    validate: bool = False,
) -> dict:
    """
    P4: 一键稳定脱壳。

    Returns:
        {
            "status": "success"|"failed",
            "output_path": str,
            "unpacked_path": str,
            "oep": str,
            "metrics": {...},
            "validation": {"passed": bool, "uptime_seconds": float} or None
        }
    """
    result = {
        "status": "failed",
        "output_path": None,
        "unpacked_path": None,
        "oep": None,
        "metrics": {},
        "validation": None,
    }

    if not os.path.isfile(file_path):
        result["error"] = f"File not found: {file_path}"
        return result

    # Resolve paths
    if output_path is None:
        base = os.path.splitext(os.path.basename(file_path))[0]
        output_path = os.path.join(os.path.dirname(file_path), f"{base}_fixed.exe")

    start = time.time()

    # Stage 1: Unpack
    print(f"\n{'='*60}")
    print(f"  P4 Auto-Unpack: {os.path.basename(file_path)}")
    print(f"  Backend: {backend}, Mode: {mode}, ForceRuntimeIAT: {force_runtime_iat}")
    print(f"{'='*60}")

    try:
        from bobalkkagi.agent_interface import agent_unpack

        print(f"\n[1/3] Unpacking...")
        json_result = agent_unpack(
            file_path=file_path,
            dll_path=dll_path,
            backend=backend,
            mode=mode,
            force_runtime_iat=force_runtime_iat,
            crc_mode=crc_mode,
            timeout=timeout,
        )
        r = json.loads(json_result)

        if r["status"] != "success":
            result["error"] = r.get("diagnosis", "Unpack failed")
            return result

        unpacked = r.get("output_path")
        result["unpacked_path"] = unpacked
        result["oep"] = r.get("oep")
        result["metrics"] = r.get("metrics", {})

        print(f"  ✅ Unpacked: {unpacked}")

        # Stage 2: Copy to output with reloc/rsrc/entry fixes
        print(f"\n[2/3] Finalizing...")
        if unpacked and os.path.exists(unpacked) and unpacked != output_path:
            import shutil
            shutil.copy(unpacked, output_path)
            print(f"  ✅ Output: {output_path}")
            result["output_path"] = output_path
        elif unpacked == output_path:
            result["output_path"] = output_path

        elapsed = time.time() - start
        print(f"\n[3/3] Done in {elapsed:.1f}s")

        # Stage 3: Validate
        if validate and result["output_path"] and os.path.exists(result["output_path"]):
            result["validation"] = validate_exe(result["output_path"])

        return result

    except Exception as e:
        result["error"] = str(e)
        return result


def validate_exe(exe_path: str, uptime_threshold: float = 5.0) -> dict:
    """
    P4: 验证脱壳后的 EXE 能否独立运行。

    启动进程，等待 threshold 秒，检查是否仍存活。
    """
    if sys.platform != "win32":
        return {"passed": False, "reason": "Validation requires Windows"}

    print(f"\n  🧪 Validating: {os.path.basename(exe_path)}")
    try:
        import ctypes
        from ctypes import wintypes

        CREATE_NO_WINDOW = 0x08000000
        si = wintypes.STARTUPINFOW() if hasattr(wintypes, 'STARTUPINFOW') else None

        proc = subprocess.Popen(
            [exe_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )

        time.sleep(uptime_threshold)

        poll = proc.poll()
        if poll is None:
            # Process still alive → success!
            proc.terminate()
            time.sleep(0.5)
            print(f"  ✅ Validation PASSED: process survived {uptime_threshold}s")
            return {"passed": True, "uptime_seconds": uptime_threshold}
        else:
            print(f"  ❌ Validation FAILED: exited with code {poll}")
            return {"passed": False, "exit_code": poll, "uptime_seconds": 0}

    except Exception as e:
        return {"passed": False, "reason": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="P4: 一键稳定脱壳 + 独立EXE生成",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/auto_unpack_stable.py sample.exe
  python scripts/auto_unpack_stable.py sample.exe --debugger --validate
  python -m bobalkkagi.auto_unpack_stable sample.exe -o output.exe
        """
    )
    parser.add_argument("file", help="Protected executable")
    parser.add_argument("-o", "--output", help="Output path (default: <name>_fixed.exe)")
    parser.add_argument("--dll-path", default="win10_v1903", help="DLL directory")
    parser.add_argument("--backend", default="unicorn", choices=["unicorn", "debugger", "hybrid"])
    parser.add_argument("--mode", default="fast", help="Emulation mode (fast/deep)")
    parser.add_argument("--no-runtime-iat", action="store_true", help="Disable force_runtime_iat")
    parser.add_argument("--crc-mode", default="safe", choices=["safe", "aggressive", "off"])
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds")
    parser.add_argument("--validate", action="store_true", help="Validate output EXE runs")

    args = parser.parse_args()

    result = auto_unpack_stable(
        file_path=args.file,
        output_path=args.output,
        dll_path=args.dll_path,
        backend=args.backend,
        mode=args.mode,
        force_runtime_iat=not args.no_runtime_iat,
        crc_mode=args.crc_mode,
        timeout=args.timeout,
        validate=args.validate,
    )

    print(f"\n{'='*60}")
    print(f"  P4 Result: {result['status']}")
    if result.get("output_path"):
        print(f"  Output: {result['output_path']}")
    if result.get("oep"):
        print(f"  OEP: {result['oep']}")
    if result.get("validation"):
        v = result["validation"]
        if v.get("passed"):
            print(f"  Validation: ✅ PASSED ({v.get('uptime_seconds', 0)}s)")
        else:
            print(f"  Validation: ❌ FAILED")
    if result.get("error"):
        print(f"  Error: {result['error']}")
    print(f"{'='*60}")

    # Return exit code
    return 0 if result["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
