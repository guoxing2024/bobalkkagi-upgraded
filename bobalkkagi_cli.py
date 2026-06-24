#!/usr/bin/env python3
"""
bobalkkagi_cli.py — V6 一键脱壳命令行工具
==============================================
Bobalkkagi V6.0 Phase 4 — 全自动脱壳流水线。

用法:
  python bobalkkagi_cli.py -t sample.exe -o output.exe        # 自动模式
  python bobalkkagi_cli.py -t sample.exe --mode unicorn        # Unicorn 模式
  python bobalkkagi_cli.py -t sample.exe --forensic            # 取证模式
  python bobalkkagi_cli.py -t sample.exe --oep 0x4ed393       # 手动指定OEP
"""

import argparse
import json
import os
import sys
import time

# Ensure bobalkkagi is on path
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.dirname(_script_dir) if 'scripts' in _script_dir else _script_dir
if _project_dir not in sys.path:
    sys.path.insert(0, _project_dir)


def auto_mode(target: str, output: str, dll_path: str = None, timeout: int = 300):
    """自动决策: 先尝试 Unicorn，OEP 自动检测 + Phase3修正"""
    from bobalkkagi.agent_interface import agent_unpack
    from bobalkkagi.phase3_produce import produce_final_exe

    print(f"[bobalkkagi] Auto mode: {target}")
    t0 = time.time()

    # Step 1: Unicorn unpack
    r = json.loads(agent_unpack(
        file_path=target, dll_path=dll_path,
        backend='unicorn', force_runtime_iat=True, timeout=timeout))

    if r['status'] != 'success':
        print(f"[bobalkkagi] Unpack failed: {r.get('diagnosis', 'unknown')}")
        return None

    print(f"[bobalkkagi] Unpack OK ({time.time() - t0:.1f}s)")

    # Step 2: Phase 3 finalize (OEP fix + verify)
    out_path = r.get('output_path')
    if not out_path or not os.path.isfile(out_path):
        print("[bobalkkagi] No output file")
        return None

    final = produce_final_exe(out_path, output=output)
    elapsed = time.time() - t0
    print(f"[bobalkkagi] Done: {final} ({elapsed:.1f}s)")

    # Summary
    import pefile
    pe = pefile.PE(final)
    iat = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            iat += len(e.imports)
    print(f"[bobalkkagi] Summary: OEP=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}, "
          f"IAT={iat}, reloc={'YES' if hasattr(pe,'DIRECTORY_ENTRY_BASERELOC') else 'NO'}, "
          f"size={os.path.getsize(final):,}b")

    return final


def forensic_mode(target: str, dll_path: str = None):
    """取证模式: 记录反调试检测点，不干预"""
    from bobalkkagi.agent_interface import agent_unpack

    r = json.loads(agent_unpack(
        file_path=target, dll_path=dll_path,
        backend='unicorn', timeout=120))

    report = {
        "target": target,
        "status": r['status'],
        "oep_detected": r.get('oep'),
        "runtime_apis": r['metrics'].get('runtime_apis', 0),
        "elapsed": r['metrics'].get('elapsed_seconds', 0),
        "diagnosis": r.get('diagnosis', ''),
    }

    report_path = target + '.forensic.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[bobalkkagi] Forensic report: {report_path}")
    return report_path


def main():
    parser = argparse.ArgumentParser(description='bobalkkagi V6 — Unicorn Ultimate Unpacker')
    parser.add_argument('-t', '--target', required=True, help='Target PE file')
    parser.add_argument('-o', '--output', help='Output EXE path')
    parser.add_argument('--dll-path', help='Win10 DLL directory')
    parser.add_argument('--mode', choices=['auto','unicorn','forensic'],
                       default='auto', help='Execution mode')
    parser.add_argument('--timeout', type=int, default=300, help='Timeout (seconds)')
    parser.add_argument('--forensic', action='store_true', help='Forensic mode')

    args = parser.parse_args()

    if not os.path.isfile(args.target):
        print(f"Error: target not found: {args.target}")
        sys.exit(1)

    dll = args.dll_path or os.path.join(os.path.dirname(args.target), '..', 'win10_v1903')
    output = args.output or args.target.replace('.exe', '_bobalkkagi.exe')

    if args.forensic:
        forensic_mode(args.target, dll)
    else:
        auto_mode(args.target, output, dll, args.timeout)


if __name__ == '__main__':
    main()
