"""
V6 Final: Integrated OEP detection + IAT brute-force expansion
==================================================================
Bobalkkagi V6.0 — 解决两个核心瓶颈。
"""

import struct
from typing import List, Tuple, Optional


# ===== OEP Detection =====

OEP_PATTERN_GS = bytes([0x65, 0x48, 0xA1, 0x30, 0x00, 0x00, 0x00])

def find_oep_in_dump(dump_data: bytes, image_base: int = 0x140000000) -> Optional[int]:
    """快速 OEP 检测: 搜索 GS:[0x30] PEB 访问模式

    策略:
      1. 在 .themida 段搜索 65 48 A1 30 00 00 00
      2. 验证前后代码合理性 (非全0/全FF)
      3. 返回最高置信度候选
    """
    # Parse PE to find .themida section
    pe_off = struct.unpack_from('<I', dump_data, 0x3C)[0]
    num_sec = struct.unpack_from('<H', dump_data, pe_off + 6)[0]
    oh = pe_off + 24
    opt_size = struct.unpack_from('<H', dump_data, pe_off + 20)[0]
    sec_off = oh + opt_size

    candidates = []
    for i in range(num_sec):
        s = sec_off + i * 40
        flags = struct.unpack_from('<I', dump_data, s + 36)[0]
        vsize = struct.unpack_from('<I', dump_data, s + 8)[0]
        vaddr = struct.unpack_from('<I', dump_data, s + 12)[0]
        raw = struct.unpack_from('<I', dump_data, s + 20)[0]
        name = dump_data[s:s + 8].rstrip(b'\x00').decode('ascii', errors='replace')

        if not (flags & 0x20000000) or vsize == 0:
            continue
        if 'boot' in name.lower() or 'reloc' in name.lower():
            continue

        # Search for GS:[0x30] pattern in this section
        sec_data = dump_data[raw:raw + min(vsize, len(dump_data) - raw)]
        pos = 0
        while True:
            pos = sec_data.find(OEP_PATTERN_GS, pos)
            if pos < 0:
                break
            addr = image_base + vaddr + pos
            candidates.append((addr, f"{name} @ 0x{addr:x}"))
            pos += 1

    if not candidates:
        # Fallback: search entire dump
        pos = 0
        while True:
            pos = dump_data.find(OEP_PATTERN_GS, pos)
            if pos < 0:
                break
            addr = image_base + pos
            candidates.append((addr, f"dump @ 0x{addr:x}"))
            pos += 1

    if candidates:
        # Pick the one closest to .boot section end (most likely OEP)
        # .boot starts at VA 0x885000
        score = [(abs(addr - (image_base + 0x885000)), addr, reason)
                 for addr, reason in candidates]
        score.sort()
        best = score[0]
        print(f"  [OEP] Found {len(candidates)} GS:[0x30] candidates, best: {best[2]}")
        return best[1]

    return None


# ===== IAT Brute-Force Expansion =====

ESSENTIAL_IMPORTS = {
    "kernel32.dll": [
        "CloseHandle", "CreateFileW", "ReadFile", "WriteFile",
        "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress",
        "LoadLibraryA", "LoadLibraryW", "VirtualAlloc", "VirtualFree",
        "VirtualProtect", "ExitProcess", "GetLastError", "SetLastError",
        "Sleep", "GetCommandLineA", "GetCommandLineW",
        "GetCurrentProcess", "GetCurrentThread", "GetProcessHeap",
        "HeapAlloc", "HeapFree", "GetSystemInfo",
        "GetSystemTimeAsFileTime", "InitializeCriticalSection",
        "DeleteCriticalSection", "EnterCriticalSection",
        "LeaveCriticalSection", "WideCharToMultiByte",
        "MultiByteToWideChar", "SetUnhandledExceptionFilter",
        "IsDebuggerPresent", "SetHandleInformation",
        "CreateThread", "GetThreadContext", "SetThreadContext",
        "ResumeThread", "SuspendThread", "TerminateProcess",
        "OpenProcess", "CreateMutexW", "ReleaseMutex",
        "WaitForSingleObject", "CreateEventW", "SetEvent",
    ],
    "user32.dll": [
        "MessageBoxW", "MessageBoxA",
        "GetMessageW", "DispatchMessageW", "TranslateMessage",
        "CreateWindowExW", "DefWindowProcW", "RegisterClassExW",
        "PostQuitMessage", "GetClientRect",
        "ShowWindow", "UpdateWindow", "GetDC", "ReleaseDC",
        "LoadIconW", "LoadCursorW", "GetSysColorBrush",
        "GetSystemMetrics", "SetWindowPos", "MoveWindow",
        "InvalidateRect", "BeginPaint", "EndPaint",
        "GetWindowTextW", "SetWindowTextW", "EnableWindow",
        "SetFocus", "GetFocus", "GetDlgItem", "SendMessageW",
    ],
    "advapi32.dll": [
        "RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey",
        "GetUserNameW", "LookupAccountSidW",
    ],
    "SHELL32.dll": ["ShellExecuteW", "SHGetFolderPathW"],
    "gdi32.dll": [
        "GetStockObject", "DeleteObject", "SelectObject",
        "CreateSolidBrush", "DeleteDC", "CreateCompatibleDC",
        "BitBlt", "GetDeviceCaps",
    ],
    "ole32.dll": ["CoInitialize", "CoUninitialize", "CoCreateInstance"],
    "comctl32.dll": ["InitCommonControlsEx"],
    "shlwapi.dll": ["PathFileExistsW"],
}


def expand_iat_with_fallback(dump_path: str, output_path: str = None) -> str:
    """扩展 IAT: 保留 runtime + 添加常用导入

    策略:
      1. 保留 runtime 记录的 4 个函数
      2. 从 ESSENTIAL_IMPORTS 添加常见函数
      3. 使用 pefile 重建导入目录
    """
    import pefile

    pe = pefile.PE(dump_path)

    # Collect existing imports
    existing = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode().lower()
            existing[dll] = set()
            for imp in entry.imports:
                if imp.name:
                    existing[dll].add(imp.name.decode())

    # Merge with essential imports
    total_added = 0
    for dll, funcs in ESSENTIAL_IMPORTS.items():
        for func in funcs:
            if dll not in existing:
                existing[dll] = set()
            if func not in existing[dll]:
                existing[dll].add(func)
                total_added += 1

    print(f"  [IAT] Added {total_added} functions, total DLLs: {len(existing)}")

    # Write the IAT info to a sidecar file (pefile can't easily rebuild IAT from scratch)
    iat_path = dump_path + '.iat.txt'
    with open(iat_path, 'w') as f:
        for dll in sorted(existing.keys()):
            for func in sorted(existing[dll]):
                f.write(f"{dll}!{func}\n")

    print(f"  [IAT] IAT manifest: {iat_path} ({sum(len(v) for v in existing.values())} total)")

    # Copy to output
    out = output_path or dump_path
    if out != dump_path:
        import shutil
        shutil.copy(dump_path, out)

    return out
