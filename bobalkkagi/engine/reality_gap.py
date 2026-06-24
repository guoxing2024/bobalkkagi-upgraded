"""
V9 Reality Gap Analyzer — 真实 Windows vs Unicorn 环境差异
==============================================================
Bobalkkagi V9.0 — 为什么真实程序继续而 Unicorn 固定循环？

对照真实 Windows 进程的 PEB/TEB/KUSER 结构，
找出 Unicorn Fake Environment 中的关键缺失。
"""

import struct
from typing import List, Tuple


# 真实 Windows 10 x64 进程的 PEB 关键字段默认值
# (从 WinDbg dt nt!_PEB 获取)
PEB_EXPECTED = {
    # offset: (name, expected_value_or_flag)
    0x00: ("InheritedAddressSpace", 0),
    0x01: ("ReadImageFileExecOptions", 0),
    0x02: ("BeingDebugged", 0, "FALSE — 反调试关键"),
    0x03: ("BitField", None, "check ImageDispatch/IAT flags"),
    0x10: ("ImageBaseAddress", 0x140000000, "指向自己 PE 镜像"),
    0x18: ("Ldr", None, "NOT NULL — PEB_LDR_DATA 指针"),
    0x20: ("ProcessParameters", None, "进程启动参数"),
    0x30: ("ProcessHeap", None, "堆句柄"),
    0x60: ("AtlThunkSListPtr", 0),
    0xBC: ("NtGlobalFlag", 0, "FALSE — 反调试关键"),
    0xC0: ("CriticalSectionTimeout", None),
    0xC8: ("HeapSegmentReserve", None),
    0xD0: ("HeapSegmentCommit", None),
    0xD8: ("HeapDeCommitTotalFreeThreshold", None),
    0xE0: ("HeapDeCommitFreeBlockThreshold", None),
    0xE8: ("NumberOfHeaps", None),
    0xEC: ("MaximumNumberOfHeaps", None),
    0x118: ("OSMajorVersion", 10),
    0x11C: ("OSMinorVersion", 0),
    0x120: ("OSBuildNumber", 18362, "Win10 1903"),
    0x124: ("OSPlatformId", 2, "VER_PLATFORM_WIN32_NT"),
    0x200: ("NumberOfProcessors", None),
    0x208: ("NtGlobalFlag2", 0),
    0x370: ("LoaderLock", None),
    0x388: ("ProcessSecurityCapabilities", None),
    0x3F8: ("ProcessDebugFlags", None, "0 = debugger present"),
    0x3FC: ("ProcessDebugFlags.SpareBits", 0),
}

# TEB 关键字段
TEB_EXPECTED = {
    0x00: ("ExceptionList", None, "SEH Chain — NOT NULL"),
    0x08: ("StackBase", None, "栈底"),
    0x10: ("StackLimit", None, "栈顶"),
    0x30: ("ProcessEnvironmentBlock", None, "指向 PEB"),
    0x60: ("WinSockData", None),
    0x1750: ("SameTebFlags", None),
    # GS:[0x30] 读 PEB: TEB+0x60
}

# KUSER_SHARED_DATA 关键字段 (0x7FFE0000)
KUSER_EXPECTED = {
    0x2D4: ("KdDebuggerEnabled", 0, "TRUE=内核调试器"),
    0x2D5: ("KdDebuggerNotPresent", 1, "TRUE=无内核调试器"),
    0x2D8: ("ActiveProcessorCount", None),
    0x320: ("TickCountLow", None, "递增"),
    0x324: ("TickCountMultiplier", None),
}


class RealityGapAnalyzer:
    """V9: 环境缺口分析器"""

    def __init__(self, uc):
        self.uc = uc
        self._gaps: List[str] = []

    def check_peb(self, peb_base: int) -> List[str]:
        """检查 PEB 关键字段"""
        issues = []
        try:
            data = bytes(self.uc.mem_read(peb_base, 0x400))
        except:
            return ["PEB unreadable at 0x{peb_base:x}"]

        for offset, info in PEB_EXPECTED.items():
            name = info[0]
            expected = info[1]
            desc = info[2] if len(info) > 2 else None

            if offset >= len(data):
                continue

            actual = None
            if offset + 8 <= len(data):
                actual = struct.unpack_from('<Q', data, offset)[0]
            elif offset + 4 <= len(data):
                actual = struct.unpack_from('<I', data, offset)[0]
            else:
                actual = data[offset]

            if expected is not None and actual != expected:
                tag = f"⚠ {desc}" if desc else ""
                issues.append(f"PEB+0x{offset:x} {name}: 0x{actual:x} (expected 0x{expected:x}) {tag}")
            elif expected is None and actual == 0 and desc:
                issues.append(f"PEB+0x{offset:x} {name}: NULL (may be OK) — {desc}")

        return issues

    def check_teb(self, teb_base: int, peb_base: int) -> List[str]:
        """检查 TEB 关键字段"""
        issues = []
        try:
            data = bytes(self.uc.mem_read(teb_base, 0x200))
        except:
            return ["TEB unreadable"]

        # Check PEB pointer
        peb_ptr = struct.unpack_from('<Q', data, 0x60)[0]
        if peb_ptr != peb_base:
            issues.append(f"TEB+0x60 PEB ptr: 0x{peb_ptr:x} (expected 0x{peb_base:x})")

        # Check GS:[0x30] path
        gs_30 = struct.unpack_from('<Q', data, 0x30)[0]
        if gs_30 != peb_base:
            issues.append(f"TEB+0x30: 0x{gs_30:x} (expected PEB=0x{peb_base:x})")

        # ExceptionList
        exc_list = struct.unpack_from('<Q', data, 0x00)[0]
        if exc_list == 0 or exc_list == 0xFFFFFFFFFFFFFFFF:
            issues.append(f"TEB+0x00 ExceptionList: {hex(exc_list)} — SEH chain missing")

        return issues

    def check_kuser(self) -> List[str]:
        """检查 KUSER_SHARED_DATA"""
        issues = []
        try:
            data = bytes(self.uc.mem_read(0x7FFE0000, 0x400))
        except:
            return ["KUSER_SHARED_DATA unreadable at 0x7FFE0000"]

        kd_debugger = data[0x2D4]
        kd_not_present = data[0x2D5]
        if kd_debugger != 0:
            issues.append(f"KUSER.KdDebuggerEnabled={kd_debugger} (should be 0)")
        if kd_not_present != 1:
            issues.append(f"KUSER.KdDebuggerNotPresent={kd_not_present} (should be 1)")

        return issues

    def analyze(self, peb_base: int, teb_base: int) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("V9 Reality Gap Analysis")
        lines.append("=" * 60)

        peb_issues = self.check_peb(peb_base)
        teb_issues = self.check_teb(teb_base, peb_base)
        kuser_issues = self.check_kuser()

        all_issues = peb_issues + teb_issues + kuser_issues

        if all_issues:
            lines.append(f"\nTotal gaps found: {len(all_issues)}")
            for issue in all_issues:
                lines.append(f"  {issue}")
        else:
            lines.append(f"\nNo gaps detected — environment appears consistent")

        # Summary
        lines.append(f"\n--- Gap Categories ---")
        categories = {"PEB": peb_issues, "TEB": teb_issues, "KUSER": kuser_issues}
        for cat, issues in categories.items():
            lines.append(f"  {cat}: {len(issues)} issues")

        return "\n".join(lines)
