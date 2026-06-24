"""
V6 User-Mode API Stub — Phase 1 Task 3: 用户态反调试函数伪返回
=================================================================
Bobalkkagi V6.0 — 对非 syscall 的反调试 API (IsDebuggerPresent 等)
在 Unicorn 中替换为自定义 Stub，拦截后直接返回"无调试器"。

工作原理:
  1. 识别目标 DLL 中的反调试函数 IAT 条目
  2. 将 IAT slot 值替换为 Stub 区域地址
  3. UC_HOOK_CODE 捕获 Stub 调用
  4. 写入 RAX=0, 调整 RSP (模拟 RET), 跳回调用者

处理函数:
  - kernel32!IsDebuggerPresent
  - kernel32!CheckRemoteDebuggerPresent
  - ntdll!RtlQueryProcessDebugInformation
  - 以及其他常见的用户态检测函数
"""

import struct
from typing import Set, Tuple

try:
    from unicorn import UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RIP, UC_X86_REG_RSP
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False


# 需要 stub 的反调试函数列表
ANTI_DEBUG_FUNCTIONS = {
    "kernel32.dll": {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
    },
    "ntdll.dll": {
        "RtlQueryProcessDebugInformation",
    },
}

# Stub 区域的固定地址 (Unicorn 内存 — 避开所有已知区域)
STUB_BASE = 0x80000000  # 低地址, 不冲突
STUB_SIZE = 0x10000
NEXT_STUB_OFFSET = 0


class UserModeStubber:
    """V6: 用户态反调试 API Stub 管理器"""

    def __init__(self, uc: 'Uc', verbose: bool = False):
        self.uc = uc
        self.verbose = verbose
        self._stub_map: dict = {}  # {stub_addr: (dll, func_name)}
        self._next_stub = STUB_BASE

    def setup(self) -> bool:
        """分配 Stub 区域并注册 UC_HOOK_CODE"""
        if not HAS_UNICORN:
            return False

        from unicorn import UC_PROT_ALL
        self.uc.mem_map(STUB_BASE, STUB_SIZE, UC_PROT_ALL)

        # Register code hook
        self.uc.hook_add(UC_HOOK_CODE, self._on_stub_call, None,
                         STUB_BASE, STUB_BASE + STUB_SIZE)

        if self.verbose:
            print(f"  [Stubber] Stub region: 0x{STUB_BASE:x} - 0x{STUB_BASE + STUB_SIZE:x}")
        return True

    def patch_iat(self, dll_name: str, dll_base: int, iat_slots: dict):
        """遍历 IAT slot，将反调试函数替换为 Stub

        Args:
            dll_name: DLL 名称 (如 "kernel32.dll")
            dll_base: DLL 在 Unicorn 中的加载基址
            iat_slots: {slot_addr: func_name} — IAT 槽位映射
        """
        targets = ANTI_DEBUG_FUNCTIONS.get(dll_name, set())
        if not targets:
            return 0

        patched = 0
        for slot_addr, func_name in iat_slots.items():
            if func_name in targets:
                stub_addr = self._allocate_stub(func_name)
                # Replace IAT value with stub address
                self.uc.mem_write(slot_addr, struct.pack('<Q', stub_addr))
                self._stub_map[stub_addr] = (dll_name, func_name)
                patched += 1
                if self.verbose:
                    print(f"  [Stubber] Patched {dll_name}!{func_name} @ 0x{slot_addr:x} -> stub 0x{stub_addr:x}")

        return patched

    def _allocate_stub(self, func_name: str) -> int:
        """分配一个唯一 Stub 地址"""
        addr = self._next_stub
        # 每个 stub 16 字节 (留空间写 shellcode)
        self._next_stub += 16
        if self._next_stub >= STUB_BASE + STUB_SIZE:
            self._next_stub = STUB_BASE  # wrap (shouldn't happen)
        return addr

    def _on_stub_call(self, uc, address, size, user_data):
        """Stub 被调用时触发 — 模拟函数返回"""
        info = self._stub_map.get(address)
        if not info:
            return

        dll, func = info

        if func == "IsDebuggerPresent":
            # Return 0 (FALSE) — no debugger
            uc.reg_write(UC_X86_REG_RAX, 0)

        elif func == "CheckRemoteDebuggerPresent":
            # RCX = output pointer → write 0 (FALSE)
            rcx = uc.reg_write(UC_X86_REG_RCX, 0)
            # Actually read RCX first
            rcx = 0
            for reg_name in [UC_X86_REG_RCX]:
                rcx = uc.reg_read(reg_name)
                break
            # Re-read properly
            rcx_val = 0
            try:
                rcx_val = uc.reg_read(UC_X86_REG_RCX)
            except:
                pass
            if rcx_val:
                uc.mem_write(rcx_val, struct.pack('<I', 0))
            uc.reg_write(UC_X86_REG_RAX, 0)  # return TRUE (success)

        elif func == "RtlQueryProcessDebugInformation":
            # Return STATUS_NOT_SUPPORTED
            uc.reg_write(UC_X86_REG_RAX, 0xC00000BB)

        # Simulate RET: RSP += 8 (pop return address), RIP = [old RSP]
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_addr_bytes = uc.mem_read(rsp, 8)
        ret_addr = struct.unpack('<Q', bytes(ret_addr_bytes))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)

        if self.verbose:
            print(f"  [Stubber] {dll}!{func} → returned")


def install_user_mode_stubs(uc: 'Uc', verbose: bool = False) -> UserModeStubber:
    """便捷函数: 安装用户态 Stub"""
    stubber = UserModeStubber(uc, verbose)
    stubber.setup()
    return stubber
