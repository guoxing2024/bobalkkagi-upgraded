"""
Direct EP Execution — 跳过 Windows Loader，直捣 OEP
========================================================
Bobalkkagi V6 — 不模拟 DLL 初始化，直接从 .boot EP 执行。
Themida 壳代码自带初始化逻辑，只需拦截 API 调用即可。
"""

import struct

class DirectEPLauncher:
    """直接从 EntryPoint 执行 — 跳过 OS Loader"""

    def __init__(self, uc, image_base=0x140000000, ep_rva=0x885058,
                 stack_base=0x600000, verbose=False):
        self.uc = uc
        self.image_base = image_base
        self.ep = image_base + ep_rva
        self.stack_base = stack_base
        self.verbose = verbose
        self._real_oep = None

    def launch(self, timeout_seconds=30):
        """设置 RIP=EP, RSP=stack, 启动模拟"""
        from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP

        # 1. 设置 RIP = EntryPoint
        self.uc.reg_write(UC_X86_REG_RIP, self.ep)

        # 2. 设置 RSP = stack top
        self.uc.reg_write(UC_X86_REG_RSP, self.stack_base + 0x8000)

        # 3. .text = RW (不可执行) — Fetch Trap
        from unicorn import UC_PROT_READ, UC_PROT_WRITE
        self.uc.mem_protect(0x140001000, 0x1a4000, UC_PROT_READ | UC_PROT_WRITE)

        if self.verbose:
            print(f"  [DirectEP] RIP=0x{self.ep:x} RSP=0x{self.stack_base + 0x8000:x}")

        # 4. 注册 Fetch Trap
        def on_fetch(uc, acc, addr, sz, val, ud):
            if acc == 512:  # FETCH_PROT
                self._real_oep = addr
                print(f"\n  🎯 [DirectEP] REAL OEP: 0x{addr:x}")
                uc.mem_protect(0x140001000, 0x1a4000, 0x7)  # RWX
                return True
            return False

        def on_unmapped(uc, acc, addr, sz, val, ud):
            """自动映射缺失内存"""
            page = addr & ~0xFFF
            try:
                uc.mem_map(page, 0x1000, 0x7)  # RWX
                if self.verbose:
                    print(f"  [DirectEP] Auto-mapped 0x{page:x}")
            except:
                pass
            return True

        from unicorn import (UC_HOOK_MEM_FETCH_PROT, UC_HOOK_MEM_FETCH_UNMAPPED,
                           UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_FETCH_UNMAPPED, on_fetch)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped)

        # 5. 启动 — 直接执行 EP，没有终止地址（让它跑）
        from unicorn import UC_SECOND_SCALE
        try:
            self.uc.emu_start(self.ep, 0, timeout_seconds * UC_SECOND_SCALE)
        except Exception as e:
            if self.verbose:
                print(f"  [DirectEP] Emulation ended: {e}")

        return self._real_oep

    @property
    def real_oep(self):
        return self._real_oep
