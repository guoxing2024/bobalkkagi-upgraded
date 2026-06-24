"""
V6 Fetch Trap — .text = RW (不可执行), 捕获 Themida 跳入真实 OEP
===================================================================
Themida 解密 .text → CRC 校验 (可读 ✓) → jmp reg → FETCH TRAP! → RIP = OEP
"""

import struct

class FetchTrapOEP:
    """.text 段 Fetch Trap: 设置不可执行, 捕获首次执行尝试"""

    def __init__(self, uc, image_base=0x140000000, verbose=False):
        self.uc = uc
        self.image_base = image_base
        self.verbose = verbose
        self._real_oep = None
        self._trap_set = False
        self._text_start = 0x140001000
        self._text_size = 0x1a3550

    def setup(self):
        """设置 .text 段为 RW (不可执行)"""
        self._trap_set = True
        # Read original protection first
        from unicorn import UC_PROT_READ, UC_PROT_WRITE
        self.uc.mem_protect(self._text_start, self._text_size,
                           UC_PROT_READ | UC_PROT_WRITE)
        if self.verbose:
            print(f"  [FetchTrap] .text @ 0x{self._text_start:x} set to RW")

    def on_fetch_prot(self, uc, access, address, size, value, user_data):
        """UC_HOOK_MEM_FETCH_PROT — 尝试执行 RW 区域 → 捕获!"""
        if self._text_start <= address < self._text_start + self._text_size:
            self._real_oep = address
            if self.verbose:
                print(f"  [FetchTrap] 🎯 OEP captured: 0x{address:x}")

            # Restore .text to RWX so execution can continue
            from unicorn import UC_PROT_ALL
            uc.mem_protect(self._text_start, self._text_size, UC_PROT_ALL)

            # Read OEP code for verification
            try:
                code = bytes(uc.mem_read(address, 16))
                if self.verbose:
                    print(f"  [FetchTrap] OEP code: {code[:12].hex()}")
                    if code[:3] == b'\x48\x83\xec':
                        print(f"  [FetchTrap] ✅ sub rsp prologue confirmed")
                    elif code[0] == 0x55:
                        print(f"  [FetchTrap] ✅ push rbp prologue confirmed")
            except:
                pass

            return True  # handled
        return False

    # VirtualProtect 拦截 — 阻止授予执行权限
    @staticmethod
    def on_virtual_protect(uc, address, size, new_prot):
        """如果目标在 .text, 强制去掉 Execute 位"""
        text_start = 0x140001000
        text_end = text_start + 0x1a3550
        if text_start <= address < text_end:
            # Remove execute permission
            UC_PROT_EXEC = 8  # X
            safe_prot = new_prot & ~UC_PROT_EXEC
            if safe_prot != new_prot:
                from unicorn import UC_PROT_READ, UC_PROT_WRITE
                safe_prot = UC_PROT_READ | UC_PROT_WRITE
                uc.mem_protect(address, size, safe_prot)
                return safe_prot
        return new_prot

    @property
    def real_oep(self):
        return self._real_oep
