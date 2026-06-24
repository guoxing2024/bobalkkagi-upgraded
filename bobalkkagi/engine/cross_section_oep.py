"""
Cross-Section OEP Detector — V6: 跨段跳转监控
=================================================
Themida 在 .themida/.boot 运行，OEP 在原始 .text。
当 RIP 从 .themida 跳入 .text → 暂停 = OEP。
"""

class CrossSectionOEP:
    """监控跨段跳转，捕获真实 OEP"""
    
    def __init__(self, uc, image_base=0x140000000, verbose=False):
        self.uc = uc
        self.image_base = image_base
        self.verbose = verbose
        self._real_oep = None
        self._prev_section = None  # 'themida'|'boot'|'text'|'other'
        self._count = 0
        self._max_count = 500_000  # safety limit

    def on_code(self, uc, address, size, user_data):
        """每条指令回调 — 仅检测段间跳转"""
        self._count += 1
        if self._count > self._max_count:
            return

        cur = self._classify(address)

        if self._prev_section and cur == 'text' and self._prev_section == 'themida':
            # 从 .themida 跳入 .text → OEP!
            self._real_oep = address
            if self.verbose:
                print(f"  [CrossOEP] CAPTURED: 0x{address:x} ({self._count} insn)")
            # Stop emulation
            uc.emu_stop()
            return

        self._prev_section = cur

    def _classify(self, addr):
        """判断地址属于哪个段"""
        if 0x140001000 <= addr < 0x140001000 + 0x1a3550:
            return 'text'
        if 0x140213000 <= addr < 0x140885000:
            return 'themida'
        if 0x140885000 <= addr < 0x140885000 + 0x400000:
            return 'boot'
        return 'other'

    @property
    def real_oep(self):
        return self._real_oep
