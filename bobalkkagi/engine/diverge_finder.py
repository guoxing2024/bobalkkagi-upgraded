"""
V10 Divergence Point Finder — 定位 VM 吸收态的精确触发点
=============================================================
找出 Unicorn VM dispatcher 中哪个具体内存地址的值导致分支永远相同。
"""

from collections import Counter, defaultdict
import struct


class DivergenceFinder:
    """V10: 精确定位吸收点"""

    def __init__(self, uc, verbose=False):
        self.uc = uc
        self.verbose = verbose

        # Track: branch RIP → last memory read before branch
        self._branch_pre_reads: list = []  # [(read_addr, read_val, branch_rip)]
        self._instr_count = 0
        self._sample_interval = 5000
        self._last_read_addr = 0
        self._last_read_val = 0
        self._critical_values: Counter = Counter()  # {(read_addr, read_val): branch_count}

    def on_read(self, uc, access, address, size, value):
        """记录 .themida 内存读取"""
        if not (0x140213000 <= address < 0x140885000):
            return
        try:
            val_bytes = bytes(uc.mem_read(address, min(size, 8)))
            val = int.from_bytes(val_bytes, 'little')
            self._last_read_addr = address
            self._last_read_val = val
        except:
            pass

    def on_code(self, uc, address, size):
        """检查条件跳转"""
        self._instr_count += 1
        if self._instr_count % self._sample_interval != 0:
            return

        try:
            code = bytes(uc.mem_read(address, 6))
        except:
            return

        # 检测条件跳转
        is_jcc = (code[0] == 0x0F and len(code) >= 6 and 0x80 <= code[1] <= 0x8F) or \
                 (0x70 <= code[0] <= 0x7F)

        if is_jcc:
            if self._last_read_addr:
                self._branch_pre_reads.append(
                    (self._last_read_addr, self._last_read_val, address))
                self._critical_values[(self._last_read_addr, self._last_read_val)] += 1

    def report(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("V10 Divergence Point Analysis")
        lines.append("=" * 60)

        lines.append(f"\nInstructions: {self._instr_count}")
        lines.append(f"Branch-read pairs: {len(self._branch_pre_reads)}")

        # Top critical values
        top = self._critical_values.most_common(10)
        if top:
            lines.append(f"\nTop critical values (read_addr → read_val → branch count):")
            for (addr, val), count in top:
                pct = count * 100 / max(len(self._branch_pre_reads), 1)
                lines.append(f"  [0x{addr:x}] = 0x{val:x} → {count} branches ({pct:.0f}%)")

        # Find single-value dominance
        unique_addrs = set(addr for addr, _ in self._critical_values)
        lines.append(f"\nUnique addresses controlling branches: {len(unique_addrs)}")

        if unique_addrs:
            for addr in sorted(unique_addrs):
                vals = Counter()
                for (a, v), c in self._critical_values.items():
                    if a == addr:
                        vals[v] = c
                total = sum(vals.values())
                unique_vals = len(vals)
                if unique_vals == 1:
                    only_val = list(vals.keys())[0]
                    lines.append(f"  0x{addr:x}: SINGLE VALUE 0x{only_val:x} ({total} branches)")
                else:
                    lines.append(f"  0x{addr:x}: {unique_vals} different values")

        # Summary
        single_val_addrs = sum(1 for addr in unique_addrs
                              if len({v for (a, v), _ in self._critical_values.items()
                                      if a == addr}) == 1)

        lines.append(f"\n--- V10 Summary ---")
        if single_val_addrs == len(unique_addrs) and unique_addrs:
            lines.append(f"ALL {len(unique_addrs)} critical addresses hold single static values")
            lines.append(f"CONFIRMED: VM absorption is caused by static state at these addresses")
            for addr in sorted(unique_addrs):
                val = next(v for (a, v) in self._critical_values if a == addr)
                lines.append(f"  → Address 0x{addr:x} is stuck at value 0x{val:x}")
        else:
            lines.append(f"Mixed: {single_val_addrs} static, {len(unique_addrs) - single_val_addrs} dynamic")

        return "\n".join(lines)

    def print_report(self):
        print(self.report())
