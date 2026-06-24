"""
V10 Runtime Dependency Graph — 追踪 VM 状态读取和分支决策
===============================================================
Bobalkkagi V10.0 — 记录哪些内存读取控制 VM 分支，形成依赖链。

问题: 为什么 VM 进入吸收态（固定循环）？
方法: 追踪 .themida 内存读取 → 确定哪些状态控制分支 → 看状态是否变化
"""

from collections import Counter, defaultdict
import struct


class DependencyTracker:
    """V10: 运行时依赖追踪器"""

    def __init__(self, uc, verbose=False):
        self.uc = uc
        self.verbose = verbose

        # Memory read tracking
        self._reads: list = []  # [(rip, addr, value)]
        self._read_counter: Counter = Counter()  # {(rip, addr): count}
        self._read_values: dict = {}  # {(rip, addr): {value: count}}

        # Branch tracking
        self._branches: list = []  # [(rip_from, rip_to, condition)]
        self._branch_counter: Counter = Counter()  # {(from, to): count}

        # Instruction counter
        self._instr_count = 0
        self._sample_interval = 5000

    def on_code(self, uc, address, size):
        """每条指令 — 检查是否是条件跳转"""
        self._instr_count += 1
        if self._instr_count % self._sample_interval != 0:
            return

        # Read the instruction bytes to detect conditional jumps
        try:
            code = bytes(uc.mem_read(address, 6))
        except:
            return

        # Check for conditional jumps
        is_cond = False
        target = 0

        if code[0] == 0x0F and len(code) >= 6 and code[1] in range(0x80, 0x90):
            # Jcc rel32
            rel = struct.unpack_from('<i', code, 2)[0]
            target = address + 6 + rel
            is_cond = True
        elif code[0] in range(0x70, 0x80) and len(code) >= 2:
            # Jcc rel8
            rel = struct.unpack_from('<b', code, 1)[0]
            target = address + 2 + rel
            is_cond = True

        if is_cond:
            # Record this branch point
            self._branches.append((address, target, code[0]))
            self._branch_counter[(address, target)] += 1

    def on_read(self, uc, access, address, size, value):
        """.themida 内存读取"""
        rip = 0
        try:
            from unicorn.x86_const import UC_X86_REG_RIP
            rip = uc.reg_read(UC_X86_REG_RIP)
        except:
            return

        # Read the value at this address
        try:
            val_bytes = bytes(uc.mem_read(address, min(size, 8)))
            val = int.from_bytes(val_bytes, 'little')
        except:
            return

        self._reads.append((rip, address, val))
        self._read_counter[(rip, address)] += 1

        key = (rip, address)
        if key not in self._read_values:
            self._read_values[key] = Counter()
        self._read_values[key][val] += 1

    def report(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("V10 Runtime Dependency Graph")
        lines.append("=" * 60)

        lines.append(f"\nInstructions: {self._instr_count}")
        lines.append(f"Branch points tracked: {len(self._branch_counter)}")
        lines.append(f"Unique reads tracked: {len(self._read_counter)}")

        # === Branch Analysis ===
        if self._branches:
            lines.append(f"\n--- Top Branch Points ---")
            # Group branches by source RIP
            by_source = defaultdict(Counter)
            for (frm, to), count in self._branch_counter.items():
                by_source[frm][to] += count

            for frm, targets in sorted(by_source.items(), key=lambda x: -sum(x[1].values()))[:10]:
                total = sum(targets.values())
                most_to = targets.most_common(1)[0]
                always_same = most_to[1] == total
                lines.append(f"  0x{frm:x}: {total} branches")
                for to, count in targets.most_common(3):
                    pct = count * 100 / total
                    lines.append(f"    → 0x{to:x}: {count} ({pct:.0f}%)")
                if always_same:
                    lines.append(f"    ⚡ DETERMINISTIC — always same target")

        # === Read Analysis — 哪些读取值总是不变 ===
        if self._read_values:
            lines.append(f"\n--- Memory Read Analysis ---")
            static_reads = 0
            dynamic_reads = 0

            for (rip, addr), values in self._read_values.items():
                unique = len(values)
                if unique == 1:
                    static_reads += 1
                else:
                    dynamic_reads += 1

            lines.append(f"Static reads (always same value): {static_reads}")
            lines.append(f"Dynamic reads (varying values): {dynamic_reads}")

            if dynamic_reads > 0:
                lines.append(f"\nTop dynamic reads:")
                for (rip, addr), values in sorted(
                    self._read_values.items(),
                    key=lambda x: -len(x[1])
                )[:10]:
                    total = sum(values.values())
                    if len(values) <= 1:
                        continue
                    lines.append(f"  0x{rip:x} reads [0x{addr:x}]: {total} times, {len(values)} unique")
                    for val, count in values.most_common(5):
                        pct = count * 100 / total
                        lines.append(f"    val=0x{val:x}: {count} ({pct:.0f}%)")

        # === Dependency Chain ===
        lines.append(f"\n--- Dependency Chain ---")
        has_static = static_reads > 0
        has_dynamic = dynamic_reads > 0
        has_deterministic = any(
            targets.most_common(1)[0][1] == sum(targets.values())
            for targets in by_source.values() if sum(targets.values()) > 5
        )

        if has_static and has_deterministic and not has_dynamic:
            lines.append("DIAGNOSIS: VM reads static values → deterministic branches → absorption loop")
            lines.append("  Root: memory reads always return same values")
            lines.append("  Effect: all branches are deterministic")
            lines.append("  Result: fixed dispatch cycle, no state progression")
            lines.append("  Fix: need to identify why read values never change")
        elif has_static and not has_dynamic:
            lines.append("DIAGNOSIS: All reads static — no dynamic state at all")
            lines.append("  Either: VM uses only static dispatch table")
            lines.append("  Or: state changes happen outside monitored region")
        else:
            lines.append("DIAGNOSIS: Mixed — some reads static, some dynamic")
            lines.append("  VM is reading varying state but branches remain deterministic")

        return "\n".join(lines)

    def print_report(self):
        print(self.report())
