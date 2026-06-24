"""
V9 Environment + Transition + Context Analyzer
==================================================
Bobalkkagi V9.0 — Answer: Why doesn't the VM advance?

1. Handler Transition Matrix — 17×17 probability matrix
2. VM Context Diff — .themida page snapshots every 1M instructions
3. Environment Check — Fake PEB vs Real Windows fields
"""

import hashlib, struct, time
from collections import Counter, defaultdict


class V9Analyzer:
    """V9: Why is the VM stuck?"""

    def __init__(self, uc, verbose=False):
        self.uc = uc
        self.verbose = verbose

        # === Transition Matrix ===
        self._transitions: Counter = Counter()  # {(from_HID, to_HID): count}
        self._handler_map: dict = {}  # {rip: hid}
        self._next_hid = 0
        self._last_hid: int = -1
        self._sample_interval = 5000
        self._instr_count = 0

        # === VM Context Diff ===
        self._snapshots: list = []  # [{iter, page_hashes}]
        self._snapshot_interval = 1_000_000  # every 1M instructions
        self._monitored_pages = list(range(0x140213000, 0x140219000, 0x1000))

        # === Environment Check ===
        self._env_issues: list = []

    def _get_hid(self, rip: int) -> int:
        for r, h in self._handler_map.items():
            if abs(rip - r) < 16:
                return h
        h = self._next_hid
        self._next_hid += 1
        self._handler_map[rip] = h
        return h

    def on_code(self, uc, address, size):
        self._instr_count += 1
        if self._instr_count % self._sample_interval != 0:
            return

        hid = self._get_hid(address)
        if self._last_hid >= 0:
            self._transitions[(self._last_hid, hid)] += 1
        self._last_hid = hid

        # Periodic snapshot
        if self._instr_count % self._snapshot_interval == 0:
            self._take_snapshot()

    def _take_snapshot(self):
        """Snapshot .themida pages"""
        snap = {'iteration': self._instr_count, 'hashes': {}}
        for page in self._monitored_pages:
            try:
                data = bytes(self.uc.mem_read(page, 0x1000))
                snap['hashes'][page] = hashlib.md5(data).hexdigest()[:8]
            except:
                pass
        self._snapshots.append(snap)
        if self.verbose:
            print(f"  [V9] Snapshot @ {self._instr_count // 1_000_000}M")

    def check_environment(self, peb_base: int = 0, teb_base: int = 0):
        """检查 Fake Environment vs Real Windows"""
        issues = []

        if peb_base:
            try:
                # Read PEB fields from UC memory
                data = bytes(self.uc.mem_read(peb_base, 0x200))
                being_debugged = data[2]
                nt_global_flag = struct.unpack_from('<Q', data, 0xBC)[0] if len(data) > 0xBC else 0
                image_base = struct.unpack_from('<Q', data, 0x10)[0] if len(data) > 0x10 else 0
                ldr = struct.unpack_from('<Q', data, 0x18)[0] if len(data) > 0x18 else 0
                process_heap = struct.unpack_from('<Q', data, 0x30)[0] if len(data) > 0x30 else 0
                os_major = struct.unpack_from('<I', data, 0x118)[0] if len(data) > 0x118 else 0
                os_minor = struct.unpack_from('<I', data, 0x11C)[0] if len(data) > 0x11C else 0
                os_build = struct.unpack_from('<I', data, 0x120)[0] if len(data) > 0x120 else 0

                issues.append(f"BeingDebugged={being_debugged} (expect 0)")
                issues.append(f"NtGlobalFlag=0x{nt_global_flag:x} (expect 0)")
                issues.append(f"ImageBase=0x{image_base:x} (expect 0x140000000)")
                issues.append(f"Ldr={'SET' if ldr else 'NULL'} (expect SET)")
                issues.append(f"ProcessHeap={'SET' if process_heap else 'NULL'} (expect SET)")
                issues.append(f"OSVersion={os_major}.{os_minor}.{os_build} (expect 10.0.18362)")

                if being_debugged != 0:
                    self._env_issues.append("PEB: BeingDebugged != 0")
                if nt_global_flag != 0:
                    self._env_issues.append(f"PEB: NtGlobalFlag=0x{nt_global_flag:x}")
                if not ldr:
                    self._env_issues.append("PEB: Ldr = NULL")
                if not process_heap:
                    self._env_issues.append("PEB: ProcessHeap = NULL")
            except Exception as e:
                issues.append(f"PEB read error: {e}")

        if teb_base:
            try:
                data = bytes(self.uc.mem_read(teb_base, 0x100))
                peb_ptr = struct.unpack_from('<Q', data, 0x60)[0] if len(data) > 0x60 else 0
                stack_base = struct.unpack_from('<Q', data, 8)[0] if len(data) > 8 else 0
                stack_limit = struct.unpack_from('<Q', data, 16)[0] if len(data) > 16 else 0
                issues.append(f"TEB.PEB=0x{peb_ptr:x} (expect 0x{peb_base:x})")
                issues.append(f"TEB.StackBase=0x{stack_base:x}")
                issues.append(f"TEB.StackLimit=0x{stack_limit:x}")
                if peb_ptr != peb_base:
                    self._env_issues.append(f"TEB: PEB pointer mismatch")
            except Exception as e:
                issues.append(f"TEB read error: {e}")

        return issues

    def report(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("V9 — Why is the VM stuck?")
        lines.append("=" * 60)

        # === 1. Handler Transition Matrix ===
        lines.append(f"\n--- Handler Transition Matrix (17x17) ---")
        lines.append(f"Total instructions: {self._instr_count}")
        lines.append(f"Total transitions: {sum(self._transitions.values())}")

        # Build matrix
        all_hids = sorted(set(
            h for pair in self._transitions for h in pair
        ))
        if all_hids:
            # Header
            header = "     " + "".join(f" H{h:02d} " for h in all_hids)
            lines.append(header)

            total = max(sum(self._transitions.values()), 1)
            for from_h in all_hids:
                row = f" H{from_h:02d} |"
                for to_h in all_hids:
                    count = self._transitions.get((from_h, to_h), 0)
                    pct = count * 100 / total
                    if pct >= 1:
                        row += f" {pct:3.0f} "  # show % if >= 1%
                    elif count > 0:
                        row += "  ·  "
                    else:
                        row += "  .  "
                lines.append(row)

        # Cycle detection
        if self._transitions:
            # Find self-loops
            self_loops = sum(c for (f, t), c in self._transitions.items() if f == t)
            total = max(sum(self._transitions.values()), 1)
            loop_pct = self_loops * 100 / total
            lines.append(f"\nSelf-loops (H→H): {self_loops} ({loop_pct:.1f}%)")

            # Deterministic check
            from_counter = Counter(f for f, _ in self._transitions.keys())
            most_from = from_counter.most_common(1)[0] if from_counter else (0, 0)
            from_pct = most_from[1] * 100 / len(set(f for f, _ in self._transitions.keys()))
            lines.append(f"Dominant source: H{most_from[0]:02d} ({from_pct:.0f}%)")

            # Is the matrix FIXED or EVOLVING?
            unique_transitions = len(self._transitions)
            possible = len(set(f for f, _ in self._transitions.keys())) * len(
                set(t for _, t in self._transitions.keys()))
            sparsity = unique_transitions * 100 / max(possible, 1)
            lines.append(f"Transition sparsity: {unique_transitions}/{possible} ({sparsity:.0f}%)")
            lines.append(f"Matrix type: {'FIXED (deterministic)' if sparsity < 30 else 'EVOLVING (probabilistic)'}")

        # === 2. VM Context Diff ===
        lines.append(f"\n--- VM Context Diff ---")
        lines.append(f"Snapshots taken: {len(self._snapshots)}")

        if len(self._snapshots) >= 2:
            first = self._snapshots[0]['hashes']
            last = self._snapshots[-1]['hashes']
            changed = sum(1 for p in first if p in last and first[p] != last[p])
            identical = sum(1 for p in first if p in last and first[p] == last[p])

            lines.append(f"Pages monitored: {len(first)}")
            lines.append(f"Changed since first snapshot: {changed}")
            lines.append(f"Identical: {identical}")
            lines.append(f"Context: {'STATIC (no evolution)' if changed == 0 else f'{changed} pages EVOLVING'}")

            # Show per-page hash history
            if changed > 0:
                lines.append(f"\nPage hash evolution:")
                for page in sorted(first.keys()):
                    hashes = [s['hashes'].get(page, '?') for s in self._snapshots]
                    unique = len(set(hashes))
                    lines.append(f"  0x{page:x}: {unique} states → {hashes}")

        # === 3. Environment Check ===
        lines.append(f"\n--- Environment Issues ---")
        if self._env_issues:
            for issue in self._env_issues:
                lines.append(f"  ⚠ {issue}")
        else:
            lines.append(f"  No issues detected")

        # === Summary ===
        lines.append(f"\n--- V9 Summary ---")
        stuck_reasons = []
        if len(self._snapshots) >= 2 and changed == 0:
            stuck_reasons.append("VM context static (no page evolution)")
        if self_loops > total * 0.1:
            stuck_reasons.append(f"High self-loop rate ({loop_pct:.0f}%)")
        if self._env_issues:
            stuck_reasons.append(f"Environment issues ({len(self._env_issues)})")
        if stuck_reasons:
            lines.append("VM stuck because:")
            for r in stuck_reasons:
                lines.append(f"  → {r}")
        else:
            lines.append("No clear reason found")

        return "\n".join(lines)

    def print_report(self):
        print(self.report())
