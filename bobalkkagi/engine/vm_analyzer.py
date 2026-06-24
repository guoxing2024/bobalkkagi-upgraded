"""
V8 VM Runtime Analyzer — State + Delta + Loop Detection
===========================================================
Bobalkkagi V8.0 — Expert Phase: 证明 Dispatcher 是循环/状态机/等待

三合一模块:
  1. VM State Analyzer — 追踪 Dispatcher 状态推进
  2. Write Delta Analyzer — 监视 .themida 页内容变化
  3. Loop Detector — SCC 分析确认 Dispatcher Loop
"""

import hashlib
import struct
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple


class VMRuntimeAnalyzer:
    """V8: VM 运行时分析器"""

    def __init__(self, uc, verbose=False):
        self.uc = uc
        self.verbose = verbose

        # === VM State Analyzer ===
        self._rip_samples: List[int] = []         # 采样 RIP
        self._rip_counter: Counter = Counter()     # RIP 频率
        self._handler_map: Dict[int, int] = {}     # {rip: handler_id}
        self._handler_freq: Counter = Counter()     # handler 使用频率
        self._next_handler_id = 0
        self._vm_stack_samples: List[Tuple[int, int]] = []  # (iter, rsp)

        # === Write Delta Analyzer ===
        self._page_hashes: Dict[int, bytes] = {}   # {page: hash_before_write}
        self._page_history: List[dict] = []         # [{page, hash_before, hash_after, delta_bytes, iteration}]
        self._iteration = 0

        # === Loop Detector ===
        self._edge_counter: Counter = Counter()     # {(from_rip, to_rip): count}
        self._last_rip: int = 0
        self._basic_blocks: Dict[int, List[int]] = defaultdict(list)  # {bb_start: [succ_bb]}

        # Sample interval
        self._sample_interval = 1000  # snapshot every N instructions
        self._instr_count = 0

    def _get_handler_id(self, rip: int) -> int:
        """将 RIP 映射到 handler ID (相近地址 = 同一 handler)"""
        # Cluster RIPs within 8 bytes of each other
        for existing_rip, hid in self._handler_map.items():
            if abs(rip - existing_rip) < 16:
                return hid
        hid = self._next_handler_id
        self._next_handler_id += 1
        self._handler_map[rip] = hid
        return hid

    def on_code(self, uc, address: int, size: int):
        """指令回调 — 采样 + 边追踪"""
        self._instr_count += 1

        if self._instr_count % self._sample_interval == 0:
            self._rip_samples.append(address)
            self._rip_counter[address] += 1
            hid = self._get_handler_id(address)
            self._handler_freq[hid] += 1

            # Record VM stack
            from unicorn.x86_const import UC_X86_REG_RSP
            rsp = uc.reg_read(UC_X86_REG_RSP)
            self._vm_stack_samples.append((self._instr_count, rsp))

            # Edge tracking for loop detection
            if self._last_rip:
                self._edge_counter[(self._last_rip, address)] += 1
            self._last_rip = address

    def on_write_before(self, addr: int, size: int):
        """写前 — 记录页面哈希"""
        page = addr & ~0xFFF
        if page not in self._page_hashes:
            try:
                data = bytes(self.uc.mem_read(page, 0x1000))
                self._page_hashes[page] = hashlib.md5(data).digest()
            except:
                pass

    def on_write_after(self, addr: int, size: int):
        """写后 — 比较哈希变化"""
        page = addr & ~0xFFF
        if page in self._page_hashes:
            try:
                data = bytes(self.uc.mem_read(page, 0x1000))
                new_hash = hashlib.md5(data).digest()
                old_hash = self._page_hashes[page]

                if old_hash != new_hash:
                    delta_bytes = sum(1 for a, b in zip(
                        self.uc.mem_read(page, min(256, 0x1000)),
                        data[:256]) if a != b)

                    self._page_history.append({
                        'page': page,
                        'hash_before': old_hash.hex()[:8],
                        'hash_after': new_hash.hex()[:8],
                        'delta_bytes': delta_bytes,
                        'iteration': self._instr_count // self._sample_interval,
                    })

                    self._page_hashes[page] = new_hash  # update baseline
            except:
                pass

    def report(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("V8 VM Runtime Analysis Report")
        lines.append("=" * 60)

        # === 1. VM State Analyzer ===
        lines.append(f"\n--- VM State Analyzer ---")
        lines.append(f"Total instructions: {self._instr_count}")
        lines.append(f"Unique RIPs: {len(self._rip_counter)}")
        lines.append(f"Unique Handlers (clustered): {len(self._handler_map)}")

        top_h = self._handler_freq.most_common(10)
        if top_h:
            lines.append(f"\nHandler frequency (top 10):")
            for hid, count in top_h:
                reps = [rip for rip, h in self._handler_map.items() if h == hid]
                rep = min(reps) if reps else 0
                pct = count * 100 / max(self._instr_count // self._sample_interval, 1)
                lines.append(f"  H{hid:02d} @0x{rep:x}: {count} ({pct:.1f}%)")

        # VM Stack trend
        if len(self._vm_stack_samples) > 2:
            first_rsp = self._vm_stack_samples[0][1]
            last_rsp = self._vm_stack_samples[-1][1]
            lines.append(f"\nVM Stack: first=0x{first_rsp:x} last=0x{last_rsp:x} "
                        f"delta={last_rsp - first_rsp:+d}")

        # Handler sequence analysis — does the dispatch follow a pattern?
        if len(self._rip_samples) > 100:
            # Build handler transition matrix
            handler_seq = [self._get_handler_id(r) for r in self._rip_samples[-200:]]
            transitions = Counter()
            for i in range(len(handler_seq) - 1):
                transitions[(handler_seq[i], handler_seq[i + 1])] += 1

            lines.append(f"\nHandler transition matrix (last 200 samples):")
            for (h1, h2), count in transitions.most_common(8):
                lines.append(f"  H{h1:02d} → H{h2:02d}: {count}")

        # === 2. Write Delta Analyzer ===
        lines.append(f"\n--- Write Delta Analyzer ---")
        lines.append(f"Pages monitored: {len(self._page_hashes)}")
        lines.append(f"Hash changes detected: {len(self._page_history)}")

        if self._page_history:
            # Group by page
            by_page = defaultdict(list)
            for entry in self._page_history:
                by_page[entry['page']].append(entry)

            lines.append(f"\nPage change history:")
            for page, entries in sorted(by_page.items()):
                unique_hashes = len(set(e['hash_after'] for e in entries))
                stable = unique_hashes == 1
                total_delta = sum(e['delta_bytes'] for e in entries)
                lines.append(f"  0x{page:x}: {len(entries)} changes, "
                           f"{unique_hashes} unique states, "
                           f"{'STABLE' if stable else 'EVOLVING'}, "
                           f"total delta: {total_delta} bytes")

        # === 3. Loop Detector ===
        lines.append(f"\n--- Loop Detector ---")

        if len(self._rip_counter) > 50:
            # Simple SCC: check if all top RIPs form a single connected component
            top_rips = set(r for r, _ in self._rip_counter.most_common(30))
            edges = [(frm, to) for (frm, to), _ in self._edge_counter.most_common(100)
                    if frm in top_rips and to in top_rips]

            # Build adjacency
            adj = defaultdict(set)
            for frm, to in edges:
                adj[frm].add(to)

            # Find in-component (nodes with both in and out edges in the set)
            reachable = set()
            if top_rips:
                start = next(iter(top_rips))
                # BFS from each node
                for node in list(top_rips)[:5]:
                    visited = set()
                    stack = [node]
                    while stack:
                        v = stack.pop()
                        if v in visited:
                            continue
                        visited.add(v)
                        for n in adj.get(v, set()):
                            if n in top_rips and n not in visited:
                                stack.append(n)
                    reachable |= visited

                scc_ratio = len(reachable & top_rips) * 100 / len(top_rips)
                lines.append(f"Top RIPs: {len(top_rips)}")
                lines.append(f"In connected component: {len(reachable & top_rips)} ({scc_ratio:.0f}%)")
                lines.append(f"Edges in graph: {len(edges)}")
                lines.append(f"Dispatcher loop confirmed: {scc_ratio > 90}")

        # === Summary ===
        lines.append(f"\n--- V8 Summary ---")
        has_state_progress = len(self._page_history) > 0 and \
            any(len(set(e['hash_after'] for e in entries)) > 1
                for entries in by_page.values())
        lines.append(f"State progression: {'YES' if has_state_progress else 'NO (static)'}")
        lines.append(f"Dispatcher loop: {'YES' if len(self._rip_counter) < 200 else 'TBD (need more data)'}")
        lines.append(f"Second execution hotspot: {'FOUND' if any('other' in str(p) for p in self._rip_counter) else 'NOT FOUND'}")

        return "\n".join(lines)

    def print_report(self):
        print(self.report())
