"""
VTIL Intermediate Representation — P3: 统一中间表示层
========================================================
Bobalkkagi v4.0 — Python-native VTIL-compatible IR for VM analysis.

VTIL (Virtual-machine Translation Intermediate Language) 是一种
面向虚拟机逆向分析的中间表示。本模块在 Python 中实现了其核心
数据结构，兼容 VTIL-Core 的语义模型。

核心设计:
  - 三地址码表示: dst = opcode src1, src2
  - 虚拟寄存器 (vreg) 用于 SSA 形式
  - 操作数支持: 寄存器 / 立即数 / 内存 / 临时变量
  - 简化器: 常量折叠 / 死代码消除 / 控制流恢复

参考:
  - VTIL-Core (https://github.com/vtil-project/VTIL-Core)
  - VMPDump VTIL x64 lifter
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict, Set, Tuple


# ============================================================
# 操作数类型
# ============================================================

class OperandKind(Enum):
    REGISTER = auto()       # x86-64 硬件寄存器
    IMMEDIATE = auto()      # 立即数
    MEMORY = auto()         # 内存引用 [base + index*scale + disp]
    TEMP = auto()           # 临时变量 / 虚拟寄存器
    LABEL = auto()          # 跳转标签


@dataclass
class VTIROperand:
    """VTIL 操作数"""
    kind: OperandKind
    # 寄存器
    reg_name: str = ""           # e.g., "rax", "rsp", "rip"
    reg_size: int = 8            # bytes: 1/2/4/8
    # 立即数
    imm_value: int = 0
    # 内存
    mem_base: str = ""           # base register
    mem_index: str = ""          # index register
    mem_scale: int = 1           # 1, 2, 4, 8
    mem_disp: int = 0
    # 临时
    temp_id: int = 0
    # 标签
    label_name: str = ""

    @classmethod
    def reg(cls, name: str, size: int = 8) -> 'VTIROperand':
        return cls(kind=OperandKind.REGISTER, reg_name=name, reg_size=size)

    @classmethod
    def imm(cls, value: int, size: int = 8) -> 'VTIROperand':
        return cls(kind=OperandKind.IMMEDIATE, imm_value=value, reg_size=size)

    @classmethod
    def mem(cls, base: str = "", index: str = "", scale: int = 1,
            disp: int = 0, size: int = 8) -> 'VTIROperand':
        return cls(kind=OperandKind.MEMORY, mem_base=base, mem_index=index,
                   mem_scale=scale, mem_disp=disp, reg_size=size)

    @classmethod
    def tmp(cls, tid: int, size: int = 8) -> 'VTIROperand':
        return cls(kind=OperandKind.TEMP, temp_id=tid, reg_size=size)

    @classmethod
    def label(cls, name: str) -> 'VTIROperand':
        return cls(kind=OperandKind.LABEL, label_name=name)

    def __repr__(self) -> str:
        if self.kind == OperandKind.REGISTER:
            return f"reg({self.reg_name})"
        elif self.kind == OperandKind.IMMEDIATE:
            return f"0x{self.imm_value:x}"
        elif self.kind == OperandKind.MEMORY:
            parts = []
            if self.mem_base:
                parts.append(self.mem_base)
            if self.mem_index:
                parts.append(f"{self.mem_index}*{self.mem_scale}")
            addr = "+".join(parts) if parts else "0"
            if self.mem_disp:
                addr += f"+0x{self.mem_disp:x}" if addr != "0" else f"0x{self.mem_disp:x}"
            return f"[{addr}]"
        elif self.kind == OperandKind.TEMP:
            return f"t{self.temp_id}"
        elif self.kind == OperandKind.LABEL:
            return f"@{self.label_name}"
        return "?"


# ============================================================
# VTIL 指令
# ============================================================

class VTILOpcode(Enum):
    # 数据传送
    MOV = "mov"
    PUSH = "push"
    POP = "pop"
    LEA = "lea"
    # 算术
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"
    NEG = "neg"
    # 逻辑
    AND = "and"
    OR = "or"
    XOR = "xor"
    NOT = "not"
    SHL = "shl"
    SHR = "shr"
    ROL = "rol"
    ROR = "ror"
    # 比较
    CMP = "cmp"
    TEST = "test"
    # 控制流
    JMP = "jmp"
    JCC = "jcc"           # 条件跳转 (condition stored in meta)
    CALL = "call"
    RET = "ret"
    # 系统
    SYSCALL = "syscall"
    NOP = "nop"
    # VTIL 特有 — 语义
    STR = "str"           # store to memory
    LDD = "ldd"           # load from memory
    MOVSX = "movsx"       # sign-extend
    MOVZX = "movzx"       # zero-extend
    # 分支
    BRANCH = "branch"     # unconditional branch
    # 函数调用 (stub分析用)
    API_CALL = "api_call"  # 解析出的API调用
    # 未知
    UNKNOWN = "unknown"


@dataclass
class VTILInstruction:
    """单条 VTIL 指令 (三地址码)"""
    opcode: VTILOpcode
    operands: List[VTIROperand] = field(default_factory=list)
    address: int = 0                  # 原始 x86 地址
    size: int = 0                     # 原始 x86 字节数
    # 元数据
    meta: Dict[str, object] = field(default_factory=dict)
    # 条件跳转的条件码
    cc: str = ""                      # e.g., "e", "ne", "l", "g", ...
    # SSA 表单
    ssa_dst: Optional[int] = None     # 目标虚拟寄存器
    ssa_srcs: List[int] = field(default_factory=list)
    # 优化标记
    is_dead: bool = False

    def __repr__(self) -> str:
        ops = ", ".join(str(op) for op in self.operands)
        cc_str = f".{self.cc}" if self.cc else ""
        return f"0x{self.address:x}: {self.opcode.value}{cc_str} {ops}"


# ============================================================
# VTIL 基本块
# ============================================================

@dataclass
class VTILBlock:
    """VTIL 基本块 — 单入口单出口的指令序列"""
    name: str = ""
    instructions: List[VTILInstruction] = field(default_factory=list)
    start_addr: int = 0
    end_addr: int = 0
    # 控制流
    successors: List[str] = field(default_factory=list)  # 后继块名
    predecessors: List[str] = field(default_factory=list)  # 前驱块名
    # 优化
    is_simplified: bool = False

    def append(self, insn: VTILInstruction):
        self.instructions.append(insn)
        if not self.start_addr:
            self.start_addr = insn.address
        self.end_addr = insn.address + insn.size

    def __len__(self):
        return len(self.instructions)

    def __iter__(self):
        return iter(self.instructions)

    def __repr__(self) -> str:
        n = len(self.instructions)
        return f"VTILBlock({self.name}, {n} insns, 0x{self.start_addr:x}-0x{self.end_addr:x})"


# ============================================================
# VTIL 例程 (函数)
# ============================================================

@dataclass
class VTILRoutine:
    """VTIL 例程 — 多个基本块组成的函数"""
    name: str = ""
    entry_block: str = ""
    blocks: Dict[str, VTILBlock] = field(default_factory=dict)
    # 分析结果
    api_calls: List[Tuple[int, str, str]] = field(default_factory=list)  # (addr, dll, func)
    memory_refs: List[Tuple[int, int, str]] = field(default_factory=list)  # (addr, size, type)
    is_stub: bool = False                # 是否为导入 stub

    def add_block(self, block: VTILBlock):
        self.blocks[block.name] = block

    def get_block(self, name: str) -> Optional[VTILBlock]:
        return self.blocks.get(name)

    @property
    def total_instructions(self) -> int:
        return sum(len(b) for b in self.blocks.values())

    def __repr__(self) -> str:
        return f"VTILRoutine({self.name}, {len(self.blocks)} blocks, {self.total_instructions} insns)"


# ============================================================
# Handler 信息 (VM 分析)
# ============================================================

@dataclass
class HandlerInfo:
    """VM Handler 描述"""
    address: int = 0               # Handler 入口地址
    name: str = ""                 # 推测名称, e.g. "ADD64", "PUSH_IMM"
    bytecode_range: Tuple[int, int] = (0, 0)  # 对应字节码范围
    visit_count: int = 0           # 执行次数
    lifted_block: Optional[VTILBlock] = None  # VTIL 提升结果
    is_entry: bool = False         # 是否为 VM 入口 Handler

    def __repr__(self) -> str:
        return f"Handler({self.name or '0x{self.address:x}'}, visits={self.visit_count})"


# ============================================================
# Stub 信息 (导入修复)
# ============================================================

@dataclass
class StubInfo:
    """导入 stub 描述"""
    address: int = 0               # stub 地址
    size: int = 0                  # stub 大小
    dll_name: str = ""             # 目标 DLL
    func_name: str = ""            # 目标函数
    call_type: str = "direct"      # "direct" | "indirect" | "vm_call"
    bytes_to_overwrite: int = 0    # 需要覆盖的字节数
    replacement_bytes: bytes = b'' # 替换字节
    confidence: float = 0.0        # 置信度 0-1

    def __repr__(self) -> str:
        return f"Stub(0x{self.address:x}, {self.dll_name}!{self.func_name}, conf={self.confidence:.1%})"
