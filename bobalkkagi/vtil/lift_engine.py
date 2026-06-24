"""
VTIL Lift Engine — P3: x86-64 → VTIL IR 提升与简化
=====================================================
Bobalkkagi v4.0 — 基于 Capstone 的 x64 指令提升器。

功能:
  - 将内存区域中的 x86-64 指令提升为 VTIL IR
  - 简化: 常量折叠、死代码消除、控制流分析
  - 为 VMAnalyzer / StubFixer 提供统一接口

依赖:
  - capstone: x86-64 反汇编
  - bobalkkagi.vtil.ir: VTIL 数据结构

参考:
  - VTIL-NativeLifters (x64 lifter)
  - VMPDump VTIL x64 lifter 实现
"""

from typing import Optional, List, Dict, Set, Tuple
from dataclasses import dataclass

from .ir import (
    VTILOpcode, VTIROperand, OperandKind,
    VTILInstruction, VTILBlock, VTILRoutine,
)

# Capstone
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# ============================================================
# x64 寄存器名称 → VTIL 寄存器名 (小写规范化)
# ============================================================

_X64_REG_MAP = {
    # GPRs
    19: 'rax', 20: 'rbx', 21: 'rcx', 22: 'rdx',
    23: 'rsi', 24: 'rdi', 25: 'rbp', 26: 'rsp',
    27: 'r8',  28: 'r9',  29: 'r10', 30: 'r11',
    31: 'r12', 32: 'r13', 33: 'r14', 34: 'r15',
    35: 'rip',
    # 32-bit
    37: 'eax', 38: 'ebx', 39: 'ecx', 40: 'edx',
    41: 'esi', 42: 'edi', 43: 'ebp', 44: 'esp',
}

_CAPSTONE_REG_TO_NAME = {
    # x86_reg numbers from capstone
    19: 'rax', 21: 'rcx', 22: 'rdx', 20: 'rbx',
    26: 'rsp', 25: 'rbp', 23: 'rsi', 24: 'rdi',
    27: 'r8', 28: 'r9', 29: 'r10', 30: 'r11',
    31: 'r12', 32: 'r13', 33: 'r14', 34: 'r15',
}

_CAPSTONE_REG_SIZES = {
    'rax': 8, 'rbx': 8, 'rcx': 8, 'rdx': 8,
    'rsi': 8, 'rdi': 8, 'rbp': 8, 'rsp': 8,
    'r8': 8, 'r9': 8, 'r10': 8, 'r11': 8,
    'r12': 8, 'r13': 8, 'r14': 8, 'r15': 8, 'rip': 8,
}

# x86 insn id → VTIL opcode
_X86_TO_VTIL = {
    'mov': VTILOpcode.MOV, 'lea': VTILOpcode.LEA,
    'push': VTILOpcode.PUSH, 'pop': VTILOpcode.POP,
    'add': VTILOpcode.ADD, 'sub': VTILOpcode.SUB,
    'mul': VTILOpcode.MUL, 'div': VTILOpcode.DIV, 'neg': VTILOpcode.NEG,
    'and': VTILOpcode.AND, 'or': VTILOpcode.OR, 'xor': VTILOpcode.XOR, 'not': VTILOpcode.NOT,
    'shl': VTILOpcode.SHL, 'shr': VTILOpcode.SHR,
    'rol': VTILOpcode.ROL, 'ror': VTILOpcode.ROR,
    'cmp': VTILOpcode.CMP, 'test': VTILOpcode.TEST,
    'jmp': VTILOpcode.JMP, 'call': VTILOpcode.CALL, 'ret': VTILOpcode.RET,
    'nop': VTILOpcode.NOP, 'syscall': VTILOpcode.SYSCALL,
    'movsx': VTILOpcode.MOVSX, 'movzx': VTILOpcode.MOVZX,
    'movsxd': VTILOpcode.MOVSX,
}

# 条件跳转 cc 映射
_CC_MAP = {
    'je': 'e', 'jz': 'e', 'jne': 'ne', 'jnz': 'ne',
    'jl': 'l', 'jnge': 'l', 'jle': 'le', 'jng': 'le',
    'jg': 'g', 'jnle': 'g', 'jge': 'ge', 'jnl': 'ge',
    'jb': 'b', 'jnae': 'b', 'jbe': 'be', 'jna': 'be',
    'ja': 'a', 'jnbe': 'a', 'jae': 'ae', 'jnb': 'ae',
    'jo': 'o', 'jno': 'no', 'js': 's', 'jns': 'ns',
    'jp': 'p', 'jpe': 'p', 'jnp': 'np', 'jpo': 'np',
    'jcxz': 'cxz', 'jecxz': 'ecxz', 'jrcxz': 'rcxz',
}


# ============================================================
# 简化器: 常量折叠
# ============================================================

@dataclass
class ConstantFoldResult:
    """常量折叠结果"""
    folded: bool = False
    value: int = 0


class ConstantFolder:
    """常量折叠优化器"""

    @staticmethod
    def try_fold(opcode: VTILOpcode, op1: VTIROperand, op2: VTIROperand) -> ConstantFoldResult:
        """尝试对二元操作做常量折叠"""
        if op1.kind != OperandKind.IMMEDIATE or op2.kind != OperandKind.IMMEDIATE:
            return ConstantFoldResult()

        a, b = op1.imm_value, op2.imm_value
        result = ConstantFoldResult(folded=True)

        if opcode == VTILOpcode.ADD:
            result.value = a + b
        elif opcode == VTILOpcode.SUB:
            result.value = a - b
        elif opcode == VTILOpcode.AND:
            result.value = a & b
        elif opcode == VTILOpcode.OR:
            result.value = a | b
        elif opcode == VTILOpcode.XOR:
            result.value = a ^ b
        elif opcode == VTILOpcode.SHL:
            result.value = a << b
        elif opcode == VTILOpcode.SHR:
            result.value = a >> b
        else:
            result.folded = False

        return result

    @staticmethod
    def is_zero(op: VTIROperand) -> bool:
        return op.kind == OperandKind.IMMEDIATE and op.imm_value == 0

    @staticmethod
    def is_one(op: VTIROperand) -> bool:
        return op.kind == OperandKind.IMMEDIATE and op.imm_value == 1


# ============================================================
# VTILLiftEngine
# ============================================================

class VTILLiftEngine:
    """
    x86-64 → VTIL IR 提升引擎。

    使用 Capstone 反汇编 + 手工映射 → VTIL IR。
    """

    def __init__(self):
        self._md = None
        if HAS_CAPSTONE:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
        self._temp_counter = 0

    @property
    def available(self) -> bool:
        return self._md is not None

    def _new_temp(self) -> int:
        self._temp_counter += 1
        return self._temp_counter

    def _reset_temps(self):
        self._temp_counter = 0

    # ===== 核心: 提升 =====

    def lift_region(self, data: bytes, base_addr: int, size: int = -1) -> 'VTILRoutine':
        """
        将内存区域中的指令提升为 VTIL IR。

        Args:
            data: 原始字节
            base_addr: 基址
            size: 最大字节数 (-1 = 全部)
        Returns:
            VTILRoutine
        """
        if not self._md:
            return VTILRoutine(name=f"region_0x{base_addr:x}")

        self._reset_temps()
        routine = VTILRoutine(name=f"region_0x{base_addr:x}")
        block = VTILBlock(name="entry", start_addr=base_addr)

        chunk = data[:size] if size > 0 else data

        for insn in self._md.disasm(chunk, base_addr):
            vtil_insns = self._lift_instruction(insn)
            for vi in vtil_insns:
                block.append(vi)

        routine.add_block(block)
        routine.entry_block = "entry"

        # 后处理: 识别 API 调用
        self._postprocess_api_calls(routine, block)

        return routine

    def lift_stub(self, data: bytes, addr: int, max_size: int = 128) -> 'VTILRoutine':
        """
        提升导入 stub（短代码片段）。

        与 lift_region 相同，但额外标记为 stub 并限制大小。
        """
        routine = self.lift_region(data, addr, max_size)
        routine.is_stub = True
        return routine

    def _lift_instruction(self, capstone_insn) -> List[VTILInstruction]:
        """将单条 capstone 指令提升为 1-N 条 VTIL 指令"""
        mnemonic = capstone_insn.mnemonic.lower()
        addr = capstone_insn.address
        size = capstone_insn.size

        # NOP
        if mnemonic == 'nop':
            return [VTILInstruction(VTILOpcode.NOP, address=addr, size=size)]

        # RET
        if mnemonic == 'ret':
            return [VTILInstruction(VTILOpcode.RET, address=addr, size=size)]

        # Unconditional JMP
        if mnemonic == 'jmp':
            ops = self._extract_operands(capstone_insn)
            if len(ops) >= 1:
                return [VTILInstruction(VTILOpcode.JMP, ops, addr, size)]
            return [VTILInstruction(VTILOpcode.JMP, address=addr, size=size)]

        # Conditional JMP → JCC
        if mnemonic in _CC_MAP:
            target = self._get_branch_target(capstone_insn)
            cc = _CC_MAP[mnemonic]
            op = VTIROperand.imm(target, 8) if target else VTIROperand.label(f"addr_0x{addr:x}")
            return [VTILInstruction(VTILOpcode.JCC, [op], addr, size, cc=cc)]

        # CALL
        if mnemonic == 'call':
            ops = self._extract_operands(capstone_insn)
            if len(ops) >= 1:
                return [VTILInstruction(VTILOpcode.CALL, ops, addr, size)]
            return [VTILInstruction(VTILOpcode.CALL, address=addr, size=size)]

        # 通用: 查找 VTIL 映射
        vtil_op = _X86_TO_VTIL.get(mnemonic, VTILOpcode.UNKNOWN)
        ops = self._extract_operands(capstone_insn)
        if vtil_op == VTILOpcode.UNKNOWN and ops:
            # 尝试推断
            pass

        return [VTILInstruction(vtil_op, ops, addr, size)]

    def _extract_operands(self, capstone_insn) -> List[VTIROperand]:
        """提取 capstone 指令的操作数 → VTIL 操作数"""
        ops = []
        try:
            for op in capstone_insn.operands:
                if op.type == 1:  # REG
                    reg_name = _CAPSTONE_REG_TO_NAME.get(op.reg, f"r{op.reg}")
                    ops.append(VTIROperand.reg(reg_name))
                elif op.type == 2:  # IMM
                    ops.append(VTIROperand.imm(op.imm))
                elif op.type == 3:  # MEM
                    base = _CAPSTONE_REG_TO_NAME.get(op.mem.base, "") if op.mem.base else ""
                    index = _CAPSTONE_REG_TO_NAME.get(op.mem.index, "") if op.mem.index else ""
                    ops.append(VTIROperand.mem(
                        base=base, index=index, scale=op.mem.scale, disp=op.mem.disp
                    ))
        except:
            pass
        return ops

    def _get_branch_target(self, capstone_insn) -> int:
        """获取跳转目标地址"""
        try:
            for op in capstone_insn.operands:
                if op.type == 2:  # IMM
                    return op.imm
        except:
            pass
        return 0

    def _postprocess_api_calls(self, routine: VTILRoutine, block: VTILBlock):
        """
        后处理: 识别 VTIL 中的 API 调用模式。

        常见 stub 模式:
          jmp [rip+disp]  → 跳转到 IAT thunk
          call [rip+disp] → 调用 IAT thunk
          mov rax, addr; call rax → 间接调用

        提取这些模式标记为 api_call。
        """
        for i, insn in enumerate(block.instructions):
            if insn.opcode == VTILOpcode.JMP:
                ops = insn.operands
                if len(ops) >= 1 and ops[0].kind == OperandKind.MEMORY:
                    block.instructions[i] = VTILInstruction(
                        VTILOpcode.API_CALL, ops, insn.address, insn.size,
                        meta={"api_pattern": "jmp_mem"}
                    )
            elif insn.opcode == VTILOpcode.CALL:
                ops = insn.operands
                if len(ops) >= 1 and ops[0].kind == OperandKind.MEMORY:
                    block.instructions[i] = VTILInstruction(
                        VTILOpcode.API_CALL, ops, insn.address, insn.size,
                        meta={"api_pattern": "call_mem"}
                    )

    # ===== 简化 =====

    def simplify_block(self, block: VTILBlock) -> VTILBlock:
        """
        简化 VTIL 基本块:
          1. 常量折叠
          2. 死代码消除 (未使用的写入)
          3. 合并冗余 MOV
        """
        if not block.instructions:
            return block

        # Pass 1: 常量折叠
        folded = []
        for insn in block.instructions:
            ops = insn.operands
            if len(ops) >= 3:
                result = ConstantFolder.try_fold(insn.opcode, ops[1], ops[2])
                if result.folded:
                    # 替换为 MOV dst, folded_value
                    new_insn = VTILInstruction(
                        VTILOpcode.MOV,
                        [ops[0], VTIROperand.imm(result.value)],
                        insn.address, insn.size
                    )
                    folded.append(new_insn)
                    continue
            folded.append(insn)

        # Pass 2: 消除冗余 MOV (相同寄存器 → 相同值的连续 MOV)
        simplified = []
        prev_dst = None
        for insn in folded:
            if insn.opcode == VTILOpcode.MOV and len(insn.operands) >= 2:
                dst = str(insn.operands[0])
                if dst == prev_dst:
                    # 跳过连续相同目标的 MOV
                    continue
                prev_dst = dst
            else:
                prev_dst = None
            simplified.append(insn)

        # 创建新 block
        result = VTILBlock(
            name=block.name, start_addr=block.start_addr,
            end_addr=block.end_addr, is_simplified=True
        )
        for insn in simplified:
            result.append(insn)
        result.successors = block.successors
        result.predecessors = block.predecessors

        return result

    def simplify_routine(self, routine: VTILRoutine) -> VTILRoutine:
        """简化整个例程"""
        result = VTILRoutine(
            name=routine.name, entry_block=routine.entry_block,
            is_stub=routine.is_stub
        )
        for name, block in routine.blocks.items():
            simplified = self.simplify_block(block)
            result.add_block(simplified)
        for addr, dll, func in routine.api_calls:
            result.api_calls.append((addr, dll, func))
        return result

    # ===== 摘要 =====

    def get_summary(self, routine: VTILRoutine) -> dict:
        """生成例程分析摘要"""
        blocks = len(routine.blocks)
        insns = routine.total_instructions
        api_calls = set()
        mem_refs = []

        for block in routine.blocks.values():
            for insn in block:
                if insn.opcode == VTILOpcode.CALL:
                    mem_refs.append(("call", insn.address))
                elif insn.opcode == VTILOpcode.API_CALL:
                    api_calls.add(str(insn.operands[0]) if insn.operands else "?")

        return {
            "blocks": blocks,
            "instructions": insns,
            "api_patterns": len(api_calls),
            "api_targets": list(api_calls)[:10],
            "memory_refs": len(mem_refs),
            "is_stub": routine.is_stub,
        }
