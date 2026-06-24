"""
VTIL Package — P3: 中间表示与提升引擎
=======================================
Bobalkkagi v4.0 — VTIL-based VM analysis infrastructure.

参考:
  - VTIL-Core (https://github.com/vtil-project/VTIL-Core)
  - VMPDump VTIL x64 lifter
"""

from .ir import (
    VTIROperand, OperandKind,
    VTILOpcode, VTILInstruction,
    VTILBlock, VTILRoutine,
    HandlerInfo, StubInfo,
)
from .lift_engine import VTILLiftEngine, ConstantFolder

__all__ = [
    'VTIROperand', 'OperandKind',
    'VTILOpcode', 'VTILInstruction',
    'VTILBlock', 'VTILRoutine',
    'HandlerInfo', 'StubInfo',
    'VTILLiftEngine', 'ConstantFolder',
]
