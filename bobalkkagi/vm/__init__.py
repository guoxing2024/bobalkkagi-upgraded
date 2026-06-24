"""
VM Package — P3: VM 分析框架
=============================
Bobalkkagi v4.0 — Themida/VMProtect 虚拟机分析。

包含:
  - VMAnalyzer: VM 入口检测 + Handler 提取 + 字节码分析
"""

from .analyzer import (
    VMAnalyzer, VM_ENGINE_THEMIDA, VM_ENGINE_VMPROTECT, VM_ENGINE_AUTO,
    VMEntrySignature, THEMIDA_VM_SIGNATURES, VMPROTECT_VM_SIGNATURES,
)

__all__ = [
    'VMAnalyzer',
    'VM_ENGINE_THEMIDA', 'VM_ENGINE_VMPROTECT', 'VM_ENGINE_AUTO',
    'VMEntrySignature', 'THEMIDA_VM_SIGNATURES', 'VMPROTECT_VM_SIGNATURES',
]
