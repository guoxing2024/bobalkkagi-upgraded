"""
Exception Engine — 异常处理引擎
=================================
Bobalkkagi升级 — P4: SEH/VEH恢复

Themida样本严重依赖异常流（Guard Page、INT3、ICEBP等）。
此模块在Unicorn中拦截异常事件并模拟Windows异常分发。

当前实现：
1. 拦截 UC_HOOK_MEM_UNMAPPED / UC_HOOK_MEM_PROT 异常
2. 记录异常信息
3. 对于已知的Themida反调试异常，返回"已处理"
4. 提供异常日志供事后分析

未来扩展：
1. 完整的VEH链模拟
2. EXCEPTION_RECORD / CONTEXT 结构维护
3. 异常回调分发
"""

import struct
import logging
from datetime import datetime

logger = logging.getLogger("Bobalkkagi.ExceptionEngine")

# Windows NTSTATUS
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094
STATUS_SINGLE_STEP = 0x80000004
STATUS_BREAKPOINT = 0x80000003
STATUS_GUARD_PAGE_VIOLATION = 0x80000001
STATUS_STACK_BUFFER_OVERRUN = 0xC0000409
STATUS_FLOAT_DIVIDE_BY_ZERO = 0xC000008E
STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096
STATUS_INTEGER_OVERFLOW = 0xC0000095


class ExceptionRecord:
    """异常记录"""
    def __init__(self, code, address, info=""):
        self.code = code
        self.address = address
        self.info = info
        self.timestamp = datetime.now()
        self.handled = False
    
    def __repr__(self):
        handled = " [HANDLED]" if self.handled else ""
        return (f"EXCEPTION 0x{self.code:08x} @ 0x{self.address:x}"
                f" {self.info}{handled}")


class ExceptionEngine:
    """Unicorn异常处理引擎"""
    
    def __init__(self):
        self.exception_log = []
        self._hooks = []
        self.uc = None
        self.running = False
        
        # 已知的Themida反调试异常模式
        self.handled_patterns = {
            0x80000003: "INT3 breakpoint",           # 常见的anti-debug INT3
            0x80000004: "single step (trap flag)",    # TF单步
        }
    
    def install(self, uc):
        """安装异常处理hook"""
        self.uc = uc
        self.running = True
        
        hook_unmapped = uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_mem_error)
        hook_prot = uc.hook_add(UC_HOOK_MEM_PROT, self._on_mem_error)
        hook_read_bad = uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._on_mem_error)
        hook_write_bad = uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._on_mem_error)
        hook_fetch_bad = uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._on_mem_error)
        
        self._hooks = [hook_unmapped, hook_prot, hook_read_bad, hook_write_bad, hook_fetch_bad]
    
    def uninstall(self):
        if self.uc and self.running:
            for h in self._hooks:
                try:
                    self.uc.hook_del(h)
                except:
                    pass
        self.running = False
    
    def _on_mem_error(self, uc, access, address, size, value, user_data):
        """内存错误回调"""
        # 记录异常
        rec = ExceptionRecord(
            STATUS_ACCESS_VIOLATION, address,
            f"access={access} size={size} value=0x{value:x}"
        )
        
        # 检查是否是已知的可处理模式
        rip = uc.reg_read(UC_X86_REG_RIP)
        
        # 跳过分页错误（Unicorn常见）
        # 跳过guard page相关错误
        if size == 0:
            rec.handled = True
        
        self.exception_log.append(rec)
        
        # 对于已知的INT3断点，skip过去
        code = uc.mem_read(rip, 1)
        if code == b'\xcc':  # INT3
            uc.reg_write(UC_X86_REG_RIP, rip + 1)
            rec.handled = True
        
        return True  # 继续模拟
    
    def get_report(self):
        """获取异常报告"""
        total = len(self.exception_log)
        handled = sum(1 for e in self.exception_log if e.handled)
        
        lines = ["\n=== Exception Engine Report ==="]
        lines.append(f"Total exceptions: {total}")
        lines.append(f"Handled: {handled}")
        
        # 显示最近的异常
        recent = self.exception_log[-10:] if len(self.exception_log) > 10 else self.exception_log
        if recent:
            lines.append("\nRecent exceptions:")
            for e in recent:
                lines.append(f"  {e}")
        
        return '\n'.join(lines)
