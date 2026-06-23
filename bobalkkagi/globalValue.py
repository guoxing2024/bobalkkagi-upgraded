"""
Context Bridge — 线程安全的上下文访问
=======================================
提供 get_context() / set_context() 供所有模块获取当前 UnpackContext。
此模块自身不再持有任何业务状态。

验收标准: 全局搜索 GLOBAL_VAR 仅此文件出现（定义+类体），其他文件通过 get_context() 访问。
"""

import threading

# 线程本地存储 — 每个线程独立上下文
_local = threading.local()


def set_context(ctx):
    """设置当前线程的 UnpackContext"""
    _local.ctx = ctx


def get_context():
    """获取当前线程的 UnpackContext"""
    return getattr(_local, 'ctx', None)


# === DLL_SETTING（DLL加载状态，与样本无关，保持不变） ===
class DLL_SETTING:
    DllFuncs = {}
    LoadedDll = {}
    InverseDllFuncs = {}
    InverseLoadedDll = {}


class HEAP_HANDLE:
    HeapHandle = [0x000001E9E3850000]
    HeapHandleSize = 1


def InvDllDict():
    DLL_SETTING.InverseDllFuncs = {v: k for k, v in DLL_SETTING.DllFuncs.items()}
    DLL_SETTING.InverseLoadedDll = {v: k for k, v in DLL_SETTING.LoadedDll.items()}


def InvHookFuncDict():
    from .hookFuncs import HookFuncs
    ctx = get_context()
    if ctx:
        ctx.inverse_hook_funcs = {v: k for k, v in HookFuncs.items()}


# === 队列函数（迁移到ctx） ===
def i_queue(data):
    ctx = get_context()
    if ctx:
        ctx.log_queue.insert(0, data)


def p_queue():
    ctx = get_context()
    if ctx and ctx.log_queue:
        ctx.log_queue.pop()


def get_queue():
    ctx = get_context()
    return ctx.log_queue if ctx else []


def get_len():
    ctx = get_context()
    return len(ctx.log_queue) if ctx else 0


def get_size():
    ctx = get_context()
    return ctx.log_queue_size if ctx else 20


# ============================================================
# 向后兼容: 保留 GLOBAL_VAR 作为 get_context() 的代理
# 用于避免一次性修改大量代码
# 验收后可以删除此类
# ============================================================
class _GlobalVarProxy:
    """向后兼容代理 — 所有属性委托给 ctx"""
    
    # 默认值映射
    _defaults = {
        'ImageBaseStart': 0x140000000, 'ImageBaseEnd': 0x140000000,
        'DllEnd': 0x7FF000000000, 'HookRegion': 0x7FF010000000,
        'AllocateChunkEnd': 0x0000020000000000,
        'ProtectedFile': None, 'DirectoryPath': None,
        'DebugOption': False, 'DebugFlag': False,
        'BreakPoint': [], 'HookInt': 0,
        'SectionInfo': [], 'text': [], 'themida': [], 'boot': [],
        'InverseHookFuncs': {}, 'a_queue': [], 'queue_size': 20,
        'FindOEP': True, 'AllocateChunkStart': 0x0000020000000000,
    }
    
    # 属性名映射: proxy_name → ctx_attribute
    _map = {
        'ImageBaseStart': 'image_base', 'ImageBaseEnd': 'image_end',
        'DllEnd': 'dll_end', 'HookRegion': 'hook_region',
        'AllocateChunkEnd': 'allocate_chunk_end',
        'ProtectedFile': 'sample_path', 'DirectoryPath': 'directory_path',
        'DebugOption': 'debug_option', 'DebugFlag': 'debug_flag',
        'BreakPoint': 'breakpoints', 'HookInt': 'hook_int',
        'SectionInfo': 'section_info', 'text': 'text_section',
        'themida': 'themida_section', 'boot': 'boot_section',
        'InverseHookFuncs': 'inverse_hook_funcs',
        'a_queue': 'log_queue', 'queue_size': 'log_queue_size',
    }
    
    def __getattr__(self, name):
        ctx = get_context()
        if ctx:
            ctx_name = self._map.get(name)
            if ctx_name and hasattr(ctx, ctx_name):
                return getattr(ctx, ctx_name)
        return self._defaults.get(name)
    
    def __setattr__(self, name, value):
        if name in ('_defaults', '_map'):
            super().__setattr__(name, value)
            return
        ctx = get_context()
        if ctx:
            ctx_name = self._map.get(name)
            if ctx_name and hasattr(ctx, ctx_name):
                setattr(ctx, ctx_name, value)
                return
        self._defaults[name] = value


# 向后兼容的单例
GLOBAL_VAR = _GlobalVarProxy()
