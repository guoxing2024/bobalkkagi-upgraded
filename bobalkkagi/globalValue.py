"""
Global Bridge — GLOBAL_VAR 到 UnpackContext 的平滑迁移

策略：
  - 当 ctx 被设置后，GLOBAL_VAR 的读写委托给 ctx
  - 原有代码零改动
  - 新代码使用 ctx 直接访问
  - 验收：全项目搜索 GLOBAL_VAR 发现全通过桥接层

用法：
  ctx = UnpackContext("sample.exe")
  bind_context(ctx)       # 此后 GLOBAL_VAR.xxx = ctx.xxx

  # 旧代码继续工作：
  GLOBAL_VAR.ImageBaseStart  # → ctx.image_base

  # 新代码直接用 ctx：
  ctx.image_base
"""

from .core.context import UnpackContext


class _GlobalVarBridge:
    """
    全局状态桥接器。
    
    当 _ctx 为 None 时，使用自身存储（兼容旧版）。
    当 _ctx 被设置后，所有属性读写委托给 UnpackContext。
    """
    
    _ctx: 'UnpackContext' = None
    
    # === 映射表：GLOBAL_VAR属性 → ctx属性 ===
    _attr_map = {
        'ImageBaseStart': 'image_base',
        'ImageBaseEnd': 'image_end',
        'DllEnd': None,  # 通过 modules 管理
        'AllocateChunkEnd': None,  # 动态分配
        'HookRegion': None,  # 内部使用
        'ProtectedFile': 'sample_path',
        'DirectoryPath': None,  # 配置
        'DebugOption': None,  # 调试
        'DebugFlag': None,  # 调试
        'BreakPoint': None,  # 调试
        'theMida': None,  # section追踪
        'boot': None,  # section追踪
        'text': None,  # section追踪
        'SectionInfo': None,  # section追踪
        'InverseHookFuncs': None,  # hook系统
        'a_queue': None,  # 日志队列
        'queue_size': None,  # 日志队列
        'HookInt': None,  # Unicorn hook句柄
    }
    
    # === 旧版默认值 ===
    ImageBaseStart = 0x140000000
    ImageBaseEnd = 0x140000000
    DllEnd = 0x7FF000000000
    AllocateChunkStart = 0x0000020000000000
    AllocateChunkEnd = 0x0000020000000000
    HookRegion = 0x7FF010000000
    FindOEP = True
    DebugOption = False
    DebugFlag = False
    BreakPoint = []
    HookInt = 0
    SectionInfo = []
    InverseHookFuncs = {}
    ProtectedFile = None
    DirectoryPath = None
    a_queue = []
    queue_size = 20
    text = []
    themida = []
    boot = []
    
    def __getattr__(self, name):
        """委托给 ctx 或返回自身值"""
        if self._ctx is not None:
            ctx_name = self._attr_map.get(name)
            if ctx_name and hasattr(self._ctx, ctx_name):
                return getattr(self._ctx, ctx_name)
        
        # Fall back to stored value
        if name in self.__dict__:
            return self.__dict__[name]
        if name in type(self).__dict__:
            return type(self).__dict__[name]
        raise AttributeError(f"GLOBAL_VAR has no attribute '{name}'")
    
    def __setattr__(self, name, value):
        """委托给 ctx 或写入自身"""
        if name.startswith('_'):
            super().__setattr__(name, value)
            return
        
        if self._ctx is not None:
            ctx_name = self._attr_map.get(name)
            if ctx_name and hasattr(self._ctx, ctx_name):
                setattr(self._ctx, ctx_name, value)
                return
        
        super().__setattr__(name, value)
    
    def bind(self, ctx: 'UnpackContext'):
        """绑定到 UnpackContext"""
        self._ctx = ctx
        # 同步现有状态
        ctx.image_base = self.ImageBaseStart
        ctx.image_end = self.ImageBaseEnd
        ctx.sample_path = self.ProtectedFile if self.ProtectedFile else ctx.sample_path
    
    def unbind(self):
        """解绑"""
        self._ctx = None


# 全局单例
GLOBAL_VAR = _GlobalVarBridge()


def bind_context(ctx: 'UnpackContext'):
    """将 UnpackContext 绑定到 GLOBAL_VAR"""
    GLOBAL_VAR.bind(ctx)


def unbind_context():
    """解绑"""
    GLOBAL_VAR.unbind()


# === DLL_SETTING 保持不变（DLL加载状态，与样本无关） ===
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
    GLOBAL_VAR.InverseHookFuncs = {v: k for k, v in HookFuncs.items()}


# === 队列函数（保持不变） ===
def i_queue(data):
    GLOBAL_VAR.a_queue.insert(0, data)

def p_queue():
    GLOBAL_VAR.a_queue.pop()

def get_queue():
    return GLOBAL_VAR.a_queue

def get_len():
    return len(GLOBAL_VAR.a_queue)

def get_size():
    return GLOBAL_VAR.queue_size
