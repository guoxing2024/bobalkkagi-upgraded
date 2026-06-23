"""
TLS Rebuilder — TLS目录恢复
=============================
Bobalkkagi升级 — P3: TLS恢复

从原始PE中提取TLS目录，重建到dump后的PE中。
TLS回调在Themida样本中常用于反调试/初始化，必须恢复。
"""

import struct
import logging

logger = logging.getLogger("Bobalkkagi.TLSRebuilder")


def rebuild_tls(dump_data, orig_pe, image_base=0x140000000):
    """
    从原始PE拷贝TLS目录到dump中。
    
    Args:
        dump_data: bytearray — dump文件数据（将被修改）
        orig_pe: pefile.PE — 原始受保护PE
        image_base: int — dump的镜像基址
    
    Returns: bool — 是否成功
    """
    # Step 1: 检查原始PE是否有TLS目录
    tls_dir = orig_pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]  # IMAGE_DIRECTORY_ENTRY_TLS
    if not tls_dir.VirtualAddress or not tls_dir.Size:
        return False
    
    # Step 2: 获取TLS目录数据
    try:
        tls_data = orig_pe.get_data(tls_dir.VirtualAddress, tls_dir.Size)
    except:
        return False
    
    if not tls_data or len(tls_data) < 24:
        return False
    
    # Step 3: 解析TLS结构并修正地址
    # IMAGE_TLS_DIRECTORY64:
    #   StartAddressOfRawData: 8 bytes
    #   EndAddressOfRawData: 8 bytes
    #   AddressOfIndex: 8 bytes
    #   AddressOfCallbacks: 8 bytes
    #   SizeOfZeroFill: 4 bytes
    #   Characteristics: 4 bytes
    
    if len(tls_data) >= 40:
        # 读取TLS回调地址表
        callback_va = struct.unpack('<Q', tls_data[24:32])[0]
        
        # Step 4: 将TLS目录写入dump的相同RVA位置
        # （需要找到dump中对应VA的空间）
        data_offset = tls_dir.VirtualAddress  # flat dump: offset = VA
        if data_offset + len(tls_data) <= len(dump_data):
            dump_data[data_offset:data_offset + len(tls_data)] = tls_data
            logger.info(f"TLS restored @ 0x{data_offset:x} ({len(tls_data)} bytes)")
            
            if callback_va:
                logger.info(f"TLS callbacks at 0x{callback_va:x}")
            return True
        else:
            logger.warning(f"TLS directory 0x{data_offset:x} outside dump file")
    
    return False
