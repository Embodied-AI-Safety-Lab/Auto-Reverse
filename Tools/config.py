# Tools/config.py
import os
import shutil
import sys

# 获取项目根目录
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) # Tools 目录
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)              # 项目根目录

# 输入输出路径
APK_DIR = os.path.join(PROJECT_ROOT, "Dataset", "Raw_APKs")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "Dataset")
FRAME_DIR = os.path.join(OUTPUT_DIR, "Frame_Apps")
DECRYPTED_MODS = os.path.join(OUTPUT_DIR, "Decompiled_Mods")
DECOMPILED_DIR = os.path.join(OUTPUT_DIR, "Decompiled_Native")
OUT_UNPACKED_DIR = os.path.join(OUTPUT_DIR, "Decompiled_Unpacked")
DECRYPTED_TEMP = os.path.join(OUTPUT_DIR, "Temp_Decrypted")
# ================= 工具命令配置 =================

# 0. 规则库路径
RULES_PATH = os.path.join(CURRENT_DIR, "rules.json")

# 1. JADX 路径
# JADX 通常不加 PATH
JADX_PATH = os.path.join(CURRENT_DIR, "jadx-1.5.3", "bin", "jadx.bat")

# 2. AAPT 命令 (系统 PATH 已配置)
AAPT_COMMAND = "aapt"

# 3. ADB 命令 (系统 PATH 已配置)
ADB_COMMAND = "adb"

# ================= 辅助函数 =================
def check_tools():
    """启动前自检: 检查工具和规则库是否就绪"""
    missing = []
    
    # 检查 JADX (绝对路径)
    if not os.path.exists(JADX_PATH):
        missing.append(f"JADX 未找到 (请修改 config.py 中的路径): {JADX_PATH}")
    
    # 检查 AAPT (环境变量)
    if not shutil.which(AAPT_COMMAND):
        missing.append(f"AAPT 未找到 (请确保已添加至 PATH)")
        
    # 检查 ADB (环境变量)
    if not shutil.which(ADB_COMMAND):
        missing.append(f"ADB 未找到 (请确保已添加至 PATH)")
        
     # 检查 rules.json (规则库)
    if not os.path.exists(RULES_PATH):
        missing.append(f"规则库文件丢失 (请创建): {RULES_PATH}")    
    return missing