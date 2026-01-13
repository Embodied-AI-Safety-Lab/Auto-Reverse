import os
import sys
import zipfile
import re
import json
import csv
from datetime import datetime

# ==================== 1. 环境配置 ====================
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

# 默认配置 (如果没有 config.py)
DEFAULT_APK_DIR = os.path.join(project_root, "Dataset", "Raw_APKs")
DEFAULT_RULES_PATH = os.path.join(project_root, "Tools", "rules.json")
DEFAULT_OUTPUT_DIR = os.path.join(project_root, "Dataset")

try:
    from Tools import config
    APK_DIR = config.APK_DIR
    RULES_PATH = config.RULES_PATH
    OUTPUT_DIR = config.OUTPUT_DIR
except ImportError:
    APK_DIR = DEFAULT_APK_DIR
    RULES_PATH = DEFAULT_RULES_PATH
    OUTPUT_DIR = DEFAULT_OUTPUT_DIR

OUTPUT_CSV = os.path.join(OUTPUT_DIR, "scan_report.csv")

# ==================== 2. 核心检测引擎 ====================
class AppScanner:
    def __init__(self):
        self.rules = self._load_rules()
        
        # 白名单 (针对 V25 算法)
        self.whitelist_names = {
            'bin', 'src', 'res', 'lib', 'libs', 'raw', 'xml', 'js', 'css', 
            'img', 'map', 'lua', 'html', 'data', 'conf', 'cfg', 'db', 'sql',
            'p12', 'pem', 'crt', 'key', 'id', 'v1', 'v2', 'v3', 'x86', 'arm',
            'www', 'public', 'assets', 'meta', 'inf', 'opt', 'etc', 'usr',
            'font', 'fonts', 'icon', 'icons', 'sound', 'sounds', 'video',
            'google', 'facebook', 'amazon', 'unity', 'vuforia', 'aliyun',
            'model', 'models', 'tflite', 'onnx', 'weights', 'ros', 'slam', 
            'dexopt', 'odex', 'oat' # 强制忽略优化文件
        }

    def _load_rules(self):
        rules = {}
        if os.path.exists(RULES_PATH):
            try:
                with open(RULES_PATH, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                print(f"[Init] 规则库加载成功: {RULES_PATH}")
            except: pass
        else:
            print(f"[Fatal] 找不到 rules.json")
            sys.exit(1)
        return rules

    def scan(self, apk_path):
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                file_list = zf.namelist()
                all_files_str = "\n".join(file_list)
                all_filenames_lower = set(f.split('/')[-1].lower() for f in file_list)
                
                # --- 1. Framework 优先 ---
                # Flutter (Strict)
                if any(re.search(r"lib/[^/]+/libflutter\.so", f) for f in file_list):
                    return "Framework", "Flutter"

                # React Native
                if "assets/index.android.bundle" in all_files_str: return "Framework", "React Native"
                if "libreactnativejni.so" in all_filenames_lower: return "Framework", "React Native"

                # Unity / Xamarin
                if "libunity.so" in all_filenames_lower: return "Framework", "Unity 3D"
                if "libmonodroid.so" in all_filenames_lower: return "Framework", "Xamarin/Mono"

                # --- 2. 规则匹配 (Packer & Mod) ---
                for p_name, rule_data in self.rules.items():
                    rule_type = rule_data.get("type", "packer").capitalize()
                    if rule_type == "Packer": rule_type = "Packed"
                    
                    # Libs 匹配
                    if "libs" in rule_data:
                        for sig in rule_data["libs"]:
                            if sig.lower() in all_filenames_lower:
                                return rule_type, f"{p_name} (Lib: {sig})"
                    
                    # Files 匹配
                    if "files" in rule_data:
                        for sig in rule_data["files"]:
                            if sig in all_files_str:
                                # [核心修复]：强制跳过 dexopt 相关的特征
                                if "dexopt" in sig.lower(): 
                                    continue 
                                return rule_type, f"{p_name} (File: {sig})"

                # --- 3. DexGuard 严格启发式 (V25/26 算法) ---
                is_obf, reason = self.detect_dexguard_strict(file_list)
                if is_obf:
                    return "Packed", reason

                # --- 4. 兜底检测 ---
                try:
                    if "classes.dex" in file_list:
                        info = zf.getinfo("classes.dex")
                        if info.file_size < 200 * 1024:
                             if any(f.endswith('.so') for f in file_list):
                                if "libunity.so" not in all_filenames_lower:
                                    return "Packed", f"未知壳 (Dex极小: {info.file_size}B)"
                except: pass

        except zipfile.BadZipFile:
            return "Error", "APK损坏"
        except Exception as e:
            return "Error", str(e)

        return "Native", "Unpacked"

    def detect_dexguard_strict(self, file_list):
        """
        寻找 Skydio 特征：大量无后缀的短乱码文件
        """
        suspicious_count = 0
        assets_total = 0
        
        for f in file_list:
            parts = f.split('/')
            
            # 只分析 assets 一级目录
            if len(parts) == 2 and parts[0] == 'assets':
                name = parts[1]
                if not name: continue
                
                # 白名单
                if name.lower() in self.whitelist_names: continue
                # [新增] 再次过滤 dexopt 文件夹
                if "dexopt" in name.lower(): continue

                assets_total += 1
                
                # 严苛条件：1-3位，纯字母数字，【无后缀】
                if 1 <= len(name) <= 3 and re.match(r'^[a-zA-Z0-9]+$', name):
                    if '.' not in name:
                        suspicious_count += 1

        # 阈值：数量 > 15 且 占比 > 50%
        if suspicious_count > 15:
            ratio = suspicious_count / assets_total
            if ratio > 0.5:
                return True, f"DexGuard/强混淆 (碎片文件 > 15, 密度 {int(ratio*100)}%)"
        
        return False, ""

# ==================== 3. 主程序 ====================
if __name__ == "__main__":
    print("="*60)
    print(f"APK 检测引擎 (V26.0 DexOpt 修复版)")
    print(f"输入: {APK_DIR}")
    print("="*60)

    if not os.path.exists(APK_DIR):
        print(f"[ERROR] 目录不存在: {APK_DIR}")
        exit(1)

    apk_tasks = [os.path.join(r, f) for r, d, fs in os.walk(APK_DIR) for f in fs if f.lower().endswith(".apk") and "install_" not in f]

    print(f"[队列] {len(apk_tasks)} 个任务")
    print("-" * 100)
    print(f"{'文件名':<35} | {'类型':<12} | {'详情'}")
    print("-" * 100)

    scanner = AppScanner()
    report_data = []
    stats = {"Packed": 0, "Native": 0, "Framework": 0, "Mod": 0, "Error": 0}

    for idx, apk_path in enumerate(apk_tasks, 1):
        file_name = os.path.basename(apk_path)
        category = os.path.relpath(os.path.dirname(apk_path), APK_DIR)
        
        res_type, res_info = scanner.scan(apk_path)
        
        if res_type in stats: stats[res_type] += 1
        else: stats["Native"] += 1

        print(f"[{idx}] {file_name[:35]:<35} | {res_type[:12]:<12} | {res_info}")

        report_data.append({
            "Category": category,
            "File Name": file_name,
            "Type": res_type,
            "Details": res_info
        })

    try:
        os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=["Category", "File Name", "Type", "Details"])
            writer.writeheader()
            writer.writerows(report_data)
        print(f"\n[报告] {OUTPUT_CSV}")
    except: pass

    print(f"统计: 壳:{stats['Packed']} | 挂:{stats['Mod']} | 框架:{stats['Framework']} | 原生:{stats['Native']}")