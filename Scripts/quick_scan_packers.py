import os
import sys
import zipfile
import json
import csv
import subprocess
from datetime import datetime

# ==================== 1. 环境与路径配置 ====================
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

# 默认路径
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

# ==================== 2. 规则加载器 ====================
class RuleLoader:
    def __init__(self, path):
        self.rules = self._load(path)
    
    def _load(self, path):
        if not os.path.exists(path):
            print(f"[Fatal] 找不到规则文件: {path}")
            print("请创建 Tools/rules.json，否则无法进行静态特征匹配。")
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"[Init] 成功加载规则库: {len(data.get('Packers', {}))} Packers, {len(data.get('Mods', {}))} Mods")
                return data
        except Exception as e:
            print(f"[Error] 规则文件 JSON 格式错误: {e}")
            return {}

    def scan_zip_entries(self, zip_file_list):
        """
        遍历 ZIP 内的所有文件，按优先级匹配规则
        优先级: Packers > Mods > Frameworks
        返回: (Is_Hit, Type, Name, Category)
        """
        if not self.rules: return False, "Native", "Unknown", "Native"

        # 1. 优先检查 Packers (必须脱壳)
        if "Packers" in self.rules:
            for name, data in self.rules["Packers"].items():
                for sig in data.get("files", []):
                    # 精确匹配 or 路径匹配
                    if any(sig == f.split('/')[-1] or ("/" in sig and sig in f) for f in zip_file_list):
                        return True, "Packed", name, "Packers"

        # 2. 其次检查 Mods (视为有壳/修改)
        if "Mods" in self.rules:
            for name, data in self.rules["Mods"].items():
                for sig in data.get("files", []):
                    if any(sig == f.split('/')[-1] or ("/" in sig and sig in f) for f in zip_file_list):
                        return True, "Mod", name, "Mods"

        # 3. 最后检查 Frameworks (无壳，但记录类型)
        if "Frameworks" in self.rules:
            for name, data in self.rules["Frameworks"].items():
                for sig in data.get("files", []):
                    if any(sig == f.split('/')[-1] or ("/" in sig and sig in f) for f in zip_file_list):
                        return True, "Framework", name, "Frameworks"
        
        return False, "Native", "Clean", "Native"

# ==================== 3. APKiD 调用模块 ====================
class ApkidWrapper:
    @staticmethod
    def scan(apk_path):
        """调用 APKiD 并返回 JSON 数据"""
        try:
            # --typing none: 专注查壳，速度最快
            cmd = ["apkid", "-j", "--typing", "none", apk_path]
            
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            result = subprocess.run(cmd, capture_output=True, text=True, startupinfo=startupinfo)
            
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except: pass
        return {}

# ==================== 4. 智能检测核心 ====================
class SmartDetector:
    def __init__(self, rules_path):
        self.rule_loader = RuleLoader(rules_path)

    def check(self, apk_path):
        """
        返回: (Has_Shell: str, Type: str, Detail: str)
        Has_Shell: "YES" / "NO"
        Type: Packed / Mod / Framework / Native
        """
        # [Step 1] 静态规则匹配 (基于 rules.json)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                file_list = zf.namelist()
                is_hit, r_type, r_name, r_cat = self.rule_loader.scan_zip_entries(file_list)
                
                if is_hit:
                    # 如果是 Packer 或 Mod -> YES
                    if r_cat in ["Packers", "Mods"]:
                        return "YES", r_type, f"Rule: {r_name}"
                    # 如果是 Framework -> NO (但在 Detail 里记录)
                    if r_cat == "Frameworks":
                        # 注意：这里我们暂定为 NO，但为了防止 Framework 实际上被 APKiD 查出有壳，
                        # 我们可以选择直接返回，或者继续跑 APKiD。
                        # 策略：为了速度，如果命中 Framework 且没命中 Packer，通常就是无壳。
                        return "NO", r_type, f"Framework: {r_name}"

        except zipfile.BadZipFile:
            return "NO", "Error", "Bad Zip"
        except Exception as e:
            return "NO", "Error", str(e)

        # [Step 2] APKiD 深度扫描 (兜底)
        # 如果静态规则完全没命中 (Native)，或者刚才只命中了 Framework (想二次确认可以放开，但这里暂且认为Native需要查)
        apkid_data = ApkidWrapper.scan(apk_path)
        if apk_path in apkid_data:
            matches = apkid_data[apk_path]
            
            # A. Packer -> YES
            if "packer" in matches:
                return "YES", "Packed", f"APKiD: {matches['packer'][0]}"

            # B. Anti-Debug -> YES
            if "anti_debug" in matches:
                return "YES", "Packed", "APKiD: Anti-Debug Detected"

            # C. Obfuscator -> 智能过滤
            if "dex_obfuscator" in matches:
                obfuscators = matches["dex_obfuscator"]
                real_shells = []
                for obf in obfuscators:
                    # DexGuard / AESObfuscator -> YES
                    if "DexGuard" in obf or "AESObfuscator" in obf:
                        real_shells.append(obf)
                
                if real_shells:
                    return "YES", "Packed", f"APKiD: {', '.join(real_shells)}"
                else:
                    # ProGuard / R8 -> NO
                    return "NO", "Native", f"Clean (Ignored: {', '.join(obfuscators)})"

        # [Step 3] 没任何发现 -> NO
        return "NO", "Native", "Clean"

# ==================== 5. 主程序 ====================
if __name__ == "__main__":
    print("="*60)
    print(f"APK 壳检测器")
    print(f"规则: {RULES_PATH}")
    print(f"目录: {APK_DIR}")
    print("="*60)

    if not os.path.exists(APK_DIR):
        print("[ERROR] APK 目录不存在")
        exit(1)

    apk_tasks = []
    for root, dirs, files in os.walk(APK_DIR):
        for f in files:
            if f.lower().endswith(".apk") and not f.startswith("._"):
                apk_tasks.append(os.path.join(root, f))

    print(f"[队列] {len(apk_tasks)} 个样本")
    
    # 初始化
    detector = SmartDetector(RULES_PATH)
    report_data = []
    
    stats = {"YES": 0, "NO": 0}

    print("-" * 110)
    print(f"{'有壳?':<6} | {'类型':<10} | {'详情':<50} | {'文件名'}")
    print("-" * 110)

    for idx, apk_path in enumerate(apk_tasks, 1):
        file_name = os.path.basename(apk_path)
        category = os.path.relpath(os.path.dirname(apk_path), APK_DIR)
        
        # 执行检测
        has_shell, res_type, reason = detector.check(apk_path)
        
        stats[has_shell] += 1
        
        print(f"{has_shell:<6} | {res_type:<10} | {reason[:50]:<50} | {file_name}")

        report_data.append({
            "File Name": file_name,
            "Category": category,
            "Has_Shell": has_shell,  # 关键列
            "Type": res_type,        # Packed/Mod/Framework/Native
            "Details": reason,
            "Full Path": apk_path
        })

    try:
        os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8-sig') as f:
            fieldnames = ["File Name", "Category", "Has_Shell", "Type", "Details", "Full Path"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(report_data)
        
        print("-" * 110)
        print(f"✅ 统计: 有壳(YES): {stats['YES']} | 无壳(NO): {stats['NO']}")
        print(f"📄 报告: {OUTPUT_CSV}")
    except Exception as e:
        print(f"CSV Error: {e}")