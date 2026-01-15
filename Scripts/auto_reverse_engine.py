import os
import sys
import shutil
import time
import subprocess
import re
import uuid
import struct
import zlib
import hashlib
from quick_scan_packers import SmartDetector

# ==================== 1. 配置与常量 ====================
try:
    from Tools import config
except ImportError:
    print("[Error] 找不到 config.py，请确保 Tools/config.py 存在")
    sys.exit(1)

# 脱壳配置
DUMP_TARGET_FOLDER = "hyhzz"
WAIT_TIME_FOR_UNPACK = 25
JADX_TIMEOUT = 300 

# 输出根目录
RESULTS_ROOT = os.path.join(os.path.dirname(config.APK_DIR), "Results")
FRAMEWORK_ROOT = os.path.join(RESULTS_ROOT, "Framework")

# 临时工作区
TEMP_WORKSPACE = config.DECRYPTED_TEMP

# ==================== 2. DEX 修复技师 ====================
class DexRepairman:
    @staticmethod
    def fix_single_file(file_path):
        try:
            with open(file_path, 'rb') as f:
                data = bytearray(f.read())
            if len(data) < 112: return False

            # 修复 Magic, Size, Endian
            struct.pack_into('8s', data, 0, b'dex\n035\0')
            file_len = len(data)
            struct.pack_into('<I', data, 32, file_len)
            struct.pack_into('<I', data, 36, 112)
            struct.pack_into('<I', data, 40, 0x12345678)

            # 重算签名
            sha1 = hashlib.sha1(data[32:]).digest()
            struct.pack_into('20s', data, 12, sha1)
            adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
            struct.pack_into('<I', data, 8, adler)

            with open(file_path, 'wb') as f:
                f.write(data)
            return True
        except: return False

    @staticmethod
    def repair_folder(folder_path):
        print(f"   -> [Auto-Fix] 正在深度修复 DEX 文件头...")
        count = 0
        for root, dirs, files in os.walk(folder_path):
            for f in files:
                if f.endswith(".dex"):
                    if DexRepairman.fix_single_file(os.path.join(root, f)):
                        count += 1
        print(f"   -> [Auto-Fix] 已修复 {count} 个文件。")

# ==================== 3. 基础工具类 ====================
class EnvironmentJanitor:
    @staticmethod
    def clean_local_temp():
        if os.path.exists(TEMP_WORKSPACE):
            try: shutil.rmtree(TEMP_WORKSPACE)
            except: pass
        os.makedirs(TEMP_WORKSPACE, exist_ok=True)

    @staticmethod
    def clean_device_before_run(pkg_name):
        try:
            subprocess.run([config.ADB_COMMAND, "uninstall", pkg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([config.ADB_COMMAND, "shell", f"rm -rf /sdcard/{pkg_name}_dump*"], stdout=subprocess.DEVNULL)
            subprocess.run([config.ADB_COMMAND, "shell", "su", "-c", f"rm -rf /data/data/{pkg_name}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

class FileSanitizer:
    @staticmethod
    def prepare_safe_apk(original_path):
        if not os.path.exists(TEMP_WORKSPACE): os.makedirs(TEMP_WORKSPACE)
        safe_name = f"proc_{uuid.uuid4().hex[:8]}.apk"
        safe_path = os.path.join(TEMP_WORKSPACE, safe_name)
        try:
            shutil.copy(original_path, safe_path)
            return safe_path
        except: return None

class AndroidTools:
    @staticmethod
    def check_adb_alive():
        try:
            res = subprocess.check_output([config.ADB_COMMAND, "devices"], stderr=subprocess.STDOUT).decode()
            if "device" not in res.replace("List of devices attached", "").strip():
                return False
            return True
        except: return False

    @staticmethod
    def get_package_info(apk_path):
        cmd = [config.AAPT_COMMAND, "dump", "badging", apk_path]
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            package = re.search(r"package: name='([^']+)'", res)
            activity = re.search(r"launchable-activity: name='([^']+)'", res)
            return (package.group(1) if package else None), (activity.group(1) if activity else None)
        except: return None, None

    @staticmethod
    def install_and_run(apk_path, pkg_name, main_activity):
        print(f"   -> 正在安装 (Monkey Mode)...")
        subprocess.run([config.ADB_COMMAND, "install", "-r", "-t", "-g", apk_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"   -> 正在启动: {pkg_name}...")
        monkey_cmd = f"monkey -p {pkg_name} -c android.intent.category.LAUNCHER 1"
        subprocess.run([config.ADB_COMMAND, "shell", monkey_cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if main_activity:
            time.sleep(3)
            cmd = f"am start -n {pkg_name}/{main_activity}"
            subprocess.run([config.ADB_COMMAND, "shell", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def pull_dump_files(pkg_name, output_dir):
        try:
            subprocess.check_output([config.ADB_COMMAND, "shell", f"su -c 'ls -d /data/data/{pkg_name}/{DUMP_TARGET_FOLDER}'"], stderr=subprocess.STDOUT)
        except:
            print(f"   [Failed] 未检测到 hyhzz")
            return None

        print(f"   -> 正在拉取并修复...")
        tar_path = f"/sdcard/{pkg_name}_dump.tar"
        subprocess.run([config.ADB_COMMAND, "shell", f"su -c 'tar -cf {tar_path} -C /data/data/{pkg_name}/ {DUMP_TARGET_FOLDER}'"], stdout=subprocess.PIPE)
        subprocess.run([config.ADB_COMMAND, "shell", f"chmod 777 {tar_path}"], stdout=subprocess.DEVNULL)

        local_dump_path = os.path.join(output_dir, "dumped_dex")
        if os.path.exists(local_dump_path): shutil.rmtree(local_dump_path)
        os.makedirs(local_dump_path, exist_ok=True)
        
        safe_temp_tar = os.path.join(TEMP_WORKSPACE, f"pull_{uuid.uuid4().hex}.tar")
        if subprocess.run([config.ADB_COMMAND, "pull", tar_path, safe_temp_tar], stdout=subprocess.DEVNULL).returncode != 0:
            return None

        local_tar_file = os.path.join(local_dump_path, "dump.tar")
        shutil.move(safe_temp_tar, local_tar_file)
        
        import tarfile, warnings
        warnings.filterwarnings("ignore")
        try:
            with tarfile.open(local_tar_file, "r") as tar: tar.extractall(path=local_dump_path)
            os.remove(local_tar_file)
            
            nested = os.path.join(local_dump_path, DUMP_TARGET_FOLDER)
            if os.path.exists(nested):
                for f in os.listdir(nested): shutil.move(os.path.join(nested, f), local_dump_path)
                os.rmdir(nested)
            
            DexRepairman.repair_folder(local_dump_path)
            return local_dump_path
        except: return None

class JadxEngine:
    @staticmethod
    def decompile(input_path, output_dir, desc="反编译"):
        if not os.path.exists(input_path): return
        print(f"   -> {desc} (JADX)...")
        cmd = [config.JADX_PATH, "-d", output_dir, input_path, "--no-imports", "--show-bad-code"] 
        
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=JADX_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"   [Error] JADX 反编译超时 ({JADX_TIMEOUT}s)，强制跳过！")
            with open(os.path.join(output_dir, "DECOMPILE_TIMEOUT_ERROR.txt"), "w") as f:
                f.write("JADX process timed out.")

    @staticmethod
    def merge_resources(original_apk_path, decompiled_source_dir):
        temp_res_dir = os.path.join(TEMP_WORKSPACE, "res_" + uuid.uuid4().hex[:6])
        JadxEngine.decompile(original_apk_path, temp_res_dir, desc="提取资源")
        for item in ["resources", "AndroidManifest.xml"]:
            src = os.path.join(temp_res_dir, item)
            dst = os.path.join(decompiled_source_dir, item)
            if os.path.exists(src):
                if os.path.exists(dst) and os.path.isdir(dst): shutil.rmtree(dst)
                if os.path.isdir(src): shutil.copytree(src, dst)
                else: shutil.copy(src, dst)
        shutil.rmtree(temp_res_dir, ignore_errors=True)

# ==================== 4. 主流程 ====================
def main():
    print("="*60)
    print(f"自动化逆向引擎")
    print(f"输出根目录: {RESULTS_ROOT}")
    print("="*60)

    EnvironmentJanitor.clean_local_temp()
    
    if not AndroidTools.check_adb_alive():
        print("[Fatal] 未检测到 Android 设备！请连接手机并开启 USB 调试。")
        sys.exit(1)

    # 初始化检测器，传入 rules 路径
    scanner = SmartDetector(config.RULES_PATH)

    info_log_path = os.path.join(FRAMEWORK_ROOT, "info.txt")
    if not os.path.exists(FRAMEWORK_ROOT):
        os.makedirs(FRAMEWORK_ROOT)
        with open(info_log_path, "w", encoding="utf-8") as f:
            f.write("Filename | Original Category | Framework Type | Process Time\n")
            f.write("-" * 80 + "\n")
    
    all_tasks = []
    for root, dirs, files in os.walk(config.APK_DIR):
        for f in files:
            if f.endswith(".apk"):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(root, config.APK_DIR)
                all_tasks.append((full_path, rel_path))
    
    for idx, (raw_apk_path, category_path) in enumerate(all_tasks, 1):
        original_name = os.path.basename(raw_apk_path)
        print(f"\n[{idx}/{len(all_tasks)}] 处理: {original_name}")

        pkg_name_quick, _ = AndroidTools.get_package_info(raw_apk_path)
        if pkg_name_quick:
             folder_name = f"{os.path.splitext(original_name)[0]}_{pkg_name_quick}"
             folder_name = re.sub(r'[\\/*?:"<>|]', "_", folder_name)
             
             potential_paths = [
                 os.path.join(RESULTS_ROOT, category_path, folder_name), 
                 os.path.join(FRAMEWORK_ROOT, "Flutter", original_name),
                 os.path.join(FRAMEWORK_ROOT, "Unity", original_name),
                 os.path.join(FRAMEWORK_ROOT, "React", original_name)
             ]
             
             already_done = False
             for p in potential_paths:
                 if os.path.exists(p):
                     already_done = True
                     break
             
             if already_done:
                 print(f"   [Skip] 目标已存在，跳过处理。")
                 continue

        safe_apk_path = FileSanitizer.prepare_safe_apk(raw_apk_path)
        if not safe_apk_path: continue

        try:
            # 调用 check() 并接收 3 个返回值
            # has_shell: "YES"/"NO"
            # type_major: "Packed", "Mod", "Framework", "Native"
            # type_detail: 具体描述
            has_shell, type_major, type_detail = scanner.check(safe_apk_path)
            
            print(f"   -> 识别结果: [{type_major}] {type_detail} (Shell: {has_shell})")

            pkg_name, main_activity = AndroidTools.get_package_info(safe_apk_path)
            if not pkg_name:
                print("   [Skip] 无效 APK")
                continue
            
            folder_name = f"{os.path.splitext(original_name)[0]}_{pkg_name}"
            folder_name = re.sub(r'[\\/*?:"<>|]', "_", folder_name)

            # [B] 分流逻辑 (逻辑保持不变，但基于新的 type_major)
            
            # ---> 1. 框架: 扁平归档
            if type_major == "Framework":
                sub_type = re.sub(r'[\\/*?:"<>|]', "", type_detail.split()[1] if ":" in type_detail else type_detail)
                target_flat_dir = os.path.join(FRAMEWORK_ROOT, sub_type)
                os.makedirs(target_flat_dir, exist_ok=True)
                
                target_file_path = os.path.join(target_flat_dir, original_name)
                if os.path.exists(target_file_path): 
                      name, ext = os.path.splitext(original_name)
                      target_file_path = os.path.join(target_flat_dir, f"{name}_{uuid.uuid4().hex[:4]}{ext}")

                shutil.copy(raw_apk_path, target_file_path)

                log_line = f"{os.path.basename(target_file_path)} | {category_path} | {type_detail} | {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                with open(info_log_path, "a", encoding="utf-8") as f: f.write(log_line)
                    
                print(f"   -> [归档] 已保存: {target_file_path}")
                continue

            # ---> 2. 其他: 镜像结构
            else:
                final_app_dir = os.path.join(RESULTS_ROOT, category_path, folder_name)

            # [C] 核心处理
            
            # Mod (破解版，视作有壳处理，但通常不需要脱壳机，直接反编译)
            if type_major == "Mod":
                JadxEngine.decompile(safe_apk_path, final_app_dir)
                print(f"   [Finish] Mod 反编译完成")

            # Packed (有壳，必须上机脱壳)
            elif type_major == "Packed":
                if not main_activity:
                    print("   [Skip] 无入口")
                    continue
                
                print("   -> [Packed] 启动脱壳流水线...")
                EnvironmentJanitor.clean_device_before_run(pkg_name)
                AndroidTools.install_and_run(safe_apk_path, pkg_name, main_activity)
                
                print(f"   -> 等待脱壳 ({WAIT_TIME_FOR_UNPACK}s)...")
                time.sleep(WAIT_TIME_FOR_UNPACK)
                
                dumped_dir = AndroidTools.pull_dump_files(pkg_name, final_app_dir)
                subprocess.run([config.ADB_COMMAND, "uninstall", pkg_name], stdout=subprocess.DEVNULL)

                if dumped_dir:
                    src_out = os.path.join(final_app_dir, "source_code")
                    JadxEngine.decompile(dumped_dir, src_out, desc="反编译DEX")
                    JadxEngine.merge_resources(safe_apk_path, src_out)
                    print(f"   [Finish] 完成: {src_out}")
                else:
                    print("   [Failed] 脱壳失败")

            # Native (无壳)
            else:
                JadxEngine.decompile(safe_apk_path, final_app_dir)
                print(f"   [Finish] 完成")

        except Exception as e:
            print(f"   [Error] 流程异常: {e}")
        finally:
            if os.path.exists(safe_apk_path):
                try: os.remove(safe_apk_path)
                except: pass

    EnvironmentJanitor.clean_local_temp()
    print("\n所有任务已完成。")

if __name__ == "__main__":
    main()