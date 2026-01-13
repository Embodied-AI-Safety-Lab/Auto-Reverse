import os
import sys
import shutil
import time
import subprocess
import re
import uuid
from quick_scan_packers import AppScanner

# ==================== 1. 配置与常量 ====================
try:
    from Tools import config
except ImportError:
    print("[Error] 找不到 config.py，请确保 Tools/config.py 存在")
    sys.exit(1)

# 【核心配置】脱壳目标文件夹 
DUMP_TARGET_FOLDER = "hyhzz"
# 【核心配置】脱壳等待时间 (秒)
WAIT_TIME_FOR_UNPACK = 15  

# 输出路径配置 (使用你 config.py 中的定义)
OUT_FRAME = config.FRAME_DIR
OUT_NATIVE = config.DECOMPILED_DIR
OUT_MOD = config.DECRYPTED_MODS
OUT_UNPACKED = config.OUT_UNPACKED_DIR
TEMP_WORKSPACE = config.DECRYPTED_TEMP

# ==================== 2. 清洁工与安全工具 ====================
class EnvironmentJanitor:
    """负责清理脏数据，保证环境无菌"""
    @staticmethod
    def clean_local_temp():
        """清理电脑上的临时工作区"""
        if os.path.exists(TEMP_WORKSPACE):
            try: shutil.rmtree(TEMP_WORKSPACE)
            except: pass
        os.makedirs(TEMP_WORKSPACE, exist_ok=True)

    @staticmethod
    def clean_device_before_run(pkg_name):
        """任务开始前的手机端清理"""
        # 1. 卸载应用
        subprocess.run([config.ADB_COMMAND, "uninstall", pkg_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 2. 清理 SD 卡残留
        sdcard_path = f"/sdcard/{pkg_name}_dump"
        tar_path = f"/sdcard/{pkg_name}_dump.tar"
        subprocess.run([config.ADB_COMMAND, "shell", f"rm -rf {sdcard_path}"], stdout=subprocess.DEVNULL)
        subprocess.run([config.ADB_COMMAND, "shell", f"rm {tar_path}"], stdout=subprocess.DEVNULL)
        
        # 3. 清理私有目录 (需要 Root)
        subprocess.run([config.ADB_COMMAND, "shell", "su", "-c", f"rm -rf /data/data/{pkg_name}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

class FileSanitizer:
    """负责处理文件名，避免中文路径导致 ADB/JADX 报错"""
    @staticmethod
    def prepare_safe_apk(original_path):
        """复制 APK 到临时目录并重命名为纯英文"""
        if not os.path.exists(TEMP_WORKSPACE): os.makedirs(TEMP_WORKSPACE)
        
        # 生成唯一文件名
        safe_name = f"proc_{uuid.uuid4().hex[:8]}.apk"
        safe_path = os.path.join(TEMP_WORKSPACE, safe_name)
        
        try:
            shutil.copy(original_path, safe_path)
            return safe_path
        except Exception as e:
            print(f"[Error] 无法复制临时文件: {e}")
            return None

# ==================== 3. 核心工具类 ====================
class AndroidTools:
    @staticmethod
    def get_package_info(apk_path):
        """获取包名和入口 Activity"""
        cmd = [config.AAPT_COMMAND, "dump", "badging", apk_path]
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            package = re.search(r"package: name='([^']+)'", res)
            activity = re.search(r"launchable-activity: name='([^']+)'", res)
            return (package.group(1) if package else None), (activity.group(1) if activity else None)
        except: return None, None

    @staticmethod
    def install_and_run(apk_path, pkg_name, main_activity):
        """安装并启动 APP (Monkey 增强版 - 必选)"""
        print(f"   -> 正在安装 (Grant Permissions)...")
        # -g: 授予所有权限，防止弹窗
        # -t: 允许测试包
        subprocess.run([config.ADB_COMMAND, "install", "-r", "-t", "-g", apk_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"   -> 正在启动: {pkg_name}...")
        
        # 使用 Monkey 启动，防止壳应用打不开
        monkey_cmd = f"monkey -p {pkg_name} -c android.intent.category.LAUNCHER 1"
        subprocess.run([config.ADB_COMMAND, "shell", monkey_cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 兜底：如果 Monkey 没反应，尝试 am start
        if main_activity:
            time.sleep(3)
            cmd = f"am start -n {pkg_name}/{main_activity}"
            subprocess.run([config.ADB_COMMAND, "shell", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def pull_dump_files(pkg_name, output_dir):
        print(f"   -> [Debug] 正在检查手机内部环境...")
        
        # 1. 检查 hyhzz 是否存在
        check_cmd = f"su -c 'ls -d /data/data/{pkg_name}/{DUMP_TARGET_FOLDER}'"
        try:
            subprocess.check_output([config.ADB_COMMAND, "shell", check_cmd], stderr=subprocess.STDOUT)
            print(f"   -> 确认脱壳文件夹存在: {DUMP_TARGET_FOLDER}")
        except:
            print(f"   [!!!] 未找到 {DUMP_TARGET_FOLDER} 文件夹 (脱壳失败)")
            return None

        # 2. 手机端打包
        print(f"   -> 正在打包文件 (tar)...")
        tar_path = f"/sdcard/{pkg_name}_dump.tar"
        tar_cmd = f"su -c 'tar -cf {tar_path} -C /data/data/{pkg_name}/ {DUMP_TARGET_FOLDER}'"
        
        res = subprocess.run([config.ADB_COMMAND, "shell", tar_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode != 0:
            print(f"   [Error] 手机端打包失败: {res.stderr.decode('utf-8')}")
            return None
        subprocess.run([config.ADB_COMMAND, "shell", f"chmod 777 {tar_path}"], stdout=subprocess.DEVNULL)

        # 3. 准备本地路径
        # 最终目标目录 (可能含中文)
        local_dump_path = os.path.join(output_dir, "dumped_dex")
        if os.path.exists(local_dump_path): shutil.rmtree(local_dump_path)
        os.makedirs(local_dump_path, exist_ok=True)
        
        # 中转临时文件 (纯英文路径，避免 ADB 报错)
        safe_temp_tar = os.path.join(TEMP_WORKSPACE, f"pull_{uuid.uuid4().hex}.tar")
        
        print(f"   -> 拉取压缩包 (使用安全中转路径)...")
        
        # 4. ADB Pull 到纯英文临时目录
        pull_res = subprocess.run([config.ADB_COMMAND, "pull", tar_path, safe_temp_tar], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if pull_res.returncode != 0:
            print(f"   [Error] ADB Pull 失败: {pull_res.stderr.decode('utf-8')}")
            return None

        # 5. Python 负责移动 (Python 处理中文没问题)
        local_tar_file = os.path.join(local_dump_path, "dump.tar")
        shutil.move(safe_temp_tar, local_tar_file)

        # 6. 本地解压
        import tarfile
        try:
            print(f"   -> 正在解压...")
            # 忽略 Python 3.14 的警告
            import warnings
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            
            with tarfile.open(local_tar_file, "r") as tar:
                # 兼容性处理：extractall 会自动解压到当前目录
                tar.extractall(path=local_dump_path)
            
            # 清理
            os.remove(local_tar_file)
            subprocess.run([config.ADB_COMMAND, "shell", f"rm {tar_path}"], stdout=subprocess.DEVNULL)
            
            # 整理层级
            nested_dir = os.path.join(local_dump_path, DUMP_TARGET_FOLDER)
            if os.path.exists(nested_dir):
                for f in os.listdir(nested_dir):
                    shutil.move(os.path.join(nested_dir, f), local_dump_path)
                os.rmdir(nested_dir)
                
            files = os.listdir(local_dump_path)
            if len(files) > 0:
                print(f"   [Success] 成功提取 {len(files)} 个文件")
                return local_dump_path
            else:
                print("   [Failed] 解压后目录为空")
                return None

        except Exception as e:
            print(f"   [Error] 解压失败: {e}")
            return None

class JadxEngine:
    @staticmethod
    def decompile(input_path, output_dir, desc="反编译"):
        """调用 JADX 反编译"""
        if not os.path.exists(input_path): return
        print(f"   -> {desc}...")
        # -d: 输出目录, --no-imports: 加快速度
        cmd = [config.JADX_PATH, "-d", output_dir, input_path, "--no-imports"] 
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def merge_resources(original_apk_path, decompiled_source_dir):
        """从原包提取资源 (Resources + Manifest) 并合并到源码目录"""
        # 使用临时目录解压资源，防止污染
        temp_res_dir = os.path.join(TEMP_WORKSPACE, "res_extract_" + uuid.uuid4().hex[:6])
        JadxEngine.decompile(original_apk_path, temp_res_dir, desc="解析原包资源")
        
        # 1. 复制 resources 文件夹
        src_res = os.path.join(temp_res_dir, "resources")
        dst_res = os.path.join(decompiled_source_dir, "resources")
        if os.path.exists(src_res):
            if os.path.exists(dst_res): shutil.rmtree(dst_res)
            shutil.copytree(src_res, dst_res)
        
        # 2. 复制 AndroidManifest.xml
        src_man = os.path.join(temp_res_dir, "AndroidManifest.xml")
        if os.path.exists(src_man): 
            shutil.copy(src_man, os.path.join(decompiled_source_dir, "AndroidManifest.xml"))
            
        # 清理资源临时目录
        shutil.rmtree(temp_res_dir, ignore_errors=True)

# ==================== 4. 主流程 ====================
def main():
    print("="*60)
    print("自动化查壳与反编译引擎")
    print("="*60)

    # 1. 初始环境清理
    EnvironmentJanitor.clean_local_temp()
    scanner = AppScanner()
    
    # 2. 获取所有 APK 任务
    all_files = [os.path.join(r, f) for r, d, fs in os.walk(config.APK_DIR) for f in fs if f.endswith(".apk")]
    
    for idx, raw_apk_path in enumerate(all_files, 1):
        original_name = os.path.basename(raw_apk_path)
        print(f"\n[{idx}/{len(all_files)}] 处理: {original_name}")

        # [步骤 A] 安全化处理 (中文名 -> 英文名)
        safe_apk_path = FileSanitizer.prepare_safe_apk(raw_apk_path)
        if not safe_apk_path: continue

        try:
            # [步骤 B] 扫描
            type_major, type_detail = scanner.scan(safe_apk_path)
            print(f"   -> 类型: [{type_major}] {type_detail}")

            # [步骤 C] 获取包名 (用于命名输出文件夹)
            pkg_name, main_activity = AndroidTools.get_package_info(safe_apk_path)
            if not pkg_name:
                print("   [Skip] 无法解析包名 (可能是无效APK)")
                continue
            
            # 生成安全的输出文件夹名: "原文件名_包名"
            folder_safe_name = f"{os.path.splitext(original_name)[0]}_{pkg_name}"
            folder_safe_name = re.sub(r'[\\/*?:"<>|]', "_", folder_safe_name)

            # [步骤 D] 分支处理逻辑
            
            # ---> 分支 1: 纯框架 (按类型归档)
            if type_major == "Framework":
                # type_detail 例如 "Flutter Framework" 或 "React Native"
                # 提取第一个词作为子文件夹名 (如 "Flutter", "React", "Unity")
                subdir_name = type_detail.split()[0]
                # 清洗特殊字符，保证文件夹名合法
                subdir_name = re.sub(r'[\\/*?:"<>|]', "", subdir_name)
                
                # 构造路径: Framework_Apps / Flutter / AppName
                target_base = os.path.join(OUT_FRAME, subdir_name)
                target_dir = os.path.join(target_base, folder_safe_name)
                
                os.makedirs(target_dir, exist_ok=True)
                shutil.copy(raw_apk_path, os.path.join(target_dir, original_name))
                print(f"   -> [归档] 移动至 Framework/{subdir_name} 目录")

            # ---> 分支 2: Mod 修改版 (直接反编译，存入 Mod 目录)
            elif type_major == "Mod":
                print("   -> [Mod] 发现修改版，存入 Decompiled_Mods")
                out_path = os.path.join(OUT_MOD, folder_safe_name)
                JadxEngine.decompile(safe_apk_path, out_path)
                print(f"   [Finish] 反编译完成: {out_path}")

            # ---> 分支 3: 加壳应用 (自动脱壳流程)
            elif type_major == "Packed" or (type_major == "Error"):
                print("   -> [Packed] 启动脱壳流程...")
                if not main_activity:
                    print("   [Skip] 无入口 Activity，无法启动脱壳")
                    continue

                # 3.1 手机端环境清理
                EnvironmentJanitor.clean_device_before_run(pkg_name)
                
                # 3.2 安装并运行 (Monkey 增强版)
                AndroidTools.install_and_run(safe_apk_path, pkg_name, main_activity)
                
                print(f"   -> 等待脱壳 ({WAIT_TIME_FOR_UNPACK}s)...")
                time.sleep(WAIT_TIME_FOR_UNPACK)

                # 3.3 提取文件
                final_out_dir = os.path.join(OUT_UNPACKED, folder_safe_name)
                dumped_dir = AndroidTools.pull_dump_files(pkg_name, final_out_dir)
                
                # 3.4 卸载清理
                subprocess.run([config.ADB_COMMAND, "uninstall", pkg_name], stdout=subprocess.DEVNULL)

                if dumped_dir:
                    # 3.5 反编译脱下来的 DEX 并合并资源
                    src_out = os.path.join(final_out_dir, "source_code")
                    JadxEngine.decompile(dumped_dir, src_out, desc="反编译DEX")
                    JadxEngine.merge_resources(safe_apk_path, src_out)
                    print(f"   [Finish] 脱壳+反编译完成: {src_out}")
                else:
                    print("   [Failed] 脱壳失败 (未检测到 hyhzz 文件)")

            # ---> 分支 4: 原生/Library/其他 (直接反编译)
            else: 
                print("   -> [Native] 原生应用 (含Library)，直接反编译...")
                out_path = os.path.join(OUT_NATIVE, folder_safe_name)
                JadxEngine.decompile(safe_apk_path, out_path)
                print(f"   [Finish] 反编译完成")

        except Exception as e:
            print(f"   [Exception] 发生未知错误: {e}")
        finally:
            # 单个任务结束后，删除临时 APK
            if os.path.exists(safe_apk_path):
                try: os.remove(safe_apk_path)
                except: pass

    # 3. 最终清理
    EnvironmentJanitor.clean_local_temp()
    print("\n所有任务已完成。")

if __name__ == "__main__":
    main()