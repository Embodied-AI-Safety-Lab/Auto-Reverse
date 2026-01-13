# Auto-Reverse-Engine: 自动化 APK 查壳与反编译引擎

**Auto-Reverse-Engine** 是一个专为 **具身智能（Embodied AI）安全研究** 设计的 Android 自动化逆向流水线。它能够批量扫描 APK 文件，智能识别加固壳、开发框架（如 Flutter）以及修改版（Mod），并根据类型自动执行脱壳、反编译或归档操作。

## 主要功能

* **智能查壳与分类**：
* **加壳应用**：识别 360、腾讯、梆梆等主流加固，自动启动真机脱壳流程。
* **框架应用**：识别 Flutter、React Native、Unity，自动归档（跳过耗时反编译）。
* **Mod 修改版**：识别常见破解/修改版特征，单独分类处理。


* **自动化脱壳 (Unpacking)**：
* 通过 ADB 控制 Root 真机自动安装、运行、提取内存中的 DEX 文件。
* 自动处理 `hyhzz` 脱壳产物并拉取至本地。


* **源码重组**：
* 将脱壳后的 DEX 代码与原 APK 的资源文件（Resources/Manifest）自动合并，生成可分析的完整项目。


* **纯净与安全模式**：
* **中文文件名支持**：自动将 APK 复制为纯英文临时文件处理，解决 ADB/JADX 乱码问题。
* **环境自洁**：任务前后自动清理手机端残留数据，防止分析干扰。



---

## 环境要求

在运行脚本前，请确保满足以下条件：

### 1. 硬件环境

* 一台 **已 Root** 的 Android 真机或模拟器。
* **关键要求**：设备需配置好脱壳环境（确保 APP 运行时会在 `/data/data/<包名>/hyhzz/` 目录下生成脱壳文件）。

### 2. 软件依赖

* **Python 3.x**
* **ADB (Android Debug Bridge)**：需配置到系统环境变量 `PATH` 中。
* **AAPT (Android Asset Packaging Tool)**：需配置到系统环境变量 `PATH` 中（通常在 Android SDK build-tools 下）。
* **JADX**：需要安装 JADX，并记录其 `bin/jadx.bat` (Windows) 的相对路径。

---

## 目录结构

建议的项目文件结构如下：

```text
Project_Root/
├── Dataset/
│   └── Raw_APKs/           <-- [输入] 把下载的 APK 放在这里 (支持中文名)
│
├── Tools/
│   ├── config.py           <-- [配置] 路径配置文件
│   ├── rules.json          <-- [规则] 查壳与框架指纹库
│   └── jadx-x.x.x/         <-- (可选) JADX 工具目录
│
├── Scripts/
│   ├──  auto_reverse_engine.py  <-- [主程序] 启动脚本
│   └── quick_scan_packers.py   <-- [模块] 扫描引擎
│
└── README.md

```

---

## 配置指南

在使用前，请打开 `Tools/config.py` 并根据你的电脑环境修改以下路径：

```python
# Tools/config.py

# 1. 设置 JADX 的相对路径 (如果未更新版本，保持默认即可)
JADX_PATH = os.path.join(CURRENT_DIR, "jadx-1.5.3", "bin", "jadx.bat")

# 2. 确认 ADB 和 AAPT 命令 (如果已在环境变量中，保持默认即可)
AAPT_COMMAND = "aapt"
ADB_COMMAND = "adb"

```

---

## 使用方法

1. 连接手机至电脑，确保 `adb devices` 能看到设备。
2. 将待分析的 APK 文件放入 `Dataset/Raw_APKs` 文件夹。
3. 在终端（CMD/PowerShell）运行主程序：

```bash
python auto_reverse_engine.py

```

脚本将按照以下流程自动工作：

* **扫描** -> **重命名(安全模式)** -> **分类** -> **脱壳(如有必要)** -> **反编译** -> **清理**。

---

## 输出产物说明

运行结束后，结果会保存在 `Dataset` 目录下的不同文件夹中：

| 文件夹名称              | 说明                                                     |
| ----------------------- | -------------------------------------------------------- |
| **Decompiled_Native**   | **原生/库应用**。未加壳的 APP。                          |
| **Decompiled_Unpacked** | **脱壳后应用**。原本有壳，经脚本自动脱壳并修复后的产物。 |
| **Decompiled_Mods**     | **修改版应用**。被检测为 Mod/Hack 的应用。               |
| **Framework_Apps**      | **框架应用** (Flutter/React Native)。                    |

### `Decompiled_Unpacked` 内部结构详情

针对脱壳后的应用，文件夹结构如下：

```text
AppName_PackageName/
├── dumped_dex/      <-- [证据] 从手机内存拉取的原始 DEX 文件 (可拖入 JADX 分析)
└── source_code/     <-- [成品] JADX 反编译后的 Java 源码 + 原始资源文件

```

---

## 规则库定制

你可以编辑 `Tools/rules.json` 来添加新的检测规则：

* **type: "packer"** -> 触发自动脱壳。
* **type: "framework"** -> 触发归档跳过。
* **type: "mod"** -> 存入 Mod 专用目录。

---

