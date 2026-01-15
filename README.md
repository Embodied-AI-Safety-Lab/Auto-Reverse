# Embodied AI APK 自动化逆向与脱壳分析系统

**适用场景**: 具身智能（机器人、无人机、服务机器人）Android 应用的批量安全性分析。

## 项目简介

这是一个高度自动化的 Android 逆向工程流水线。它能够自动扫描、分类、并在必要时对 APK 进行脱壳处理。

## 核心功能

### 1. 混合检测引擎 (Scanner)

采用 **“静态指纹 + 动态探测”** 双重机制，精准度远超普通查壳工具。

- **Tier 1 (行业规则库)**: 内置 `rules.json`，识别 DJI SecNeo、AppGuard、梆梆定制版、360 加固等行业专用壳。
- **Tier 2 (Mod 识别)**: 能够识别 AndroidRepublic、MT Manager 等破解/注入特征。
- **Tier 3 (APKiD 兜底)**: 集成 APKiD v3.0，识别 DexGuard、AESObfuscator 等虚拟化混淆。
- **智能过滤**: 自动识别 Flutter/React Native 框架，并自动忽略 ProGuard 等非破坏性混淆。

### 2. 自动化脱壳流水线 (Unpacker)

基于检测结果的智能分流策略：

- **Packed (有壳)**: 自动安装至真机 -> 运行 Monkey 触发壳逻辑 -> 内存 Dump DEX -> 修复 DEX 头 -> JADX 反编译。
- **Mod (破解版)**: 跳过脱壳机（防止反检测），直接调用 JADX 反编译，方便分析破解/注入逻辑。
- **Framework (框架)**: 识别 Flutter/Unity/RN 应用，自动归档，不进行无效的 DEX 反编译。
- **Native (原生)**: 直接进行静态反编译。

## 目录结构

确保你的文件放置如下：

Plaintext

```
Project_Root\                # [项目根目录]
├── Dataset/
│   ├── Raw_APKs/              # [输入] 把 APK 放在这里
│   └── scan_report.csv        # [输出] 扫描生成的体检报告
├── Results/                   # [输出] 最终反编译结果
│   ├── drones/                # 按类别分类
│   ├── robots/
│   └── Framework/             # Flutter/RN/Unity 归档目录
├── Scripts/                   # [脚本目录]
│   ├── quick_scan_packers.py  # 检测脚本 
│   └── automated_unpack.py    # 自动化脱壳脚本
├── Tools/
│   ├── rules.json             # 核心特征库 (必须存在)
│   └── config.py              # 路径配置文件 (可选，代码有默认值)
└── README.md                  # 说明文档
```

## 环境依赖

在运行之前，请确保已安装以下工具并配置好环境变量：

1. **Python 3.8+**
2. **APKiD** (v3.0+): `pip install apkid` (用于兜底查壳)
3. **JADX**: 需配置 `jadx` 命令到环境变量 (用于反编译)
4. **ADB**: Android Debug Bridge (用于连接手机)
5. **一台 Root 过的 Android 手机**: 用于 `Packed` 类型应用的自动化脱壳。

## 配置检查 (Tools/rules.json)

请确保 `Tools\rules.json` 文件已创建并包含了最新的指纹数据（包含 DJI SecNeo, AppGuard, AndroidRepublic 等特征）。

## 使用指南

### 第一步：扫描与分类

进入脚本目录并运行检测脚本：

Bash

```
python quick_scan_packers.py
```

- **输出**: 屏幕打印检测表格，并在 `Dataset/` 下生成 `scan_report.csv`。
- **判定标准**:
  - `YES`: 包含加固、虚拟化混淆 (DexGuard) 或 恶意注入 (Mod)。
  - `NO`: 原生代码或仅包含普通混淆 (ProGuard)。

### 第二步：自动化处理

确认手机已连接并开启 USB 调试，然后运行：

Bash

```
python automated_unpack.py
```

- 脚本会自动读取 `../Dataset/Raw_APKs` 下的文件。
- **有壳应用 (Packed)** 会自动在手机上启动、脱壳、拉取 DEX 并修复。
- **结果**会保存在 `../Results/` 目录下。

## 决策逻辑矩阵

| **检测类型**  | **典型特征 (Signature/APKiD)**              | **判定 (Shell?)** | **自动化动作**                             |
| ------------- | ------------------------------------------- | ----------------- | ------------------------------------------ |
| **Packer**    | `libSecShell.so`, `libjiagu.so`, `DexGuard` | **YES**           | 📲 真机脱壳 -> 修复 -> 反编译               |
| **Mod**       | `libar-checker.so`, `MT_BIN`                | **YES**           | 📄 直接 JADX 反编译 (分析注入逻辑)          |
| **Framework** | `libflutter.so`, `libreactnative.so`        | **NO**            | 🗄️ 归档至 `Results/Framework/` (需专用工具) |
| **Native**    | 无特征, 或 `ProGuard`                       | **NO**            | 📄 直接 JADX 反编译                         |

## 免责声明

本项目仅用于具身智能领域的安全研究与学术分析。

- 请勿用于分析非法软件或进行商业破解。
- 对于分析 Mod (破解版) 应用时可能触发的安全风险（如后门），请在沙箱或专用测试机中运行。