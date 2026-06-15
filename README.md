# Admin 权限检测工具 / Admin Privilege Checker

一个轻量级的 Windows 管理员权限检测工具，使用 8 种方法检测当前进程是否以管理员身份运行。程序本身不请求提权，适合用于对比普通用户和管理员身份的权限差异。

A lightweight Windows admin privilege detection tool that checks whether the current process is running as administrator using 8 different methods. The program does NOT request elevation itself, making it ideal for comparing privilege differences between standard and admin modes.

---

## 功能特性 / Features

- **8 种检测方法**：令牌管理员组、令牌提权类型、提权标志、管理员 SID 匹配、用户特权级别、HKLM 注册表写入测试、系统目录写入测试、进程完整性级别
- **8 detection methods**: Token admin group, elevation type, elevation flag, admin SID match, user privilege level, HKLM registry write test, system directory write test, process integrity level

- **彩色状态标识**：通过/未通过一目了然，绿色表示通过，红色表示未通过
- **Color-coded status**: Green = PASS, Red = FAIL, easy to read at a glance

- **缺失权限对比**：底部自动列出当前缺少哪些管理员权限
- **Missing privilege comparison**: Automatically lists which admin privileges you are missing

- **自动检测**：启动即自动运行检测，无需手动点击
- **Auto-check**: Runs detection automatically on startup

- **自动日志**：检测结果自动追加到网络共享日志文件
- **Auto-log**: Results automatically appended to network share log file

- **多语言支持**：简体中文 / English，可在设置中切换
- **Multi-language**: Chinese / English, switchable in settings

- **可配置字体**：默认宋体 12pt（小四），可在设置中选择系统字体和字号
- **Configurable font**: Default SimSun 12pt, choose from system fonts and sizes in settings

---

## 截图 / Screenshots

程序启动后自动检测，显示结果：

![screenshot](screenshot.png)

---

## 使用方法 / Usage

### 基本用法 / Basic Usage

1. 双击 `AdminChecker.exe` 运行（标准用户模式）
2. 右键 `AdminChecker.exe` → 以管理员身份运行（提权模式）
3. 对比两次运行结果，即可看到权限差异

1. Double-click `AdminChecker.exe` (standard user mode)
2. Right-click `AdminChecker.exe` → Run as administrator (elevated mode)
3. Compare results to see the privilege difference

### 按钮说明 / Buttons

| 按钮 | 功能 |
|------|------|
| 开始检测 | 手动运行 8 项检测 |
| 写入日志 | 将当前结果追加到日志文件 |
| 设置 | 打开设置面板 |
| 关于 | 显示版本和配置信息 |
| 退出 | 关闭程序 |

| Button | Function |
|--------|----------|
| Run Check | Manually run all 8 checks |
| Write Log | Append current results to log file |
| Settings | Open settings panel |
| About | Show version and config info |
| Exit | Close the program |

---

## 设置项 / Settings

| 设置项 | 默认值 | 说明 |
|--------|--------|------|
| 界面语言 | 简体中文 | 简体中文 / English |
| 启动时自动检测 | 是 | 启动程序后自动运行检测 |
| 检测后自动写入日志 | 是 | 检测完成后自动追加到日志文件 |
| 字体 | SimSun (宋体) | 可选系统已安装的字体 |
| 字号 | 12pt (小四) | 9pt ~ 24pt |
| 日志网络路径 | `\\172.30.220.250\record\ip.log` | 网络共享路径，支持自定义 |

| Setting | Default | Description |
|---------|---------|-------------|
| Language | Chinese | Chinese / English |
| Auto-check on startup | Yes | Run checks automatically on startup |
| Auto-log after check | Yes | Append results to log file after check |
| Font | SimSun | Choose from installed system fonts |
| Font Size | 12pt | 9pt ~ 24pt |
| Log network path | `\\172.30.220.250\record\ip.log` | Network share path, customizable |

配置保存在 `AdminChecker.ini`（与 exe 同目录），也可手动用记事本编辑。

Config is saved in `AdminChecker.ini` (same directory as exe), can also be edited manually.

---

## 日志格式 / Log Format

日志以 **GB2312 编码**、**Windows CRLF 行尾** 追加写入，每行格式：

Log is appended in **GB2312 encoding** with **Windows CRLF line endings**:

```
[2026-06-15 17:04:00] | COMPUTER | DOMAIN\User | 管理员 | 令牌管理员组:通过 | 令牌提权类型:通过 | ...
```

字段说明 / Fields:
- 时间 | 计算机名 | 域\用户名 | 整体状态 | 各检测方法结果

---

## 8 种检测方法详解 / Detection Methods

| # | 方法 / Method | 原理 / Principle |
|---|--------------|-----------------|
| 1 | 令牌管理员组 / IsUserAnAdmin | CheckTokenMembership 检查 Administrators SID |
| 2 | 令牌提权类型 / TokenElevationType | TOKEN_ELEVATION_TYPE 枚举（Full/Limited/Default） |
| 3 | 提权标志 / TokenElevation | TOKEN_ELEVATION.TokenIsElevated 标志 |
| 4 | 管理员 SID 匹配 / Admin SID Match | 遍历 TokenGroups 手动匹配 Admin SID |
| 5 | 用户特权级别 / NetUserGetInfo | 用户账户特权级别（Guest/User/Admin） |
| 6 | HKLM 写入测试 / HKLM Write | 实际写入 HKLM\SOFTWARE 注册表 |
| 7 | 系统目录写入 / System Dir Write | 实际在 System32 创建文件 |
| 8 | 完整性级别 / Integrity Level | 进程强制完整性级别（Medium/High/System） |

---

## 编译方法 / Build

需要 MSVC (Visual Studio Build Tools) 和 Windows SDK。

Requires MSVC (Visual Studio Build Tools) and Windows SDK.

```batch
# 使用提供的编译脚本 / Use the included build script
build.bat

# 或手动编译 / Or compile manually
cl /EHsc /utf-8 /DUNICODE /D_UNICODE AdminChecker.cpp AdminChecker.res /link user32.lib gdi32.lib advapi32.lib shell32.lib netapi32.lib ole32.lib comctl32.lib /SUBSYSTEM:WINDOWS /OUT:AdminChecker.exe
```

---

## 系统要求 / Requirements

- Windows 7 / Server 2008 R2 或更高版本
- Windows 7 / Server 2008 R2 or later
- 无需安装，单文件运行
- No installation required, single file executable

---

## 许可证 / License

MIT License
