# OpenClaw PQC（抗量子龙虾）安装说明

本仓库是 OpenClaw 的抗量子密码分支。安装脚本会从当前源码包安装锁定的依赖、构建程序，并验证 PQC 源码、构建产物和 CLI。

> 请勿运行 `npm install -g openclaw@latest` 来安装本项目。该命令安装的是上游 OpenClaw，不包含本仓库的 PQC 修改。

## 1. 准备环境

- 64 位 Windows 10/11、macOS 或常见 Linux 发行版。
- Node.js 24.16.0 或更新版本。推荐使用 Node 24 LTS。
- 可访问 npm 软件包仓库的网络连接。
- 使用 Git 克隆时需要 Git；下载或接收 ZIP 时不需要 Git。

检查 Node：

```text
node --version
```

## 2. 获取完整源码

### 从 GitHub 克隆

```bash
git clone https://github.com/Ben-Jianming/openclaw-pqc.git
cd openclaw-pqc
```

### 从 GitHub 下载 ZIP

打开 [项目主页](https://github.com/Ben-Jianming/openclaw-pqc)，点击 **Code → Download ZIP**，下载后完整解压，再进入解压得到的目录。

如果是别人发送的 ZIP，也必须先完整解压，不能直接在压缩包预览窗口中运行脚本。

## 3. 安装

### Windows

双击 `install.bat`，或在解压目录打开 PowerShell：

```powershell
.\install.ps1
```

如果 PowerShell 阻止本次脚本执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

### macOS / Linux

```bash
chmod +x install.sh start.sh stop.sh verify.sh
./install.sh
```

安装脚本可以重复运行。它使用仓库锁定的 pnpm 版本和 `pnpm-lock.yaml`，不会调用上游 npm 包替换当前源码。

## 4. 首次配置

安装成功后，在项目目录运行：

```bash
node openclaw.mjs onboard --install-daemon
```

向导会配置模型服务、网关和工作目录。API 密钥只应通过向导、安全存储或环境变量提供，不要写入 `.bat`、`.sh` 或提交到 GitHub。

## 5. 启动、验证和停止

Windows：

```text
start.bat
verify.bat
stop.bat
```

macOS / Linux：

```bash
./start.sh
./verify.sh
./stop.sh
```

完成 `--install-daemon` 配置后，先用 `node openclaw.mjs gateway status` 检查服务。`start` 可在服务未运行时以前台模式启动网关，按 `Ctrl+C` 可停止；`verify` 会检查 PQC 源码、构建产物、`--version` 和 `--help`。

## 6. 常见问题

- **提示找不到 Node**：安装 Node 24 LTS，关闭并重新打开终端。
- **提示找不到 pnpm/Corepack**：按照 [pnpm 官方安装说明](https://pnpm.io/installation) 安装后重试。
- **依赖下载失败**：确认可以访问 npm registry，然后再次运行安装脚本。
- **提示缺少 `pnpm-lock.yaml` 或 `openclaw.mjs`**：收到的压缩包不完整，请重新下载或要求发送完整项目目录。
- **端口被占用**：先运行停止脚本，或用 `node openclaw.mjs gateway status` 查看现有实例。

PQC 的实现范围与设计说明见 [PQC 白皮书](docs/security/pqc-whitepaper.md)。
