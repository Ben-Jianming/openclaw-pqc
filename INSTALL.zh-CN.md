# OpenClaw PQC（抗量子龙虾）安装说明

本仓库是 OpenClaw 的抗量子密码分支。安装脚本会从当前源码包安装锁定的依赖、构建程序，并验证 PQC 源码、构建产物和 CLI。

> 请勿运行 `npm install -g openclaw@latest` 来安装本项目。该命令安装的是上游 OpenClaw，不包含本仓库的 PQC 修改。

## 1. 准备环境

- 64 位 Windows 10/11、macOS 或常见 Linux 发行版。
- Node.js 22.22.3+、24.15.0+ 或 25.9.0+（不支持 Node 23，推荐 Node 26）。
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

安装脚本可以重复运行。它只使用仓库锁定的 pnpm 版本和 `pnpm-lock.yaml`；如果电脑上没有匹配版本，安装器会通过 npm 临时下载并运行正确版本。它不会调用上游 OpenClaw npm 包替换当前源码。

## 4. 首次配置

安装成功后，在项目目录运行：

```bash
node openclaw.mjs onboard --install-daemon
```

向导会配置模型服务、网关和工作目录。API 密钥只应通过向导、安全存储或环境变量提供，不要写入 `.bat`、`.sh` 或提交到 GitHub。

首次创建 Node/CLI 设备身份时，程序会自动在状态目录（默认 `~/.openclaw`）的 `credentials/device-identity-wrap.key` 生成随机包裹密钥，并加密保存设备私钥。macOS/Linux 要求密钥文件权限为 `0600`；Windows 会设置并核验当前用户和 SYSTEM 的 ACL。权限设置失败时身份创建会停止，不会退回明文落盘。请把密钥文件与状态数据库一起离线备份；丢失后无法恢复已包裹的身份。已有明文身份在下一次加载时会自动迁移。

也可以由运维人员预先配置 `OPENCLAW_WRAP_KEY_FILE`（绝对路径，内容为 base64url 编码的 32 字节密钥）或 `OPENCLAW_PQC_WRAP_KEY`。请在首次创建身份前配置；以后更换密钥应使用 `node openclaw.mjs security wrap-key rotate`，不要直接替换密钥文件。可用 `node openclaw.mjs security wrap-key status` 检查加密状态，并通过 `export` 制作带密码保护的备份。

### 双签名推送密钥的首次配置与迁移

以下新增命令属于当前本地候选版本；不能据此认定 GitHub `main` 或旧安装包已包含这些功能。先运行 `node openclaw.mjs security push-key --help` 确认。完整默认安装、全量 CI、跨平台安装和浏览器关闭后的离线推送，仍须分别验收。

**全新身份**：在首次创建身份前，先用一个未使用过的配置名进行隔离验收。检查终端是否已设置 `OPENCLAW_STATE_DIR` 或 `OPENCLAW_CONFIG_PATH`；显式路径可能优先于 `--profile`，不要误用现有网关状态。将下例工作目录换成新目录，并在每条命令中使用同一配置名：

```bash
node openclaw.mjs --profile pqc-first-install config file
node openclaw.mjs --profile pqc-first-install setup --baseline --workspace <新工作目录的绝对路径>
node openclaw.mjs --profile pqc-first-install config validate --json
node openclaw.mjs --profile pqc-first-install security push-key status --json
node openclaw.mjs --profile pqc-first-install security push-key init --valid-from-ms <生效时间毫秒整数> --valid-until-ms <到期时间毫秒整数>
node openclaw.mjs --profile pqc-first-install security push-key status --json
node openclaw.mjs --profile pqc-first-install doctor --lint --only core/doctor/push-key-policy --json
```

尖括号是待替换项。时间采用 Unix 毫秒非负安全整数，且生效时间小于到期时间；有效区间为 `生效时间 ≤ 当前时间 < 到期时间`，恰好到期即失效。初始 `status` 显示 `uninitialized`、`ready: false`，退出码为 `1`，属于正常的待初始化状态；请逐条执行。完成后只有当前有效的双密钥才能得到 `ready: true` 和状态命令退出码 `0`。

`setup --baseline` 只建立基础配置、工作区和会话目录，不完成模型接入或推送配置。密钥初始化完成后，可用 `node openclaw.mjs --profile pqc-first-install setup --wizard` 配置同一隔离实例；不要用后文默认配置的启动脚本代替该实例的启动命令。

**已有身份**：不要运行 `init`，也不要删除旧文件重新生成。完整备份原状态数据库、包裹密钥和专用 Ed25519 推送密钥，核对身份后，在原配置上明确登记：

```bash
node openclaw.mjs --profile <原配置名> security push-key enroll --valid-from-ms <生效时间毫秒整数> --valid-until-ms <到期时间毫秒整数>
node openclaw.mjs --profile <原配置名> security push-key status --json
node openclaw.mjs --profile <原配置名> doctor --lint --only core/doctor/push-key-policy --json
```

`enroll` 保留原有两种签名身份，不能延长已登记期限，也不能恢复已撤销密钥。缺失部分密钥时应恢复原材料，不能用新身份冒充迁移成功。安装／验证脚本和上述 Doctor 检查不会替你静默建立信任策略；`status` 和该 Doctor 检查也不会生成签名密钥。Doctor 此项通过仅代表本地密钥策略检查通过，不代表真实推送已送达。

**恢复边界**：一个配置中的已登记策略固定绑定原有双密钥。首次登记要求策略集为空；已有策略必须恰好是与当前发送方、算法、密钥标识和公钥全部匹配的两条记录，部分记录、额外记录或身份不符均拒绝登记／续期。即使两份密钥都已丢失，只要仍有策略，`status` 也会报告 `incomplete`，`init` 会在生成前拒绝。不要覆盖／删除密钥文件、删除策略或反复运行 `init` 来绕过撤销及旧信任；应恢复与登记记录匹配的原身份材料。需要更换身份时，必须另行设计并审查密钥轮换流程，当前这些命令不支持轮换。

**续期**：优先在到期前安排维护。`enroll` 不负责续期；请先用 `status --json` 取得两项策略的原始生效时间，再明确执行：

```bash
node openclaw.mjs --profile <原配置名> security push-key renew --valid-from-ms <原生效时间毫秒整数> --valid-until-ms <延长后的到期时间毫秒整数> --json
node openclaw.mjs --profile <原配置名> doctor --lint --only core/doctor/push-key-policy --json
```

续期保留原有两种身份和公钥，生效时间必须与两项原策略完全相同；新到期时间须晚于各自原到期时间，并晚于执行时刻。两项策略在同一事务中更新，各自修订号加一；任一项缺失、已撤销或与当前密钥不匹配，整体拒绝。过期但未撤销的密钥允许明确续期，以恢复服务；续期完成前，过期策略继续阻止发送。不会自动续期，也不能用续期恢复撤销或替换密钥。此命令的源码存在不代表安装验收已完成。

确需撤销时，可在同一配置运行 `node openclaw.mjs --profile <原配置名> security push-key revoke --sender-id <发送方标识> --algorithm ed25519 --key-id <密钥标识>`；另一算法名称是 `ml-dsa-65`。撤销任一签名密钥都会阻止该双签名组合继续发送，不要为检查安装而撤销工作中的密钥。

完整边界见 [生产验收与密钥生命周期说明](docs/security/pqc-production-v2.md)。

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

完成 `--install-daemon` 配置后，先用 `node openclaw.mjs gateway status` 检查服务。`start` 可在服务未运行时以前台模式启动网关，按 `Ctrl+C` 可停止；`verify` 会检查构建产物、CLI、设备证明算法和生产接线契约。

## 6. 常见问题

- **提示找不到 Node**：安装 Node 24 LTS，关闭并重新打开终端。
- **提示无法启动锁定的 pnpm**：先确认 `npm --version` 可以正常运行，并确认网络能访问 npm registry；安装器会自动获取正确版本，不需要手动猜测 pnpm 版本。
- **依赖下载失败**：确认可以访问 npm registry，然后再次运行安装脚本。
- **提示缺少 `pnpm-lock.yaml` 或 `openclaw.mjs`**：收到的压缩包不完整，请重新下载或要求发送完整项目目录。
- **端口被占用**：先运行停止脚本，或用 `node openclaw.mjs gateway status` 查看现有实例。

PQC 的实现范围与设计说明见 [PQC 白皮书](docs/security/pqc-whitepaper.md)。
