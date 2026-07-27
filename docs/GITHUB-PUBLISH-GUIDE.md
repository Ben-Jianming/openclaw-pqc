# GitHub 发布指南（v0.1.0）

> **目标**：把 `/home/ubuntu/openclaw-pqc` 这个 fork 仓推到 GitHub `Ben-Jianming/openclaw-pqc`
> **耗时**：15-30 分钟（含认证）
> **前置**：你的 Ubuntu 24.04 服务器（已跑通 PQC）

---

## 📋 整体流程

```
1. GitHub 端：创建空仓 Ben-Jianming/openclaw-pqc
                ↓
2. Ubuntu 端：装 git 认证 (HTTPS token 或 SSH key)
                ↓
3. 同步发布文件：从 Mavis 拿的 tar.gz 解压
                ↓
4. 跑 git-publish.sh（自动 commit + push + create release）
                ↓
5. GitHub 端：检查 + 配置 About/Settings
```

---

## Step 1：在 GitHub 创建空仓（5 分钟）

1. 打开 https://github.com/new
2. 填：
   - **Owner**: `Ben-Jianming`（你的账号）
   - **Repository name**: `openclaw-pqc`
   - **Description**: `🦞 Post-Quantum Cryptography migration for OpenClaw (抗量子龙虾项目)`
   - **Public**（公开仓，方便别人看）
   - **不要**勾选 "Add a README file"（我们有自己的）
   - **不要**勾选 "Add .gitignore"（我们有自己的）
   - **不要**勾选 "Choose a license"（我们用 MIT）
3. 点 **Create repository**

**重要**：复制仓的 URL，备用：
- HTTPS: `https://github.com/Ben-Jianming/openclaw-pqc.git`
- SSH: `git@github.com:Ben-Jianming/openclaw-pqc.git`

---

## Step 2：选认证方式（5 分钟）

### 方式 A：HTTPS + Personal Access Token（推荐新手）

1. 打开 https://github.com/settings/tokens
2. 点 **Generate new token** → **Generate new token (classic)**
3. 填：
   - **Note**: `openclaw-pqc-publish`
   - **Expiration**: `90 days`（或 No expiration 看需要）
   - **Scopes**: 勾选 `repo`（全部）和 `workflow`（可选）
4. 点 **Generate token**
5. **复制 token**（只显示一次！）

**保存 token 到环境变量**（你的 Ubuntu 服务器上）：

```bash
echo 'export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx' >> ~/.bashrc
source ~/.bashrc

# 验证
echo $GITHUB_TOKEN | head -c 10
# 应输出 ghp_xxxxx
```

### 方式 B：SSH Key（推荐老手）

```bash
# 1. 生成 key（如果还没有）
ssh-keygen -t ed25519 -C "2724362782@qq.com"
# 一路回车，不设密码

# 2. 复制公钥
cat ~/.ssh/id_ed25519.pub

# 3. 在 GitHub 添加
# https://github.com/settings/keys → New SSH key
# 粘贴公钥 → Add SSH key

# 4. 测试
ssh -T git@github.com
# 期望: Hi Ben-Jianming! You've successfully authenticated...
```

---

## Step 3：拿 Mavis 准备的发布文件（1 分钟）

发布文件在沙箱 `/workspace/openclaw-pqc/github-release/`：

```
github-release/
├── README.md              # GitHub 仓首页
├── LICENSE                # MIT
├── CHANGELOG.md           # v0.1.0 entry
├── SECURITY.md            # 安全披露
├── .github/
│   ├── workflows/ci.yml   # CI workflow
│   ├── ISSUE_TEMPLATE/    # issue 模板
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/
│   ├── V0.1.0-RELEASE-NOTES.md  # release notes
│   └── GITHUB-PUBLISH-GUIDE.md  # 本文档
└── git-publish.sh         # 一键发布脚本
```

**两种方式拿到本地**：

### 方式 1：从沙箱拷贝（推荐）

我先打包成 tar.gz 给你下载。

### 方式 2：手动复制（如果用 scp）

```bash
mkdir -p ~/openclaw-pqc-github-release
cd ~/openclaw-pqc-github-release

# 用 scp 从你的 Windows 机器下载（如果在 Windows 上）
# 或者直接复制下面这些文件内容
```

---

## Step 4：跑 git-publish.sh（10 分钟）

```bash
# 1. 准备 OpenClaw 仓（已经在 ~/openclaw-pqc）
ls ~/openclaw-pqc/src/infra/crypto/  # 应有 4 个 PQC 文件

# 2. 把发布文件复制到 OpenClaw 仓
cp -r ~/openclaw-pqc-github-release/. ~/openclaw-pqc/

# 3. 跑发布脚本
cd ~/openclaw-pqc
bash ~/openclaw-pqc-github-release/git-publish.sh
```

### 脚本会做的事

1. ✅ 验证 PQC 代码在位（src/infra/crypto/, @noble/post-quantum/）
2. ✅ 同步 README/LICENSE/CHANGELOG/SECURITY/.github/workflows/docs
3. ✅ 创建 .gitignore
4. ✅ 检查/初始化 Git 仓
5. ✅ 提交所有文件（带详细 commit message）
6. ✅ 推送到 GitHub（用你的 GITHUB_TOKEN 或 SSH）
7. ✅ 打 tag `v0.1.0`
8. ✅ 创建 GitHub Release（用 gh CLI 如果装了）

### 期望输出

```
=== Step 1: 准备 OpenClaw 仓 ===
OpenClaw dir: /home/ubuntu/openclaw-pqc

=== Step 2: 同步 GitHub 发布文件 ===
复制发布文件...
✅ 发布文件已同步

=== Step 3: 清理不该进 git 的文件 ===
✅ .gitignore 已创建

=== Step 4: 检查 Git 状态 ===
初始化 Git 仓...

=== Step 5: 提交所有文件 ===
[main (root-commit) abc1234] feat(pqc): initial OpenClaw-PQC v0.1 release

=== Step 6: 推送到 GitHub ===
推送 main 分支...
To https://github.com/Ben-Jianming/openclaw-pqc.git
 * [new branch]      main -> main

=== Step 7: 创建 v0.1.0 Release ===
[gh release create] ✅ Release 已创建
https://github.com/Ben-Jianming/openclaw-pqc/releases/tag/v0.1.0

=== ✅ 发布完成 ===
仓:     https://github.com/Ben-Jianming/openclaw-pqc
Release: https://github.com/Ben-Jianming/openclaw-pqc/releases/tag/v0.1.0
```

---

## Step 5：GitHub 端配置（5 分钟）

发布完，去 GitHub 配这些：

### 5.1 About 标签

https://github.com/Ben-Jianming/openclaw-pqc → 右上角 ⚙️ (Settings) → **General** → **About**

填：
- **Description**: `🦞 Post-Quantum Cryptography migration for OpenClaw (抗量子龙虾项目)`
- **Website**: `https://github.com/openclaw/openclaw`（上游）
- **Topics**: `post-quantum-cryptography`, `pqc`, `openclaw`, `ml-dsa`, `ml-kem`, `fips-203`, `fips-204`, `quantum-resistant`, `crypto-agility`, `typescript`
- ✅ Releases
- ✅ Packages（如果有）

### 5.2 Features

**Settings** → **General** → **Features**：
- ✅ Issues
- ✅ Discussions（推荐，让用户问问题）
- ⬜ Wiki（不必要）
- ✅ Sponsors（看你要不要）
- ⬜ Projects（看你要不要）

### 5.3 Pages（可选）

如果想有 GitHub Pages 文档站：
- **Settings** → **Pages** → Source: `Deploy from a branch` → `main` / `docs`

（这次先不做，v1.0 再加）

### 5.4 Branch protection（可选但推荐）

**Settings** → **Branches** → **Add rule**：
- Branch name pattern: `main`
- ✅ Require a pull request before merging
- ✅ Require approvals: 1
- ✅ Require status checks to pass before merging: `pqc-smoke-test`, `unit-test`
- ✅ Include administrators

---

## Step 6：验证发布成功

### 6.1 看仓内容

打开 https://github.com/Ben-Jianming/openclaw-pqc

期望看到：
- ✅ README.md 渲染（带徽章）
- ✅ 5 个 PQC 抽象层文件（src/infra/crypto/）
- ✅ 14 份文档（docs/）
- ✅ CHANGELOG.md / LICENSE / SECURITY.md
- ✅ .github/workflows/ci.yml

### 6.2 看 Release

打开 https://github.com/Ben-Jianming/openclaw-pqc/releases

期望看到：
- ✅ `v0.1.0` tag
- ✅ Title: "v0.1.0 - Initial OpenClaw-PQC release 🎉"
- ✅ Description 完整（用 V0.1.0-RELEASE-NOTES.md）

### 6.3 看 CI

打开 https://github.com/Ben-Jianming/openclaw-pqc/actions

第一次 push 会触发 CI：
- ✅ `pqc-smoke-test`（Node 22.22.3 + 24.x）
- ✅ `unit-test`
- ✅ `lint`
- ✅ `typecheck`
- ✅ `cross-platform`（ubuntu + macOS + windows）

如果都过，**v0.1.0 发布成功** 🎉

### 6.4 跑 PQC smoke test（从 GitHub clone 验）

```bash
# 在另一台机器（验证仓可用）
git clone https://github.com/Ben-Jianming/openclaw-pqc.git
cd openclaw-pqc
pnpm install
pnpm build

# 装 noble 三个包
curl -fsSL -o /tmp/npqt.tgz https://registry.npmjs.org/@noble/post-quantum/-/post-quantum-0.5.0.tgz
mkdir -p node_modules/@noble/post-quantum
tar -xzf /tmp/npqt.tgz -C node_modules/@noble/post-quantum --strip-components=1
# ... 同样装 curves 和 hashes

# 跑测试
node --input-type=module -e "
import { ml_dsa44 } from './node_modules/@noble/post-quantum/ml-dsa.js';
const d = ml_dsa44.keygen();
const s = ml_dsa44.sign(new TextEncoder().encode('verify'), d.secretKey);
console.log(ml_dsa44.verify(s, new TextEncoder().encode('verify'), d.publicKey) ? '✅ OK' : '❌ FAIL');
"
```

---

## 🆘 故障排查

| 症状 | 原因 | 修法 |
|------|------|------|
| `gh: command not found` | gh CLI 没装 | `sudo apt install gh` 或 `brew install gh` |
| `Permission denied (publickey)` | SSH key 没加到 GitHub | 看 Step 2 方式 B |
| `Bad credentials` | GITHUB_TOKEN 错 | 重新生成 token |
| `remote: Repository not found` | 仓 URL 错 | 检查 Ben-Jianming/openclaw-pqc 是否存在 |
| `Updates were rejected` | GitHub 仓有初始 commit | 改用 `git push -f`（覆盖）或先 `git pull` |
| `error: failed to push some refs` | 同上 | 同上 |
| `CI 失败: pnpm install 失败` | OpenClaw 主仓 bug | 看 [DAY4-PATCH-GUIDE.md](./DAY4-PATCH-GUIDE.md) |

---

## 📋 发布检查清单

发布前：
- [ ] PQC smoke test 跑通
- [ ] dist/ 里有 PQC 代码
- [ ] fork 仓在 ~/openclaw-pqc
- [ ] GitHub 仓已创建（空仓）
- [ ] 认证方式已配（Token 或 SSH）

发布后：
- [ ] 仓能访问
- [ ] README 渲染正常
- [ ] Release v0.1.0 已创建
- [ ] CI 跑通（5 个 workflow）
- [ ] About/Topics 已配
- [ ] Issues/Discussions 已开
- [ ] v0.1.0 release notes 完整

---

## 🚀 下一步（v1.0 路线图）

发布 v0.1.0 后，3 个月内推到 v1.0.0：

- [ ] **Week 1-2**: 修 OpenClaw 主仓 bug（`node-domexception` + `write-cli-startup-metadata`）
- [ ] **Week 3-4**: 飞书端到端测试（DAY4-E2E-TEST）
- [ ] **Week 5-6**: 集成测试 + 性能优化
- [ ] **Week 7-8**: M2 Gateway TLS ML-DSA-65 自签（PR-2）
- [ ] **Week 9-10**: 文档完善 + CHANGELOG
- [ ] **Week 11-12**: GitHub release v1.0.0

---

> **发布完告诉我，我帮你 review v0.1.0 仓！** 🎉
