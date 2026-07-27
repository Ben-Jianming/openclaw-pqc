# Security Policy

## Supported Versions

| Version | Supported          | Status |
|---------|-------------------|--------|
| 1.0.x   | ✅ (TBD)          | 计划 2026-10-22 |
| 0.1.x   | ✅ (active dev)   | 当前开发版 |
| < 0.1   | ❌                | 升级到 0.1+ |

## Reporting a Vulnerability

**请不要在 GitHub Issues 公开披露安全问题。**

请发邮件到：**2724362782@qq.com**

邮件请包含：
1. **问题描述**（一两句话）
2. **复现步骤**（详细）
3. **影响范围**（哪些版本/组件受影响）
4. **POC**（如果有，附上 PoC 代码/截图）
5. **联系方式**（你希望怎么沟通 — 邮件 / GitHub DM / 其他）

### 响应时间

- **24 小时**：确认收到 + 初步评估
- **7 天**：决定严重等级 + 修复计划
- **30 天**：发布修复 + 安全公告（高危问题优先）

### 严重等级

| 等级 | 描述 | 修复 SLA |
|------|------|----------|
| 🔴 Critical | 可远程利用 / 量子破密钥 | 24 小时 |
| 🟠 High | 重大信息泄露 / 越权 | 7 天 |
| 🟡 Medium | 一般安全问题 | 30 天 |
| 🟢 Low | 改进建议 / 最佳实践 | 90 天 |

### 披露政策

我们遵循 [Coordinated Vulnerability Disclosure](https://github.com/ossf/oss-vulnerability-guide)：

1. 报告后我们内部确认 + 修复
2. 修复发布后 **30 天**（高危 7 天）后公开
3. 公开时在 [Releases](https://github.com/Ben-Jianming/openclaw-pqc/releases) 标注 security advisory

### 致谢

负责任披露的安全研究员会在 [CONTRIBUTORS.md](CONTRIBUTORS.md) 中致谢。

---

## 已实现的安全特性（v0.1）

- ✅ **Hybrid KEM TLS** (X25519 + ML-KEM-768) — Node 22.22.3+ 自动启用
- ✅ **ML-DSA-44 设备身份双套签名** — Ed25519 + ML-DSA-44 叠加
- ✅ **NIP-44 AEAD** Nostr DM
- ✅ **Crypto-agility 抽象层** — 算法切换改配置即可
- ✅ **自动备份** (`upgrade-to-pqc.sh` 升级前自动备份原文件)
- ✅ **一键回滚** (`upgrade-to-pqc.sh --rollback`)

## 已知安全问题（v0.1）

### 🟡 OpenClaw 主仓 transitive dep `node-domexception@1.0.28`

- **影响**：`pnpm install` 失败
- **修复**：[DAY4-PATCH-GUIDE.md](docs/DAY4-PATCH-GUIDE.md) 提供 `pnpm.overrides` 方案
- **计划**：v1.0 修复（2026-10）

### 🟡 OpenClaw `write-cli-startup-metadata` postbuild crash

- **影响**：`pnpm build` 末步失败
- **修复**：`pnpm build:write-cli-startup-metadata || true`
- **影响范围**：仅 postbuild 收集元数据失败，不影响 dist/ 产物
- **计划**：v1.0 修复

---

> **PGP 密钥**：待发布（v1.0 release 时附带）
