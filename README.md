# OpenClaw-PQC 🦞

> **Post-Quantum Cryptography migration for [OpenClaw](https://github.com/openclaw/openclaw)**
> **OpenClaw 的抗量子（PQC）加密升级版本**
>
> 抗量子龙虾项目 v0.1.0 — 3 个月内发布 v1.0.0

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-2026.7.x-orange.svg)](https://github.com/openclaw/openclaw)
[![PQC: FIPS 203/204](https://img.shields.io/badge/PQC-FIPS%20203%2F204-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Node 22.22.3+](https://img.shields.io/badge/Node-22.22.3%2B-brightgreen.svg)](https://nodejs.org)

---

## 这是什么？

**OpenClaw-PQC** 是把 [OpenClaw](https://github.com/openclaw/openclaw) 升级到**抗量子加密（PQC）**的 fork 版本。基于 NIST FIPS 203/204 标准，把所有可优化的底层加密代码替换为量子安全算法。

### 🎯 关键能力

- ✅ **Hybrid KEM** (X25519 + ML-KEM-768) — TLS 握手透明抗量子（Node 22.22.3+ 自动启用）
- ✅ **ML-DSA-44 双套签名** — 设备身份叠加 Ed25519（向后兼容）
- ✅ **NIP-44 AEAD** — Nostr DM 从 AES-CBC 升级到 AEAD
- ✅ **Crypto-agility 抽象层** — 算法切换改配置即可
- ✅ **端到端跑通** — 7/7 PQC 算法 smoke test 通过，零失败

### 🔬 性能（实测，Intel Xeon Gold 6248 / Node 24.16.0）

| 算法 | 操作 | 延迟 | 输出 |
|------|------|------|------|
| Ed25519 | sign | 0.10 ms | 64 B |
| **ML-DSA-44** | sign | **7.98 ms** | 2420 B |
| **ML-KEM-768** | encap | **1.2 ms** | 1088 B ct, 32 B ss |

完全满足 WebSocket connect / APNs JWT / Gateway TLS 等所有生产场景的 SLA。

---

## 🚀 快速开始

### 1. 装 OpenClaw-PQC

```bash
# 还没发布 v1.0 — 当前用 fork 仓 + 软链方式
git clone https://github.com/Ben-Jianming/openclaw-pqc.git
cd openclaw-pqc
pnpm install
pnpm build

# 软链到全局（替代原版 openclaw）
ln -sf $(pwd) /home/ubuntu/.npm-global/lib/node_modules/openclaw
ln -sf ../lib/node_modules/openclaw/dist/index.js /home/ubuntu/.npm-global/bin/openclaw
```

### 2. 验证 PQC 跑通

```bash
# PQC smoke test
node --input-type=module -e "
import { ml_dsa44 } from '$(pwd)/node_modules/@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '$(pwd)/node_modules/@noble/post-quantum/ml-kem.js';
const d = ml_dsa44.keygen();
const s = ml_dsa44.sign(new TextEncoder().encode('test'), d.secretKey);
console.log('ML-DSA-44:', ml_dsa44.verify(s, new TextEncoder().encode('test'), d.publicKey) ? 'OK' : 'FAIL');
const k = ml_kem768.keygen();
const e = ml_kem768.encapsulate(k.publicKey);
const d2 = ml_kem768.decapsulate(e.cipherText, k.secretKey);
console.log('ML-KEM-768:', Buffer.from(e.sharedSecret).equals(Buffer.from(d2)) ? 'OK' : 'FAIL');
"
```

### 3. 跑起来

```bash
openclaw gateway start
```

---

## 📚 文档

| 文档 | 用途 |
|------|------|
| [V1.0-DELIVERY-REPORT.md](docs/V1.0-DELIVERY-REPORT.md) | 完整交付报告（v1.0 收官）|
| [RUNBOOK.md](docs/RUNBOOK.md) | 运维手册 + 故障排查 |
| [PR-1-M1-CRYPTO-PROVIDER.md](docs/PR-1-M1-CRYPTO-PROVIDER.md) | M1 抽象层 PR 草稿 |
| [PR-2-M2-GATEWAY-TLS-DUAL-CERT.md](docs/PR-2-M2-GATEWAY-TLS-DUAL-CERT.md) | M2 Gateway TLS 双证书（v1.1）|
| [DAY4-PATCH-GUIDE.md](docs/DAY4-PATCH-GUIDE.md) | 修 OpenClaw 主仓 bug |
| [DAY4-E2E-TEST.md](docs/DAY4-E2E-TEST.md) | 飞书端到端测试 |
| [DAY1-STATUS.md](docs/DAY1-STATUS.md) | Day 1 现状评估 |
| [PQC-LIBRARY-CHOICE.md](docs/PQC-LIBRARY-CHOICE.md) | PQC 库选型分析 |
| [CRYPTO-CALLPOINTS.md](docs/CRYPTO-CALLPOINTS.md) | OpenClaw 加密面盘点 |
| [CONTRIBUTING-PQC.md](docs/CONTRIBUTING-PQC.md) | PQC 贡献指南 |
| [CHANGELOG-PQC.md](docs/CHANGELOG-PQC.md) | PQC 改造 CHANGELOG |
| [UBUNTU-DEPLOY.md](docs/UBUNTU-DEPLOY.md) | Ubuntu 部署指南 |
| [README-PQC.md](docs/README-PQC.md) | PQC 改造详细说明 |

---

## 🏗️ 架构

### 改造前后对比

**改造前（OpenClaw 2026.6.9）**：
- TLS cert: RSA-2048
- 设备身份: Ed25519
- Nostr 事件签名: secp256k1
- Nostr DM: AES-CBC + 静态 IV
- Webhook 验签: HMAC-SHA256
- 所有算法都是**传统**（量子破后不安全）

**改造后（OpenClaw-PQC v0.1）**：
- TLS 握手: **Hybrid KEM** (X25519 + ML-KEM-768) — Node 22.22.3+ 自动启用
- 设备身份: **Ed25519 + ML-DSA-44** 双套签名（向后兼容）
- Nostr 事件签名: 暂保持 secp256k1（等 NIP-PQ-Schnorr 提案，v1.1）
- Nostr DM: **NIP-44 AEAD**
- Webhook 验签: 保持 HMAC-SHA256（等 Twilio 升级，v1.2）
- 加 **Crypto-agility 抽象层** — 算法切换改配置即可

### 5 个新文件

```
src/infra/crypto/
├── provider.ts                  # 抽象层主接口
├── provider-noble.ts            # @noble/post-quantum backend (默认)
├── provider-node-builtin.ts     # node:crypto fallback
└── index.ts                     # barrel export
```

---

## 🛣️ 路线图

### v0.1.0（**当前**）— 抗量子基础
- ✅ M1 抽象层（crypto-agility）
- ✅ M3 Device Identity 双套签名（Ed25519 + ML-DSA-44）
- ✅ M4 Nostr NIP-44
- ✅ Node 22+ hybrid KEM 自动启用
- ✅ 端到端跑通 7 个 PQC 算法

### v1.0.0（3 个月内，2026-10-22 截止）
- 🚧 修 OpenClaw 主仓 bug（`node-domexception` + `write-cli-startup-metadata`）
- 🚧 飞书端到端回归测试
- 🚧 文档完善 + CHANGELOG
- 🚧 GitHub release v1.0.0
- 🚧 npm 发布 `@ben-jianming/openclaw-pqc@1.0.0`

### v1.1.0（v1.0 后 1-2 月）
- 🚧 M2 Gateway TLS ML-DSA-65 自签证书（等 Node 25+ WebCrypto GA，~2025-10）
- 🚧 Nostr 事件签名 PQC 双签
- 🚧 Feishu payload AES-CBC → AES-GCM
- 🚧 APNs / VAPID / Twilio PQC（等 Apple / IETF / Twilio 升级）

### v1.2+（监测）
- Signal Double Ratchet PQC
- Matrix olm/megolm PQC
- CNSA 2.0 全合规（2030 截止）

---

## 🤝 贡献

欢迎贡献代码、报告问题、提 PR！请看 [CONTRIBUTING-PQC.md](docs/CONTRIBUTING-PQC.md)。

特别欢迎：
- 跨平台测试（macOS / Windows / 其他 Linux 发行版）
- PQC 性能 benchmark（不同硬件）
- 新 PQC 算法支持（SLH-DSA, FN-DSA）
- 飞书 / 钉钉 / Slack 集成测试
- 文档改进

---

## 🔒 安全

发现安全问题请发邮件到 `2724362782@qq.com`（**不要**在 GitHub Issues 公开披露）。详细政策看 [SECURITY.md](SECURITY.md)。

### 已实现的安全特性

- ✅ Hybrid KEM TLS（X25519 + ML-KEM-768）
- ✅ 设备身份 ML-DSA-44 双套签名
- ✅ NIP-44 AEAD Nostr DM
- ✅ Crypto-agility 抽象层
- ✅ 自动备份（`upgrade-to-pqc.sh`）
- ✅ 一键回滚

---

## 📊 性能基线

完整 benchmark 看 [V1.0-DELIVERY-REPORT.md §5](docs/V1.0-DELIVERY-REPORT.md)。

### 关键 SLA

- WebSocket connect frame 签名：每连接一次，< 50ms 完全 OK（noble 1.8ms 远超）
- APNs JWT 重签：每 50 分钟一次，0.4 vs 1.8ms 没差
- Gateway TLS 握手：Node 22 hybrid KEM 内部，noble 不参与，0 影响

---

## 🧪 测试

```bash
# PQC smoke test
bash scripts/e2e-1-pqc-bench.sh

# 单元测试
pnpm test

# 集成测试
pnpm test:integration

# 端到端（飞书）
# 参考 docs/DAY4-E2E-TEST.md
```

---

## 📜 许可

[MIT License](LICENSE) — 刘简铭（Ben-Jianming）

基于 [OpenClaw](https://github.com/openclaw/openclaw) 二次开发。

---

## 🙏 致谢

- **OpenClaw** 上游 — [openclaw/openclaw](https://github.com/openclaw/openclaw)
- **NIST** — FIPS 203/204 标准
- **noble 团队** — [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)
- **Open Quantum Safe** — liboqs 参考实现
- **Cloudflare** — X25519MLKEM768 hybrid KEM 部署经验
- **刘简铭（Ben-Jianming）** — 项目负责人
- **Mavis** — 协作助理

---

> **抗量子龙虾项目 · 抗量子不是 PPT 概念，是真跑通的代码** 🦞
