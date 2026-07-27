# Changelog

All notable changes to OpenClaw-PQC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-22 (计划发布)

### Added
- 飞书端到端回归测试 + 集成测试
- 修复 OpenClaw 主仓 bug（`node-domexception` + `write-cli-startup-metadata`）
- 完整 CHANGELOG + 文档
- GitHub Actions CI workflow
- npm 发布 `@ben-jianming/openclaw-pqc@1.0.0`

## [0.1.0] - 2026-07-27

### Added
- **M1 抽象层（crypto-agility）**：新增 `src/infra/crypto/` 4 个文件
  - `provider.ts` — 抽象层主接口（CryptoProvider / Key / SignAlg / KemAlg / HashAlg）
  - `provider-noble.ts` — `@noble/post-quantum` backend（默认）
  - `provider-node-builtin.ts` — `node:crypto` fallback（仅支持旧算法）
  - `index.ts` — barrel export
- **M3 Device Identity 双套签名**：`src/infra/device-identity.ts` 追加 3 个 PQC 函数
  - `ensureDeviceIdentityMlDsa44()` — 设备身份自动创建 / 升级到 v2（含 ML-DSA-44）
  - `signDevicePayloadMlDsa44()` — 用 ML-DSA-44 签 payload
  - `verifyDeviceSignatureMlDsa44()` — 用 ML-DSA-44 验签
  - 向后兼容：旧 Ed25519 签名继续工作
- **M4 Nostr NIP-44**：`extensions/nostr/src/nostr-bus.ts` 追加 2 个函数
  - `encryptNip44()` — NIP-44 AEAD 加密（替代 AES-CBC）
  - `decryptNip44()` — NIP-44 AEAD 解密
- **Node 22+ hybrid KEM**：OpenClaw 主仓自动启用 X25519 + ML-KEM-768（零代码改动）
- **3 个新依赖**：
  - `@noble/post-quantum@0.5.0`
  - `@noble/curves@2.0.0-beta.3`
  - `@noble/hashes@2.0.0-beta.5`
- **14 份文档**：
  - `V1.0-DELIVERY-REPORT.md` — 完整交付报告
  - `RUNBOOK.md` — 运维手册
  - `PR-1-M1-CRYPTO-PROVIDER.md` — M1 抽象层 PR 草稿
  - `PR-2-M2-GATEWAY-TLS-DUAL-CERT.md` — M2 Gateway TLS 双证书草稿（v1.1）
  - `DAY1-STATUS.md` — Day 1 现状评估
  - `DAY4-PATCH-GUIDE.md` — 修 OpenClaw 主仓 bug
  - `DAY4-E2E-TEST.md` — 飞书端到端测试
  - `PQC-LIBRARY-CHOICE.md` — PQC 库选型
  - `CRYPTO-CALLPOINTS.md` — 加密面盘点
  - `CONTRIBUTING-PQC.md` — PQC 贡献指南
  - `CHANGELOG-PQC.md` — 旧版 CHANGELOG（兼容）
  - `UBUNTU-DEPLOY.md` — Ubuntu 部署
  - `README-PQC.md` — PQC 改造详细说明
  - `e2e-1-pqc-bench.sh` — PQC smoke test 脚本
- **3 个脚本**：
  - `upgrade-to-pqc.sh` — 全自动升级 + 回滚（13KB）
  - `ubuntu-setup.sh` — Ubuntu 初始部署（5.7KB）
  - `setup-pqc.sh` / `setup-pqc.ps1` — 跨平台安装

### Changed
- **设备身份 JSON schema**：v1 → v2 自动迁移（保留 Ed25519，叠加 ML-DSA-44）
- **Nostr DM 加密**：AES-CBC + 静态 IV → NIP-44 AEAD（可配置回退）

### Security
- **Harvest-now-decrypt-later TLS 流量**：Hybrid KEM 抗
- **设备身份伪造**（10 年生命周期）：ML-DSA-44 抗
- **Nostr DM 篡改**（AES-CBC + 静态 IV）：NIP-44 AEAD 抗
- **算法切换**（从 RSA 换 ECC）：改配置即可（crypto-agility）

### Performance
- ML-DSA-44 sign：7.98 ms（应用 SLA 30 秒一次，完全 OK）
- ML-DSA-44 verify：0.7 ms
- ML-KEM-768 encap：1.2 ms（hybrid KEM 透明，零影响）
- ML-KEM-768 decap：1.4 ms
- Ed25519 保持原性能（向后兼容）

### Tested
- 7/7 PQC 算法 smoke test 通过，零失败
- 涵盖：ML-DSA-44/65/87 + ML-KEM-512/768/1024 + Ed25519
- 测试环境：Intel Xeon Gold 6248 @ 2.5GHz / Node 24.16.0 / Ubuntu 24.04.4 LTS

### Known Issues
- OpenClaw 主仓 transitive dep `node-domexception@1.0.28` 跟 npm registry 不兼容（`DAY4-PATCH-GUIDE.md` 提供 patch 方案）
- OpenClaw `write-cli-startup-metadata` postbuild 跑 `openclaw --help` 时 crash（不影响 PQC 本身）

---

[Unreleased]: https://github.com/Ben-Jianming/openclaw-pqc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ben-Jianming/openclaw-pqc/releases/tag/v0.1.0
[1.0.0]: https://github.com/Ben-Jianming/openclaw-pqc/milestone/1
