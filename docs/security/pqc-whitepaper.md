# PQC OpenClaw Fork — Whitepaper (Production v1 部署版)

**版本**: production v1 (2026 年 8 月 30 日)
**最近更新:** §2.2.5.A 加入 M12 v3 source-level FileKeyring auto-inject (auto-inject hook 实现 `OPENCLAW_WRAP_KEY_FILE` + `OPENCLAW_WRAP_KEY_ID` env vars → fork 启动 1.7s 内 auto-wrap)
**作者**: danteng (吴昊天, wu <wuc8974@gmail.com>) + Mavis (co-author, Mavis <mavis@example.com>)
**对应代码仓**: `WU123-ABC-Cell/pqc-openclaw:master` (白皮书驱动) + 本地部署 `D:\openclaw-pqc\production\` (Windows fs) + `/home/abc/openclaw-fork-v3/` (WSL native fs)

---

## §1. 摘要 (Executive Summary)

本 fork 把 OpenClaw 所有签名 / 加密 / 传输路径替换为抗量子 (PQC, Post-Quantum Cryptography) 算法,在保留 legacy client 兼容性的前提下达到 NIST FIPS 203/204/205 标准。

**核心 PQC 替换**:
- **ML-DSA-65** (FIPS 204, 1952 字节公钥 + 4032 字节私钥 + 3309 字节签名) 替换 Ed25519 设备签名
- **ML-KEM-768** (FIPS 203) 替换 ECDH / X25519 密钥封装 (走 NIP-44 v2 hybrid envelope, `pqc2:` wire-format 前缀)
- **AES-256-GCM** + **PBKDF2-SHA256** (210,000 iters, OWASP 2023) 做设备私钥 wrap(plaintext 永不落盘)
- **Apple APNs JWT (ES256)** 不动(Apple 协议约束),app-layer 走 Ed25519 + ML-DSA-65 dual signature 兼容 legacy client

**达成目标**:
- 13/13 milestones (M1-M13) 全在 `WU123-ABC-Cell/pqc-openclaw:master`
- 267+ invariants 全过(tsgo:core 0 errors)
- Production 部署 4 步证据链全 PASS(Dashboard / SQLite / PQC log markers / dist symbols)
- **M12 v3 优化 (2026-08-30 commit HEAD)**: FileKeyring auto-inject source-level 实现,5 env var 启动→fork ready 1.7s(vs 老 v2 hand-roll 167s,**98x speedup**)

---

## §2. 拆解(按 milestone)

### §2.1 ML-DSA-65 设备身份 (M1-M2)

### §2.1.1 ML-DSA-65 device identity via @noble (FIPS 204)

- **根因**: Ed25519 在量子计算机面前不安全(Shor's algorithm O(n^3) 解 discrete log),需要 lattice-based 替代
- **修法**: 替换 `src/infra/device-identity.ts` 里 Ed25519 keygen / sign / verify → ML-DSA-65。`@noble/post-quantum` 走 **hedged mode** (FIPS 204 §5.3, NIST 推荐,每次 sign 加 32 字节随机 seed)
- **坑**: KAT 24 组 round-trip,签名函数收 **raw 4032 字节** 不是 PEM prefixed bytes;prefix 只是 storage 格式,签验前必须 `decodeMlDsa65SecretKey` 反解
- **测试**: 17 invariants (M1/M2 KAT round-trip)

### §2.1.2 公共 API rewire (Ed25519 KAT 主动 skip)

- **根因**: 老 Ed25519 KAT 用 `signPayload()` 全局,改 ML-DSA-65 后这些 KAT 必须 `it.skip(...)` + 加 `(PQC: Ed25519 removed by M2)` 注释
- **修法**: constant-false if-guard 替代 `describe.skip`(顶层 for-of fixtures 仍 evaluate body)
- **坑**: 不要删 `device-identity-legacy.ts`,老 migrate 路径还在用
- **测试**: 0 new tests (跟着 M1 KAT 走)

### §2.1.3 state.db schema 4 列加 (M3 additive)

- **根因**: state.db 要存 `mldsa_public_key_pem` + `mldsa_private_key_pem` + `mldsa_private_key_wrapped` (BLOB) + `mldsa_private_key_wrap_key_id`
- **修法**: `ALTER TABLE device_identities ADD COLUMN ... × 4` 纯 additive,不 bump schema version (AGENTS.md 规则)
- **坑**: BLOB 字段在 Kysely typed 是 `Uint8Array | null`,TypeScript 收窄时 `instanceof Uint8Array` 不行,改 `!== null && length > 0` hoist 到 local
- **测试**: 4 invariants (schema additive) + 17 invariants (M1 KAT 跟着重写) + 111 state-db invariants

### §2.2 私钥 wrap + keyring (M4-M8)

### §2.2.1 AES-256-GCM wrap envelope (M4)

- **根因**: ML-DSA-65 私钥 4032 字节,不能 plaintext 落 state.db(攻击者拿到 db 直接用)
- **修法**: `wrapSecret(plaintext, keyId, key)` → `{iv, ciphertext, authTag, keyId}`,12-byte fresh IV + 16-byte auth tag + 32-byte key length check
- **坑**: BLOB 编码用 UTF-8 bytes of base64url string(不是 raw JSON),`Buffer.from(blob).toString("utf8")` → deserialize
- **测试**: 23 invariants (round-trip / IV uniqueness / tamper detection)

### §2.2.2-§2.2.4 device-identity store 接 wrap (M5)

- **根因**: `device-identity-store.ts` 必须接 wrappingKeyProvider,plaintext / wrapped 互斥
- **修法**: `StoredDeviceIdentity` 加 3 字段,`fail-closed` 策略(wrapped row 没 keyring 拒绝,**不**静默 fallback plaintext)
- **坑**: `Buffer.from(row.mldsa_private_key_wrapped)` 在 `Uint8Array | null` 上 TS 不收窄,hoist local
- **测试**: 11 invariants (round-trip / fail-closed / two-keyring cross-read)

### §2.2.5 WrappingKeyProvider File / Env / Composite (M6)

- **根因**: keyring 不能 hard-code,要可换 File (POSIX 0600) / Env / Composite fallback chain
- **修法**: `FileKeyring` 启动时校验 mode 0600/0400 拒其他权限;`EnvKeyring` 每次重读 env(不 cache);`CompositeKeyring` walk-all
- **坑**: ESM 模式下 vitest 编译成 ESM,动态 `require()` 不工作 — 全用 static `import`
- **测试**: 30 invariants

### §2.2.5.A **M12 v3 FileKeyring auto-inject (Production v1 当前)**

- **根因**: 老 M5.5 v2 是 runtime patch FileKeyring(从 `OPENCLAW_WRAP_KEY_FILE` 读),启动 167s — `output-root-guard` + `FileKeyring.getActiveKey` lazy init + sqlite fingerprint cache 拖慢
- **修法**: 在 `src/security/keyring-provider.ts` source-level 实现 `getDefaultKeyringFromEnv()`:
  ```ts
  export function getDefaultKeyringFromEnv(): FileKeyring | null {
    const path = process.env.OPENCLAW_WRAP_KEY_FILE;
    if (!path) return null;
    const keyId = process.env.OPENCLAW_WRAP_KEY_ID || 'wrap-key-default';
    return new FileKeyring({ path, primaryKeyId: keyId });
  }
  ```
  + `OPENCLAW_STATE_DIR/openclaw.json` start 时 inject keyring provider 进 device-identity-store
- **坑**: 启动顺序 `getDefaultKeyringFromEnv()` 必须早于 `device-identity-store` 初始化,否则 sqlite 读 plaintext
- **测试**: 通过 `127.0.0.1:18791/healthz < 1.7s` + sqlite `mldsa_private_key_wrapped > 0` 验证
- **效果**: Production fork ready time **167s → 1.7s (98x speedup)**,dashboard `m12v3.bootLabel = "1.7s"`

### §2.2.5.B OS Keyring stub (M6.B 待办,本部署未启用)

- **根因**: FileKeyring 还是 disk-resident;OsKeyring 走 Keychain (mac) / libsecret (linux) / Credential Vault (win) 更安全
- **当前**: `OsKeyring` class 已写,**fail-closed "M6.B not implemented" message**,等 `@napi-rs/keyring` native dep 装上启用
- **测试**: 暂跳过,stub 模式

### §2.2.5.C Wrap-key rotation (M7)

- **根因**: wrap key 单点泄露风险,必须支持 rotate + backup/restore
- **修法**: `rotateWrappingKey({oldKeyring, newKey, store})` 重 wrap 每个 row;`exportWrapKey` / `importWrapKey` 用 PBKDF2 + AES-256-GCM 备份到 passphrase envelope (envelope 字段全 base64url)
- **坑**: PBKDF2 iters 210000 (OWASP 2023),`crypto.timingSafeEqual` 用于 `constantTimeEqual`,长度必须先 check
- **测试**: 19 invariants

### §2.2.7-§2.2.8 wrap-key health + CLI helpers (M8)

- **根因**: 部署后运维需要 health check + 手动 rotate / import 命令入口
- **修法**: `wrapKeyHealthCheck(store, keyring)` 返回 plain/wrapped-active/wrapped-stale 状态;CLI alias 写了但暂不 register
- **测试**: 13 invariants

### §2.2.9 [PQC] 结构化日志 (M9)

- **根因**: PQC 事件(unwrap-secret / device-identity / sign-device-payload / nip44-v2-decrypt)需要统一 redact + vocabulary
- **修法**: `PQC_EVENT` string union + `pqcLog.{info,warn,error,debug}(payload)` chokepoint + PqcEmit boundary 删 undefined / 拒 Buffer / 拒 `passphrase|rawkey|privatekey` 字段
- **测试**: 9 invariants

### §2.3 Nostr NIP-44 v2 + ML-KEM-768 (M10)

- **根因**: Nostr DM 走 NIP-44 v2,标准用 ECDH(不安全);fork 走 ML-KEM-768 hybrid envelope
- **修法**: wire format `pqc2:` + base64url(ml-kem-ct) + `.` + base64url(chacha-ct) + `.` + base64url(mac);`pad` 2-byte BE length + 32-byte aligned;`unpad` 反向,**modulus 是 `(padded.length - 2) % 32 !== 0`**
- **测试**: 17 invariants (HKDF / ChaCha20 / HMAC / wire-format)

### §2.4 APNs ML-DSA-65 fallback dual signature (M11)

- **根因**: Apple APNs JWT (ES256) 不能改,老 push client 用 Ed25519,必须 dual sig 兼容
- **修法**: app-layer envelope `{algorithms: ["ed25519", "ml-dsa-65"], ed25519_sig, mldsa65_sig, key_id_ed25519, key_id_mldsa65}`;verify fail-closed(任一失败抛错)
- **坑**: Ed25519 走 `src/infra/ed25519-signature.ts` **不是** `@noble/curves/ed25519`(后者无 `randomPrivateKey`,M11 第一版 12/13 failed)
- **测试**: 13 invariants

### §2.5 pnpm build + fork boot (M12 v3)

- **本部署 (Production v1)**: fork 启动命令:
  ```bash
  cd /home/abc/openclaw-fork-v3/dist \
    && OPENCLAW_STATE_DIR=/home/abc/openclaw-fork \
       OPENCLAW_GATEWAY_TOKEN=lobster-pqc-v3 \
       OPENCLAW_WRAP_KEY_FILE=/home/abc/openclaw-fork/wrap-key.bin \
       OPENCLAW_WRAP_KEY_ID=wrap-key-2026-08 \
       DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY \
       node ./index.js gateway run --port 18791 --allow-unconfigured
  ```
- **验证**: healthz 1.7s ready + sqlite `mldsa_private_key_wrapped > 0` + log `[PQC] unwrap-secret byteLength=4032`

---

## §3. 部署约定 (Production v1)

- **fork runtime**: `D:\openclaw-pqc\production\` (Windows fs, handoff §1.3 验证) / **或** `/home/abc/openclaw-fork-v3/` (WSL native fs, handoff §1.2 推荐)
- **端口**: 18791(v3 standard, 18789 是 v2 DEPRECATED)
- **gateway token**: `lobster-pqc-v3`(M12 v3 auto-inject 验证)
- **5 env var 必设**:
  - `OPENCLAW_STATE_DIR` = `/home/abc/openclaw-fork` 或 `C:\Users\Benjamin\.openclaw\`
  - `OPENCLAW_GATEWAY_TOKEN` = `lobster-pqc-v3`
  - `OPENCLAW_WRAP_KEY_FILE` = `/home/abc/openclaw-fork/wrap-key.bin` (mode 0600)
  - `OPENCLAW_WRAP_KEY_ID` = `wrap-key-2026-08`
  - `DEEPSEEK_API_KEY` = `$DEEPSEEK_API_KEY` (走 SecretRef, 不进 openclaw.json)
- **state dir**: sqlite 在 `$OPENCLAW_STATE_DIR/state/openclaw.sqlite`
- **dashboard**: `http://localhost:18800/` collector 验 v3 metrics

### §3.1 Dashboard 字段

- `m12v3.active = True`
- `m12v3.bootLabel = "1.7s"`
- `bundleSymbols._isV3 = True`
- PQC 路径覆盖 6 项(deviceIdentity / wsSign / wsVerify / secretWrap / secretUnwrap / pqcLog), 至少 1 live, 其余 ready
- failed bucket label 不用 `401` 等误导,改用 `error_code: run_failed`

### §3.2 SQLite 状态

```bash
sqlite3 $OPENCLAW_STATE_DIR/state/openclaw.sqlite \
  "SELECT identity_key, length(mldsa_public_key_pem), length(mldsa_private_key_wrapped), mldsa_private_key_wrap_key_id FROM device_identities;"
```

期望 `primary | 2622 | 7351 | wrap-key-2026-08`,plaintext = 0。

### §3.3 PQC log markers

```bash
grep -E '\[PQC\]' /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log
```

期望看到:`[PQC] unwrap-secret byteLength=4032` + `[PQC] device-identity unwrapped stored identity` + `[PQC] sign-device-payload` + `[PQC] nip44-v2-decrypt`。

### §3.4 dist symbols

```bash
grep -l 'getDefaultKeyringFromEnv\|wrapSecret\|MLDSA65' /home/abc/openclaw-fork-v3/dist/*.js
```

期望 ≥3 个 .js 命中(keyring-provider + secret-wrapping + device-identity)。

---

## §4. 实现细节(略,见原 13 章节 PRD)

---

## §5. 性能(略)

---

## §6. 剩余风险 (Production v1)

### §6.1 老 plaintext row migration

**风险**: 老 fork 跑过一段时间后 state.db 有 `mldsa_private_key_pem` (plaintext) + `mldsa_private_key_wrapped=NULL` row,M12 v3 fail-closed 拒绝读。

**修法**: 部署前 `DELETE FROM device_identities WHERE identity_key='primary'` 重建。production fork 已是 wrapped 状态(2026-08-30 验证)。

### §6.2 OPENCLAW_WRAP_KEY_FILE 错配

**风险**: env 没设 / 路径不存在 / mode 0644 等宽权限 → fork 启动 fail,FileKeyring 抛错。

**修法**: `ls -la $OPENCLAW_WRAP_KEY_FILE` 验证存在 + mode 0600;`new FileKeyring(...)` 启动时 stat-check,拒非 0600/0400。

### §6.3 OS Keyring 未启用 (M6.B)

**风险**: wrap key 仍在 file(磁盘泄露风险),OS Keychain (Mac) / libsecret (Linux) / Credential Vault (Win) 还没接。

**当前**: `OsKeyring` stub fail-closed "M6.B not implemented"。等 `@napi-rs/keyring` native dep。

### §6.4 feishu bot open_id 配错

**风险**: `cli_aaaffea2b138dbfc` + `JUfFJ51N...` 配错 → 飞书推送失败。

**当前**: production 已验证(`open_id = ou_5582a5dbbe5b34e16fd18c6666fadb0c`)。

---

## §7-§9 (略)

---

## §10. 未来工作

| 优先级 | 任务 | 状态 |
|--------|------|------|
| P0 | OsKeyring (M6.B) | ⏳ 等 `@napi-rs/keyring` native dep |
| P0 | HSM 集成 (YubiKey/TPM 2.0) | ⏳ backlog |
| P1 | ML-KEM TLS 1.3 (X25519MLKEM768) | ⏳ backlog |
| P1 | 签名/验签 cache | ⏳ backlog |
| P1 | mlock wrap key | ⏳ backlog |
| **已 ✅** | **M12 v3 FileKeyring auto-inject (2026-08-30)** | ✅ Production v1 (本部署) — **启动 167s → 1.7s, 98x speedup** |
| **已 ✅** | **3/3 老 plaintext row migration** | ✅ Production v1 (本部署) |
| **已 ✅** | **feishu bot push 整合** | ✅ Production v1 (本部署) |
| P2 | Nostr DM 历史迁移 (NIP-04 → NIP-44 v2) | ⏳ backlog |
| P2 | PQC 算法切换自动监测 | ⏳ backlog |
| P2 | 客户端迁移进度 dashboard | ⏳ backlog |
| P3 | SLH-DSA (FIPS 205) | ⏳ backlog |
| P3 | FN-DSA (Falcon) | ⏳ backlog |

---

## §11. 参考链接

- 白皮书源文 (`WU123-ABC-Cell/pqc-openclaw:master`): `docs/security/pqc-whitepaper.md` (489 行)
- M1-M13 commit 链: `38279d6105` → `7b08898012` → `7dc240ab1c` → `55adc8e74c` → `4ea19e91b1` → `b9eb3599e0` → `d1cfcf4aad` → `0444c2ad49` → `4978c808d9` → `c4f5de9c37` → `9463da0d08` → (M12 build) → `4a7043984e` (M13 push)
- Production v1 部署摘要: `D:\openclaw-pqc-summary\openclaw-pqc-summary.pdf` (23 页 303 KB)
- 论文 v11: `D:\minimax\paper\paper-v1.pdf` (33 页 7 theorems)
- Handoff Part 1: `D:\openclaw-pqc\docs\handoff\prompt.md` (M1-M14 + 白皮书)
- Handoff Part 2: `D:\openclaw-pqc\docs\handoff\part2-ops.md` (运维 / 扩展)

---

## §12. 变更日志

| 日期 | 版本 | 改动 | Commit |
|------|------|------|--------|
| 2026-08-30 | Production v1 | M12 v3 FileKeyring auto-inject 部署 + whitepaper 5 段 §1/§2.2.5.A/§6/§10/header | `HEAD` (本地 fork) |
