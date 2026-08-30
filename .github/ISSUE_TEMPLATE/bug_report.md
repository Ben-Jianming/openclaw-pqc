---
name: Bug Report
about: 报告 bug（功能异常、性能问题、文档错误等）
title: '[BUG] '
labels: 'bug'
assignees: ''
---

## Bug 描述

清晰简洁地描述 bug。

## 复现步骤

1. ...
2. ...
3. ...

## 期望行为

应该发生什么。

## 实际行为

实际发生了什么。

## 环境信息

- **OpenClaw-PQC 版本**：v0.1.0
- **Node.js 版本**：`node --version` 输出
- **操作系统**：Ubuntu 24.04 / macOS 14 / Windows 11 / ...
- **OpenClaw 上游版本**：2026.6.9 / 2026.7.x
- **PQC 库版本**：
  ```bash
  cat node_modules/@noble/post-quantum/package.json | grep version
  cat node_modules/@noble/curves/package.json | grep version
  cat node_modules/@noble/hashes/package.json | grep version
  ```

## 错误日志

```
粘贴完整错误日志
```

## 截图（可选）

如果是 UI 相关问题。

## 额外上下文

任何其他相关信息。

---

**报告安全问题请不要用 issue** — 看 [SECURITY.md](SECURITY.md)。
