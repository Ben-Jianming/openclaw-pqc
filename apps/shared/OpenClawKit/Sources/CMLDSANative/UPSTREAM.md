# mldsa-native vendoring record

- Project: `pq-code-package/mldsa-native`
- Release: `v2.0.0`
- Source archive commit prefix: `834a90d`
- Upstream: <https://github.com/pq-code-package/mldsa-native>
- Vendored scope: portable fixed-level ML-DSA source under `mldsa/`
- Build configuration: ML-DSA-65, core API only, reduced RAM, portable C backend
- License choice for the vendored library: MIT (the upstream library is offered under Apache-2.0 OR ISC OR MIT)

The OpenClaw bridge derives the full private key from the persisted 32-byte
seed for each signature and clears the expanded private key before returning.
Platform-specific assembly is deliberately not enabled so the same audited C
path is used on every supported Apple architecture.
