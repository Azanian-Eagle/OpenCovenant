# OpenCovenant & The Vela Programming Language (`.vela`)

**An Azanian Eagle Project** • *Compile-Time Data Sovereignty, Information-Flow PII Taint Tracking, and Formally Verified Regulatory Guardrails (POPIA, GDPR, CCPA, SARB).*

## Quickstart

```bash
# 1. Run compiler unit tests
cargo test --workspace

# 2. Verify a compliant POPIA/GDPR sovereignty contract
cargo run --bin velac -- check contracts/edtech_popia_guard.vela

# 3. Watch velac catch an unredacted SA ID & minor transcript leak at compile time
cargo run --bin velac -- check contracts/broken_leak_demo.vela

# 4. Compile a .vela contract into TypeScript, Python FastAPI, and PostgreSQL RLS targets
cargo run --bin velac -- build contracts/edtech_popia_guard.vela --out-dir ./gen

# 5. Generate a SHA-256 cryptographic compliance attestation
cargo run --bin velac -- audit contracts/edtech_popia_guard.vela
```
