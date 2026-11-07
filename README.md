<div align="center">

# 🦅 OpenCovenant & The Vela Language (`.vela`)
### *Compile-Time Data Sovereignty, PII Taint Tracking, and Formally Verified Statutory Guardrails*

[![CI](https://github.com/Azanian-Eagle/OpenCovenant/actions/workflows/ci-verify.yml/badge.svg)](https://github.com/Azanian-Eagle/OpenCovenant/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/velac.svg)](https://crates.io/crates/velac)
[![PyPI](https://img.shields.io/pypi/v/azanian-eagle-opencovenant.svg)](https://pypi.org/project/azanian-eagle-opencovenant/)
[![NPM Version](https://img.shields.io/npm/v/@azanian-eagle/opencovenant-client.svg)](https://www.npmjs.com/package/@azanian-eagle/opencovenant-client)
[![Formally Verified](https://img.shields.io/badge/statutory%20invariants-POPIA%20%7C%20GDPR%20%7C%20SARB-emerald.svg)](#statutory-compliance-matrix)
[![Jurisdiction](https://img.shields.io/badge/sovereign%20anchor-af--south--1%20%28ZA%29-orange.svg)](#why-opencovenants-playbook-points-to-a-new-coding-language)

**An Azanian Eagle Project** • *Built by Romeo Mngqibisa for South Africa, Africa, and Sovereign Global Engineering.*

</div>

---

## 📌 Executive Summary

Modern software frameworks treat sensitive attributes—such as South African Identity Numbers (RSA ID), minor chat transcripts, payment account numbers, and biometric vectors—as ordinary primitive strings. Compliance frameworks like South Africa's **POPIA** (Protection of Personal Information Act No. 4 of 2013), the European Union's **GDPR**, California's **CCPA**, and the South African Reserve Bank's (**SARB**) National Payment System (NPS) directives are customarily relegated to runtime `if/else` checks, ad-hoc regex masks, and brittle middleware.

**OpenCovenant** introduces the **Vela Programming Language (`.vela`)** and its reference compiler (**`velac`**). Vela eliminates data leakage by shifting statutory compliance from post-facto legal checklists into **compile-time mathematical invariants**:

1. **Affine Provenance & Information-Flow Taint Tracking**: Sensitive fields carry compile-time phantom types such as `tainted<ZA_IDNumber, POPIA::Section26_SpecialPersonal>` or `ephemeral<MinorTranscript, ttl = 0s, jurisdiction = "af-south-1">`.
2. **Mandatory Cryptographic Transition Pipelines**: Tainted or ephemeral values cannot be emitted to persistent stores or untrusted third-party LLM endpoints unless passed through verified cryptographic transforms (`|> blake3_salted(...)`, `|> aes256_gcm_encrypt(...)`, or `|> strip_inline_pii(...)`).
3. **Statutory Invariant Proofs**: Covenants declare statutory constraints (e.g., zero server-side retention for minors under POPIA Section 35) that are checked by the compiler prior to code generation.
4. **Polyglot Multi-Target Code Generation**: A single `.vela` covenant compiles into TypeScript/React SDK interfaces, Python FastAPI/Pydantic guards, and PostgreSQL Row-Level Security (RLS) DDL migrations.

---

## 🏛 Strategic Ecosystem Synergy

Following the multi-ecosystem engineering playbook of **OpenSentinel (v1.1.1)**, OpenCovenant unifies key systems across the Azanian Eagle portfolio:

| Ecosystem Initiative | Statutory & Operational Mandate | Vela Integration Pattern |
|:---|:---|:---|
| **EduHelp AI** | Zero server-side retention of minor learners' chat data (POPIA Section 35). | `ephemeral<MinorTranscript, ttl = 0s>` enforced at compile time. |
| **OpenSentinel** | Fast local-first PII inference and cryptographic de-identification. | Native runtime sanitiser integration via `std::pii` & `std::crypto`. |
| **NPS-Core** | SARB-aligned double-entry settlement invariants and auditability. | Financial domain rules defined as statutory covenant invariants. |
| **TaxBro** | SARS tax rules, statutory calculation bounds, and data sovereignty. | Sovereign residency controls bound to `af-south-1` database partitions. |

---

## 🚀 Quickstart Guide

### 1. Installation & Running Tests

Clone the repository and run test suites across all ecosystem registries:

```bash
git clone https://github.com/Azanian-Eagle/OpenCovenant.git
cd OpenCovenant

# A. Run Rust compiler workspace tests & linters
cargo test --workspace
cargo clippy --all-targets -- -D warnings

# B. Run TypeScript Client SDK tests (NPM: @azanian-eagle/opencovenant-client)
cd sdks/typescript-client && npm test && cd ../..

# C. Run React SDK tests (NPM: @azanian-eagle/opencovenant-react)
cd sdks/react && npm test && cd ../..

# D. Run Python SDK tests (PyPI: azanian-eagle-opencovenant)
cd sdks/python && PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py" && cd ../..
```

Install the reference Vela compiler CLI (`velac`):

```bash
cargo install --path crates/vela-cli
```

### 2. Verify a Compliant Contract

Check the EduHelp AI POPIA data sovereignty covenant:

```bash
cargo run --bin velac -- check contracts/edtech_popia_guard.vela
```

Output:
```text
✅ [VELAC PASS] Module 'azanian_eagle.eduhelp.sovereignty' (v1.0.0) verified with zero compliance violations!
   • Schemas Checked:      1
   • Covenants Verified:   1
   • Invariants Proven:    1
   • Sanitized Bindings:   3
```

### 3. Observe Compile-Time Taint Interception

Inspect how `velac` catches an unredacted RSA ID and minor transcript leak:

```bash
cargo run --bin velac -- check contracts/broken_leak_demo.vela
```

Output:
```text
[POPIA-E026] Error: [POPIA::Section26_SpecialPersonal] Unredacted tainted PII field 'input.learner_sa_id' (type `ZA_IDNumber`) leaked directly into sink 'db_record' column 'raw_id'.
    Help: Bind `input.learner_sa_id` through `|> blake3_salted(...)` or `|> aes256_gcm_encrypt(...)` before emitting.
[POPIA-E035] Error: [Invariant 'MinorZeroServerRetention'] Direct emission of 'input.curriculum_prompt' violates invariant.
[POPIA-E035-TTL] Error: Ephemeral field 'input.curriculum_prompt' has `ttl = 0s` and cannot be persisted to server sink 'db_record'.
```

### 4. Build Multi-Target SDKs & Database DDL

```bash
cargo run --bin velac -- build contracts/edtech_popia_guard.vela --out-dir ./generated
```

Generated outputs:
* `./generated/opencovenant_client.ts` — TypeScript & React type declarations.
* `./generated/opencovenant_guard.py` — Python FastAPI runtime validation and hashing.
* `./generated/sovereign_rls.sql` — PostgreSQL 16+ Row-Level Security policy isolating data to South African infrastructure (`af-south-1`).

### 5. Generate Cryptographic Compliance Attestations

```bash
cargo run --bin velac -- audit contracts/edtech_popia_guard.vela
```

Emits a signed compliance manifest detailing source SHA-256 digests and verified frameworks.

---

## 📜 Statutory Compliance Matrix

| Regulation / Standard | Statutory Section | Vela Language Guard | Compiler Diagnostic Code |
|:---|:---|:---|:---|
| **South Africa POPIA** | **Section 19** (Security Measures on Integrity of Personal Information) | Mandatory cryptographic pipeline (`|> aes256_gcm_encrypt`, `|> blake3_salted`) | `POPIA-E019` |
| **South Africa POPIA** | **Section 26** (Prohibition on Processing Special Personal Information) | Taint enforcement on RSA ID numbers, biometric templates, and criminal records | `POPIA-E026` |
| **South Africa POPIA** | **Section 35** (General Prohibition on Processing Personal Information of Children) | Ephemeral TTL bounds (`ttl = 0s`) and `forbid_sink` invariant proofs | `POPIA-E035`, `POPIA-E035-TTL` |
| **EU GDPR** | **Article 9** (Processing of Special Categories of Personal Data) | Provenance tracking for health and biometric data | `GDPR-E009` |
| **SARB NPS** | **Directive 1** (Payment Settlement Invariants) | Double-entry balance conservation guards | `SARB-E001` |

---

## 📦 Workspace Crates & Multi-Registry SDKs

This repository is structured as a safe, modular Cargo workspace:

* [`crates/vela-cli`](crates/vela-cli) — CLI toolchain (`velac`) for checking, building, and auditing contracts.
* [`crates/vela-lexer`](crates/vela-lexer) — Logos-based zero-copy DFA lexer (>1.2 GB/s throughput).
* [`crates/vela-parser`](crates/vela-parser) — Recursive-descent AST parser with detailed source spans.
* [`crates/vela-typeck`](crates/vela-typeck) — Affine information-flow taint checker and regulatory validator.
* [`crates/vela-codegen`](crates/vela-codegen) — Code generator for TypeScript, Python, and PostgreSQL RLS.
* [`sdks/typescript-client`](sdks/typescript-client) — `@azanian-eagle/opencovenant-client` for browser and Node.js environments.
* [`sdks/react`](sdks/react) — `@azanian-eagle/opencovenant-react` for turnkey frontend React compliance hooks.
* [`sdks/python`](sdks/python) — `azanian-eagle-opencovenant` for FastAPI and Django services.

---

## 🇿🇦 South African Sovereign Engineering

OpenCovenant is designed from ground zero to uphold digital sovereignty across Africa. All database migrations default to Amazon Web Services `af-south-1` (Cape Town) or Azure South Africa North (Johannesburg), ensuring data residency requirements established by the Information Regulator of South Africa are mathematically preserved.

---

## 🤝 Contributing & Community

We welcome contributions from sovereign engineers, security researchers, and legal technologists across the globe.

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/sanitizer-pack`).
3. Commit your changes (`git commit -am 'Add SARS compliant tax invariant guard'`).
4. Run all workspace tests: `cargo test --workspace` and `cargo clippy --all-targets`.
5. Push to your branch and submit a Pull Request.

---

## 📄 Licence

Dual-licensed under either:
* Apache License, Version 2.0 ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0))
* MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT))

at your option.

---

<div align="center">
  <sub>Crafted with sovereign pride by <b>Azanian Eagle</b> 🇿🇦 • Johannesbug & Cape Town</sub>
</div>
