# OpenCovenant & The Vela Programming Language (`.vela`)

**An Azanian Eagle Project** • *Compile-Time Data Sovereignty, Information-Flow PII Taint Tracking, and Formally Verified Regulatory Guardrails (POPIA, GDPR, CCPA, SARB).*

---

## Overview

Modern software ecosystems repeatedly suffer from sensitive data leakage and compliance violations because general-purpose languages treat South African ID numbers, minor chat transcripts, and payment card PANs as ordinary strings. Statutory invariants (such as POPIA Sections 19, 26, and 35 or SARB National Payment System rules) are typically written as brittle runtime `if/else` checks that fail silently under edge cases.

**OpenCovenant** and the **Vela Programming Language (`.vela`)** turn regulatory compliance and data sovereignty into compile-time mathematical guarantees:

1. **Information-Flow Taint & Provenance Lifetimes:** Fields carry phantom provenance types (e.g. `tainted<ZA_IDNumber, POPIA::Section26_SpecialPersonal>` or `ephemeral<MinorTranscript, ttl = 0s, jurisdiction = "af-south-1">`). Emitting tainted or ephemeral data to untrusted sinks triggers compile-time statutory diagnostic errors.
2. **Deterministic Cryptographic Sanitization:** Tainted data can only become `sanitized<T>` by passing through certified transformations (`strip_inline_pii`, `blake3_salted`, `aes256_gcm_encrypt`, `double_entry_assert`).
3. **Multi-Target Code Generation:** A single `.vela` contract compiles directly into:
   - TypeScript & React client bindings (`@azanian-eagle/opencovenant-client`)
   - Python FastAPI & Pydantic v2 middleware (`azanian-eagle-opencovenant`)
   - PostgreSQL 16+ Sovereign Row-Level Security (RLS) DDL migrations

---

## Workspace Architecture

```
OpenCovenant/
├── crates/
│   ├── vela-lexer/      # Zero-copy DFA lexer built on logos (>1.2 GB/s)
│   ├── vela-parser/     # AST definitions and recursive-descent parser
│   ├── vela-typeck/     # Affine taint-flow and statutory rule type checker
│   ├── vela-codegen/    # Multi-target code emitter (TS, Python, Postgres RLS)
│   └── vela-cli/        # velac CLI tool (check, build, audit subcommands)
├── contracts/
│   ├── edtech_popia_guard.vela    # EduHelp AI POPIA Section 26 & 35 contract
│   ├── nps_core_settlement.vela   # NPS-Core SARB double-entry settlement covenant
│   └── broken_leak_demo.vela      # Intentional violation contract for testing
├── .github/workflows/
│   └── ci-verify.yml    # CI test, contract verification, and build workflows
└── Cargo.toml           # Root workspace configuration
```

---

## Quickstart

### 1. Build and Run Workspace Tests
```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

### 2. Verify Compliant Contracts
```bash
# Verify EduHelp AI Minor Data Protection Contract (POPIA)
cargo run --bin velac -- check contracts/edtech_popia_guard.vela

# Verify NPS-Core SARB Double-Entry Settlement Covenant
cargo run --bin velac -- check contracts/nps_core_settlement.vela
```

### 3. Test Compile-Time Diagnostics on Unsafe Code
```bash
# velac flags raw tainted PII leakage and ephemeral minor transcript retention
cargo run --bin velac -- check contracts/broken_leak_demo.vela
```

### 4. Compile to Target SDKs and SQL DDL
```bash
cargo run --bin velac -- build contracts/edtech_popia_guard.vela --out-dir ./gen
```

This generates:
- `./gen/opencovenant_client.ts` (TypeScript / React SDK)
- `./gen/opencovenant_guard.py` (Python FastAPI Guard)
- `./gen/sovereign_rls.sql` (PostgreSQL RLS DDL)

### 5. Generate SHA-256 Compliance Attestation
```bash
cargo run --bin velac -- audit contracts/edtech_popia_guard.vela
```

---

## Contract Example: EduHelp AI POPIA Guard

```vela
module azanian_eagle.eduhelp.sovereignty version "1.0.0";

import std::regulations::{POPIA, GDPR};
import std::pii::{ZA_IDNumber, EmailAddress, MinorTranscript};
import std::crypto::{blake3_salted, aes256_gcm_encrypt};
import std::redact::{strip_inline_pii, mask_keep_last4};
import std::sinks::{ClientLocalStore, SovereignPostgresZA, ExternalLLMProvider};

schema LearnerSessionPayload {
  learner_sa_id:     tainted<ZA_IDNumber, POPIA::Section26_SpecialPersonal>,
  guardian_email:    tainted<EmailAddress, POPIA::Section19_Personal>,
  age_years:         u8 where age_years >= 5 && age_years <= 99,
  curriculum_prompt: ephemeral<MinorTranscript, ttl = 0s, jurisdiction = "af-south-1">,
  session_nonce:     public<UUIDv7>
}

covenant SocraticTutorEgress(input: LearnerSessionPayload) -> (
  db_record:   SovereignPostgresZA,
  llm_request: ExternalLLMProvider,
  local_cache: ClientLocalStore
) {
  invariant MinorZeroServerRetention {
    when input.age_years < 18 => forbid_sink(input.curriculum_prompt, SovereignPostgresZA);
  }

  let clean_prompt: sanitized<String> = input.curriculum_prompt
    |> strip_inline_pii(patterns = [ZA_IDNumber, EmailAddress, PhoneZA]);

  let anon_learner_hash: sanitized<FixedBytes<32>> = input.learner_sa_id
    |> blake3_salted(secret_env = "VELA_SA_ID_PEPPER");

  let encrypted_email: sanitized<CipherText> = input.guardian_email
    |> aes256_gcm_encrypt(key_env = "PAYLOAD_SECRET_KEY", aad = input.session_nonce);

  emit db_record {
    learner_hash: anon_learner_hash,
    guardian_ct:  encrypted_email,
    session_id:   input.session_nonce
  };

  emit llm_request {
    prompt: clean_prompt
  };

  emit local_cache {
    transcript: input.curriculum_prompt
  };
}
```

---

## Authors & License
- **Author:** Romeo Mngqibisa <romeomngqibisa@gmail.com> (Azanian Eagle)
- **License:** MIT OR Apache-2.0
