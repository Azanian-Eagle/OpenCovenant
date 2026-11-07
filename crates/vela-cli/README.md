# velac: The Vela Language Reference Compiler

[![Crates.io](https://img.shields.io/crates/v/velac.svg)](https://crates.io/crates/velac)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE)
[![Build Status](https://img.shields.io/badge/status-active-success.svg)](#)

`velac` is the command-line interface and compiler for **Vela (`.vela`)**, the statically typed data-sovereignty and PII taint-tracking language developed by **Azanian Eagle**.

## 🇿🇦 Built for Sovereign Engineering

`velac` translates statutory requirements—including South Africa's **POPIA** (Protection of Personal Information Act), the EU's **GDPR**, California's **CCPA**, and the South African Reserve Bank's (**SARB**) NPS directives—into strict compile-time invariants.

## Installation

```bash
cargo install velac
```

## CLI Commands

### 1. `velac check <CONTRACT.vela>`
Parses, type-checks, and verifies data sovereignty and taint invariants without generating build artefacts.

```bash
velac check contracts/edtech_popia_guard.vela
```

### 2. `velac build <CONTRACT.vela> [--out-dir <DIR>]`
Compiles a verified contract into polyglot artefacts:
* TypeScript / React SDK bindings
* Python FastAPI / Pydantic v2 middleware
* PostgreSQL 16+ Row-Level Security (RLS) SQL DDL

```bash
velac build contracts/edtech_popia_guard.vela --out-dir ./dist
```

### 3. `velac audit <CONTRACT.vela>`
Performs complete statutory verification and generates a signed SHA-256 compliance attestation in JSON format suitable for regulatory auditors and compliance archives.

```bash
velac audit contracts/edtech_popia_guard.vela
```

## Licence

Licensed under either of:
* Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE))
* MIT license ([LICENSE-MIT](../../LICENSE))
