# vela-codegen: Multi-Target Code Generator for Vela

[![Crates.io](https://img.shields.io/crates/v/vela-codegen.svg)](https://crates.io/crates/vela-codegen)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE)

`vela-codegen` translates verified Vela ASTs into production-grade multi-target artefacts across the modern software engineering stack.

## Compilation Targets

1. **TypeScript / React SDK**: Type definitions and immutable runtime validators (`opencovenant_client.ts`).
2. **Python FastAPI / Pydantic**: Strongly typed frozen dataclasses and salted hashing middleware (`opencovenant_guard.py`).
3. **PostgreSQL 16+ DDL**: Sovereign tables with Row-Level Security (RLS) policies guaranteeing statutory data residency in South Africa (`af-south-1`).

## Usage

```rust
use vela_codegen::generate_all_targets;

let targets = generate_all_targets(&ast);
println!("TypeScript SDK:\n{}", targets.typescript_sdk);
println!("Python Guard:\n{}", targets.python_middleware);
println!("PostgreSQL RLS:\n{}", targets.postgres_rls_sql);
```

## Licence

Licensed under either of Apache License, Version 2.0 or MIT license.
