# vela-typeck: Affine Taint Tracking & Statutory Type-Checker

[![Crates.io](https://img.shields.io/crates/v/vela-typeck.svg)](https://crates.io/crates/vela-typeck)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE)

`vela-typeck` is the static analysis engine of the Vela compiler (`velac`). It verifies that data flow through covenants strictly satisfies affine provenance rules and statutory privacy constraints.

## Statutory Rules Enforced

* **POPIA Section 19**: Requires approved cryptographic pipelines (`|> blake3_salted`, `|> aes256_gcm_encrypt`) before coercing tainted values into sanitized variables.
* **POPIA Section 26**: Forbids direct emission of tainted RSA ID numbers or special personal information into persistent storage sinks without cryptographic sanitisation.
* **POPIA Section 35 & Section 14**: Disallows storing or transmitting ephemeral zero-retention minor records (`ttl = 0s`) to persistent servers or third-party LLM providers.
* **Invariant Validation**: Enforces user-defined covenant invariants (e.g. `when age_years < 18 => forbid_sink(...)`).

## Usage

```rust
use vela_lexer::tokenize;
use vela_parser::Parser;
use vela_typeck::verify_module;

let tokens = tokenize(source).unwrap();
let mut parser = Parser::new(tokens);
let ast = parser.parse_module().unwrap();

match verify_module(&ast) {
    Ok(report) => println!("Compliant: {} covenants proven", report.covenants_verified),
    Err(violations) => {
        for v in violations {
            eprintln!("[{}] {}", v.code, v.message);
        }
    }
}
```

## Licence

Licensed under either of Apache License, Version 2.0 or MIT license.
