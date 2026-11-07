# vela-lexer: High-Throughput DFA Lexer for Vela

[![Crates.io](https://img.shields.io/crates/v/vela-lexer.svg)](https://crates.io/crates/vela-lexer)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE)

`vela-lexer` provides a zero-copy, DFA-driven tokeniser for the **Vela Programming Language (`.vela`)**, powered by [Logos](https://github.com/maciejhirsz/logos).

## Performance Highlights

* Exceeds **1.2 GB/s** lexing throughput on modern x86_64 and aarch64 processors.
* Emits zero-allocation `SpannedToken` structures with byte offsets for colourful diagnostic reporting.
* First-class token support for affine provenance keywords: `tainted`, `ephemeral`, `sanitized`, and `public`.
* Native tokenisation of duration literals (e.g. `0s`, `15m`, `24h`) and statutory jurisdiction qualifiers.

## Usage

```rust
use vela_lexer::tokenize;

let source = "schema Learner { id: tainted<ZA_IDNumber, POPIA::Section26> }";
let tokens = tokenize(source).expect("Tokenisation failed");
for token in tokens {
    println!("{:?} at {:?}", token.token, token.span);
}
```

## Licence

Licensed under either of Apache License, Version 2.0 or MIT license.
