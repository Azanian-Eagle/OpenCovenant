# vela-parser: Resilient AST Parser for Vela Contracts

[![Crates.io](https://img.shields.io/crates/v/vela-parser.svg)](https://crates.io/crates/vela-parser)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE)

`vela-parser` implements a recursive-descent parser that transforms Vela token streams into structured Abstract Syntax Trees (`ModuleAst`).

## Features

* **Complete AST Modelling**: Represents modules, schemas, provenance types, statutory covenants, invariant expressions, and pipeline transformations.
* **Precise Diagnostics**: Retains exact character byte spans across every node for statutory compiler diagnostics via Ariadne.
* **Serde Serialization**: AST nodes implement `Serialize` and `Deserialize` for seamless interop with language servers, IDE extensions, and audit visualisers.

## Usage

```rust
use vela_lexer::tokenize;
use vela_parser::Parser;

let code = r#"
module azanian_eagle.sample version "1.0.0";
schema User { id: public<UUIDv7> }
"#;

let tokens = tokenize(code).expect("Tokenisation failed");
let mut parser = Parser::new(tokens);
let ast = parser.parse_module().expect("Parsing failed");
println!("Parsed module: {} (v{})", ast.name, ast.version);
```

## Licence

Licensed under either of Apache License, Version 2.0 or MIT license.
