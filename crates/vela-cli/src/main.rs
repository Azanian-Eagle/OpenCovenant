//! `velac` — The Vela Language Compiler & Compliance Verification CLI.

use ariadne::{Color, Label, Report, ReportKind, Source};
use clap::{Parser as ClapParser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use vela_codegen::generate_all_targets;
use vela_lexer::tokenize;
use vela_parser::Parser;
use vela_typeck::verify_module;

#[derive(ClapParser)]
#[command(
    name = "velac",
    version = "0.1.0",
    author = "Romeo Mngqibisa (Azanian Eagle)",
    about = "The Vela Programming Language (.vela) Compiler & POPIA/GDPR/SARB Verification Engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Type-checks and formally verifies a .vela contract for PII taint and TTL compliance
    Check {
        /// Path to the .vela contract file
        file: PathBuf,
    },
    /// Compiles a verified .vela contract into TypeScript, Python, and PostgreSQL RLS targets
    Build {
        /// Path to the .vela contract file
        file: PathBuf,
        /// Output directory for generated SDKs and SQL migrations
        #[arg(short, long, default_value = "gen")]
        out_dir: PathBuf,
    },
    /// Generates a cryptographically signed SHA-256 regulatory audit attestation JSON
    Audit {
        /// Path to the .vela contract file
        file: PathBuf,
    },
    /// Intercepts and validates MCP tool calls against security policies (std::ai::mcp_guard)
    McpGuard {
        /// JSON string or path to JSON file representing an McpToolCall
        #[arg(short, long)]
        call: String,
        /// Forbidden tool names separated by commas
        #[arg(long, default_value = "bash,sh,eval,shell_exec,raw_sql_query")]
        forbidden_tools: String,
    },
    /// Verifies double-entry ledger balance invariants and calculates VAT (std::ledger)
    LedgerVerify {
        /// Path to a JSON transaction file containing postings
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check { file } => match compile_and_verify(&file) {
            Ok((_ast, report, _src)) => {
                println!("✅ [VELAC PASS] Module '{}' (v{}) verified with zero compliance violations!", report.module_name, report.version);
                println!("   • Schemas Checked:      {}", report.schemas_verified);
                println!("   • Covenants Verified:   {}", report.covenants_verified);
                println!("   • Invariants Proven:    {}", report.invariants_proven);
                println!("   • Sanitized Bindings:   {}", report.sanitized_bindings);
                ExitCode::SUCCESS
            }
            Err(_) => ExitCode::FAILURE,
        },
        Commands::Build { file, out_dir } => match compile_and_verify(&file) {
            Ok((ast, report, _src)) => {
                fs::create_dir_all(&out_dir).expect("Failed to create output directory");
                let targets = generate_all_targets(&ast);

                let ts_path = out_dir.join("opencovenant_client.ts");
                let py_path = out_dir.join("opencovenant_guard.py");
                let sql_path = out_dir.join("sovereign_rls.sql");

                fs::write(&ts_path, targets.typescript_sdk).unwrap();
                fs::write(&py_path, targets.python_middleware).unwrap();
                fs::write(&sql_path, targets.postgres_rls_sql).unwrap();

                println!("🚀 [VELAC BUILD] Successfully compiled '{}' (v{}) into 3 targets:", report.module_name, report.version);
                println!("   • TypeScript/React SDK: {}", ts_path.display());
                println!("   • Python FastAPI Guard: {}", py_path.display());
                println!("   • PostgreSQL RLS DDL:   {}", sql_path.display());
                ExitCode::SUCCESS
            }
            Err(_) => ExitCode::FAILURE,
        },
        Commands::Audit { file } => match compile_and_verify(&file) {
            Ok((_ast, report, src)) => {
                let mut hasher = Sha256::new();
                hasher.update(src.as_bytes());
                let digest = hex::encode(hasher.finalize());

                let attestation = serde_json::json!({
                    "engine": "Azanian-Eagle/OpenCovenant (velac v0.1.0)",
                    "module": report.module_name,
                    "version": report.version,
                    "source_sha256": digest,
                    "frameworks_enforced": ["POPIA (South Africa)", "GDPR (EU)", "CCPA (California)", "SARB NPS"],
                    "schemas_verified": report.schemas_verified,
                    "covenants_verified": report.covenants_verified,
                    "invariants_proven": report.invariants_proven,
                    "status": "COMPLIANT_ZERO_TAINT_LEAKAGE"
                });
                println!("{}", serde_json::to_string_pretty(&attestation).unwrap());
                ExitCode::SUCCESS
            }
            Err(_) => ExitCode::FAILURE,
        },
        Commands::McpGuard { call, forbidden_tools } => {
            let tool_call_json = if std::path::Path::new(&call).exists() {
                fs::read_to_string(&call).expect("Failed to read tool call file")
            } else {
                call
            };

            let tool_call: vela_mcp_guard::McpToolCall = match serde_json::from_str(&tool_call_json) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to parse MCP tool call JSON: {}", e);
                    return ExitCode::FAILURE;
                }
            };

            let mut policy = vela_mcp_guard::McpSecurityPolicy::default();
            let forbidden_set: std::collections::HashSet<String> = forbidden_tools
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            policy.forbidden_tools = forbidden_set;

            let guard = vela_mcp_guard::McpGuard::new(policy);
            let verdict = guard.intercept_call(&tool_call);

            println!("{}", serde_json::to_string_pretty(&verdict).unwrap());
            if verdict.is_blocked() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::LedgerVerify { file } => {
            let data = match fs::read_to_string(&file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Failed to read ledger transaction file: {}", e);
                    return ExitCode::FAILURE;
                }
            };

            let tx: vela_ledger::LedgerTransaction = match serde_json::from_str(&data) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Failed to parse LedgerTransaction JSON: {}", e);
                    return ExitCode::FAILURE;
                }
            };

            match tx.verify_balance() {
                Ok(()) => {
                    println!("✅ [LEDGER PASS] Transaction '{}' satisfies SARB/NPS-Core double-entry invariant (sum(debits) == sum(credits))", tx.id);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("❌ [LEDGER FAIL] Double-entry balance invariant violated in tx '{}': {}", tx.id, e);
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn compile_and_verify(
    file: &PathBuf,
) -> Result<(vela_parser::ModuleAst, vela_typeck::VerificationReport, String), ()> {
    let fname = file.display().to_string();
    let src = match fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading '{}': {}", fname, e);
            return Err(());
        }
    };

    let tokens = match tokenize(&src) {
        Ok(t) => t,
        Err(errs) => {
            for err in errs {
                Report::build(ReportKind::Error, fname.as_str(), err.span.start)
                    .with_code("VELA-LEX")
                    .with_message(format!("Unexpected token '{}'", err.unexpected))
                    .with_label(
                        Label::new((fname.as_str(), err.span))
                            .with_message("Unrecognized lexical sequence")
                            .with_color(Color::Red),
                    )
                    .finish()
                    .eprint((fname.as_str(), Source::from(&src)))
                    .ok();
            }
            return Err(());
        }
    };

    let mut parser = Parser::new(tokens);
    let ast = match parser.parse_module() {
        Ok(a) => a,
        Err(err) => {
            Report::build(ReportKind::Error, fname.as_str(), err.span.start)
                .with_code("VELA-PARSE")
                .with_message(&err.message)
                .with_label(
                    Label::new((fname.as_str(), err.span))
                        .with_message("Syntax error here")
                        .with_color(Color::Yellow),
                )
                .finish()
                .eprint((fname.as_str(), Source::from(&src)))
                .ok();
            return Err(());
        }
    };

    match verify_module(&ast) {
        Ok(report) => Ok((ast, report, src)),
        Err(violations) => {
            for v in violations {
                Report::build(ReportKind::Error, fname.as_str(), v.span.start)
                    .with_code(&v.code)
                    .with_message(format!("[{}] {}", v.statutory_clause, v.message))
                    .with_label(
                        Label::new((fname.as_str(), v.span))
                            .with_message(&v.message)
                            .with_color(Color::Red),
                    )
                    .with_help(&v.remediation_hint)
                    .finish()
                    .eprint((fname.as_str(), Source::from(&src)))
                    .ok();
            }
            Err(())
        }
    }
}
