//! Affine Information-Flow Taint & Regulatory Compliance Type-Checker for Vela.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vela_lexer::Span;
use vela_parser::{ModuleAst, ProvenanceKind, ProvenanceType};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub code: String,
    pub statutory_clause: String,
    pub message: String,
    pub remediation_hint: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub module_name: String,
    pub version: String,
    pub schemas_verified: usize,
    pub covenants_verified: usize,
    pub invariants_proven: usize,
    pub sanitized_bindings: usize,
}

const APPROVED_SANITIZERS: &[&str] = &[
    "strip_inline_pii",
    "blake3_salted",
    "aes256_gcm_encrypt",
    "mask_keep_last4",
    "token_vault_swap",
    "double_entry_assert",
];

pub fn verify_module(ast: &ModuleAst) -> Result<VerificationReport, Vec<ComplianceViolation>> {
    let mut violations = Vec::new();
    let mut schemas_map = HashMap::new();

    for schema in &ast.schemas {
        let mut field_map = HashMap::new();
        for f in &schema.fields {
            field_map.insert(f.name.clone(), f.ty.clone());
        }
        schemas_map.insert(schema.name.clone(), field_map);
    }

    let mut total_invariants = 0;
    let mut total_bindings = 0;

    for cov in &ast.covenants {
        total_invariants += cov.invariants.len();
        total_bindings += cov.bindings.len();

        let schema_fields = match schemas_map.get(&cov.input_schema) {
            Some(m) => m,
            None => {
                violations.push(ComplianceViolation {
                    code: "VELA-E001".to_string(),
                    statutory_clause: "Schema Integrity".to_string(),
                    message: format!("Unknown input schema '{}'", cov.input_schema),
                    remediation_hint: "Declare the schema before referencing it in a covenant."
                        .to_string(),
                    span: cov.span.clone(),
                });
                continue;
            }
        };

        let mut sink_types: HashMap<String, String> = HashMap::new();
        for (s_var, s_ty) in &cov.sinks {
            sink_types.insert(s_var.clone(), s_ty.clone());
        }

        let mut local_vars: HashMap<String, ProvenanceType> = HashMap::new();

        for binding in &cov.bindings {
            let src_ty = match schema_fields.get(&binding.source_field) {
                Some(ty) => ty,
                None => {
                    violations.push(ComplianceViolation {
                        code: "VELA-E002".to_string(),
                        statutory_clause: "Field Resolution".to_string(),
                        message: format!(
                            "Field '{}.{}' does not exist in schema '{}'",
                            cov.input_param, binding.source_field, cov.input_schema
                        ),
                        remediation_hint: "Check field spelling against the schema declaration."
                            .to_string(),
                        span: binding.span.clone(),
                    });
                    continue;
                }
            };

            let has_approved_sanitizer = binding
                .pipe_transforms
                .iter()
                .any(|p| APPROVED_SANITIZERS.contains(&p.as_str()));

            if (src_ty.kind == ProvenanceKind::Tainted || src_ty.kind == ProvenanceKind::Ephemeral)
                && binding.declared_type.kind == ProvenanceKind::Sanitized
                && !has_approved_sanitizer
            {
                let clause = src_ty
                    .regulation_tag
                    .clone()
                    .unwrap_or_else(|| "POPIA::Section19".to_string());
                violations.push(ComplianceViolation {
                    code: "POPIA-E019".to_string(),
                    statutory_clause: clause,
                    message: format!(
                        "Cannot coerce tainted field '{}.{}' into sanitized variable '{}' without an approved cryptographic or redaction pipe transform.",
                        cov.input_param, binding.source_field, binding.var_name
                    ),
                    remediation_hint: "Pipe the field through `|> blake3_salted(...)`, `|> aes256_gcm_encrypt(...)`, or `|> strip_inline_pii(...)`.".to_string(),
                    span: binding.span.clone(),
                });
            }

            local_vars.insert(binding.var_name.clone(), binding.declared_type.clone());
        }

        for emit in &cov.emissions {
            let sink_type = sink_types
                .get(&emit.sink_var)
                .cloned()
                .unwrap_or_else(|| "UnknownSink".to_string());

            for (col_name, expr) in &emit.assignments {
                let prefix = format!("{}.", cov.input_param);
                if let Some(raw_field) = expr.strip_prefix(&prefix) {
                    if let Some(f_ty) = schema_fields.get(raw_field) {
                        for inv in &cov.invariants {
                            if inv.forbidden_field == raw_field
                                && inv.forbidden_sink_type == sink_type
                            {
                                violations.push(ComplianceViolation {
                                    code: "POPIA-E035".to_string(),
                                    statutory_clause: format!("Invariant '{}' (POPIA Sec. 35 Minor Protection)", inv.name),
                                    message: format!(
                                        "Direct emission of '{}.{}' into sink '{}' ({}) violates invariant '{}' (when {}).",
                                        cov.input_param, raw_field, emit.sink_var, sink_type, inv.name, inv.condition_summary
                                    ),
                                    remediation_hint: format!(
                                        "Remove '{}: {}' from `emit {}` or route exclusively to `ClientLocalStore`.",
                                        col_name, expr, emit.sink_var
                                    ),
                                    span: emit.span.clone(),
                                });
                            }
                        }

                        if f_ty.kind == ProvenanceKind::Ephemeral
                            && f_ty.ttl_seconds == Some(0)
                            && sink_type != "ClientLocalStore"
                        {
                            violations.push(ComplianceViolation {
                                code: "POPIA-E035-TTL".to_string(),
                                statutory_clause: "POPIA Section 14 & 35 (Zero-Server-Retention Ephemeral Data)".to_string(),
                                message: format!(
                                    "Ephemeral field '{}.{}' has `ttl = 0s` and cannot be persisted or transmitted to server sink '{}' ({}).",
                                    cov.input_param, raw_field, emit.sink_var, sink_type
                                ),
                                remediation_hint: "Sanitize the field via `|> strip_inline_pii()` before LLM egress, or emit raw ephemeral transcripts only to `ClientLocalStore`.".to_string(),
                                span: emit.span.clone(),
                            });
                        }

                        if f_ty.kind == ProvenanceKind::Tainted {
                            let clause = f_ty
                                .regulation_tag
                                .clone()
                                .unwrap_or_else(|| "POPIA::Section26_SpecialPersonal".to_string());
                            violations.push(ComplianceViolation {
                                code: "POPIA-E026".to_string(),
                                statutory_clause: clause,
                                message: format!(
                                    "Unredacted tainted PII field '{}.{}' (type `{}`) leaked directly into sink '{}' column '{}'.",
                                    cov.input_param, raw_field, f_ty.base_type, emit.sink_var, col_name
                                ),
                                remediation_hint: format!(
                                    "Bind `{}.{}` through `|> blake3_salted(...)` or `|> aes256_gcm_encrypt(...)` before emitting.",
                                    cov.input_param, raw_field
                                ),
                                span: emit.span.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        Ok(VerificationReport {
            module_name: ast.name.clone(),
            version: ast.version.clone(),
            schemas_verified: ast.schemas.len(),
            covenants_verified: ast.covenants.len(),
            invariants_proven: total_invariants,
            sanitized_bindings: total_bindings,
        })
    } else {
        Err(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typeck_compliant_covenant() {
        let src = r#"
module azanian_eagle.clean version "1.0.0";

schema CleanInput {
  id: tainted<ZA_IDNumber, POPIA::Section26_SpecialPersonal>
}

covenant CleanCov(input: CleanInput) -> (db: PostgresSink) {
  let clean_id: sanitized<FixedBytes<32>> = input.id |> blake3_salted(secret_env = "PEPPER");

  emit db {
    hashed: clean_id
  };
}
"#;
        let tokens = vela_lexer::tokenize(src).expect("Lexing failed");
        let mut parser = vela_parser::Parser::new(tokens);
        let ast = parser.parse_module().expect("Parsing failed");
        let report = verify_module(&ast).expect("Typecheck failed");
        assert_eq!(report.schemas_verified, 1);
        assert_eq!(report.covenants_verified, 1);
        assert_eq!(report.sanitized_bindings, 1);
    }

    #[test]
    fn test_typeck_detects_leak_violation() {
        let src = r#"
module azanian_eagle.leak version "1.0.0";

schema LeakInput {
  id: tainted<ZA_IDNumber, POPIA::Section26_SpecialPersonal>
}

covenant LeakCov(input: LeakInput) -> (db: PostgresSink) {
  emit db {
    raw: input.id
  };
}
"#;
        let tokens = vela_lexer::tokenize(src).expect("Lexing failed");
        let mut parser = vela_parser::Parser::new(tokens);
        let ast = parser.parse_module().expect("Parsing failed");
        let errs = verify_module(&ast).expect_err("Should have failed");
        assert!(errs.iter().any(|e| e.code == "POPIA-E026"));
    }
}
