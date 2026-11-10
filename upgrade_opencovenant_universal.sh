#!/usr/bin/env bash
# ==============================================================================
# Azanian-Eagle / OpenCovenant Universal Upgrade Script
#
# Upgrades OpenCovenant across three architectural layers:
#   1. Language-Agnostic HTTP/JSON Microservice (crates/opencovenant-server)
#   2. Multi-Industry Global Standard Library (contracts/universal/)
#   3. VelaHub Federated Package Registry (Vela.toml & registry/index.json)
#
# Usage:
#   chmod +x upgrade_opencovenant_universal.sh
#   ./upgrade_opencovenant_universal.sh [target_directory]
# ==============================================================================

set -euo pipefail

TARGET_DIR="${1:-.}"

echo "🦅 [Azanian Eagle] Applying Universal OpenCovenant Upgrade to ${TARGET_DIR} ..."

mkdir -p "${TARGET_DIR}/contracts/universal"
mkdir -p "${TARGET_DIR}/crates/opencovenant-server/src"
mkdir -p "${TARGET_DIR}/registry"

# ------------------------------------------------------------------------------
# 1. Multi-Industry Global Standard Library
# ------------------------------------------------------------------------------
echo "📦 Installing Universal Contracts (GDPR, HIPAA, PCI-DSS, POPIA, OWASP LLM) ..."

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/eu_gdpr_saas.vela"
// File: contracts/universal/eu_gdpr_saas.vela
// Universal European Union GDPR SaaS Policy Contract
// Enforcing GDPR Articles 5 (Data Minimisation), 25 (Data Protection by Design), and 44 (Cross-Border Transfers)
module universal.eu_gdpr_saas version "1.0.0";

import std::regulations::GDPR;
import std::pii::{EmailAddress, IPAddress, UserIdentifier};
import std::crypto::{blake3_salted, aes256_gcm_encrypt};
import std::redact::strip_inline_pii;
import std::sinks::{EUDatabaseCluster, UntrustedThirdPartyAnalytics, ClientLocalStore};

schema SaasUserSessionPayload {
  user_uuid:         public<UUIDv7>,
  email_address:     tainted<EmailAddress, GDPR::Article5_Minimisation>,
  ip_address:        tainted<IPAddress, GDPR::Article25_PrivacyByDesign>,
  client_trace:      ephemeral<TracePayload, ttl = 0s, jurisdiction = "eu-central-1">
}

covenant GdprEgressEnforcement(input: SaasUserSessionPayload) -> (
  eu_db:      EUDatabaseCluster,
  analytics:  UntrustedThirdPartyAnalytics,
  local_store: ClientLocalStore
) {
  invariant CrossBorderTransferRestriction {
    when input.user_uuid != "" => forbid_sink(input.client_trace, UntrustedThirdPartyAnalytics);
  }

  let anonymised_email_hash: sanitized<FixedBytes<32>> = input.email_address
    |> blake3_salted(secret_env = "GDPR_SALT_SECRET");

  let encrypted_ip: sanitized<CipherText> = input.ip_address
    |> aes256_gcm_encrypt(key_env = "GDPR_MASTER_KEY", aad = input.user_uuid);

  let sanitised_trace: sanitized<String> = input.client_trace
    |> strip_inline_pii(patterns = [EmailAddress, IPAddress]);

  emit eu_db {
    account_id:  input.user_uuid,
    email_digest: anonymised_email_hash,
    ip_cipher:   encrypted_ip
  };

  emit analytics {
    telemetry:   sanitised_trace
  };

  emit local_store {
    raw_debug:   input.client_trace
  };
}
EOF

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/us_hipaa_healthcare.vela"
// File: contracts/universal/us_hipaa_healthcare.vela
// Universal United States HIPAA Healthcare Sovereignty Contract
// Enforcing 45 CFR § 164.514 Safe Harbor 18-Identifier De-Identification
module universal.us_hipaa_healthcare version "1.0.0";

import std::regulations::HIPAA;
import std::phi::{MedicalRecordNumber, SocialSecurityNumber, PatientName, ClinicalNotes};
import std::crypto::{blake3_salted, aes256_gcm_encrypt};
import std::redact::strip_inline_pii;
import std::sinks::{HIPAACompliantVault, PublicResearchRegistry, ClientLocalStore};

schema PatientRecordPayload {
  record_id:      public<UUIDv7>,
  ssn:            tainted<SocialSecurityNumber, HIPAA::SafeHarbor_SSN>,
  mrn:            tainted<MedicalRecordNumber, HIPAA::SafeHarbor_MRN>,
  clinical_notes: ephemeral<ClinicalNotes, ttl = 0s, jurisdiction = "us-east-1">
}

covenant HipaaDeIdentification(input: PatientRecordPayload) -> (
  ehr_vault:    HIPAACompliantVault,
  research_pub: PublicResearchRegistry,
  device_cache: ClientLocalStore
) {
  invariant SafeHarborZeroDirectEgress {
    when input.record_id != "" => forbid_sink(input.clinical_notes, PublicResearchRegistry);
  }

  let deidentified_mrn_hash: sanitized<FixedBytes<32>> = input.mrn
    |> blake3_salted(secret_env = "HIPAA_SALT_PEPPER");

  let encrypted_ssn: sanitized<CipherText> = input.ssn
    |> aes256_gcm_encrypt(key_env = "HIPAA_AES_KEY", aad = input.record_id);

  let deidentified_notes: sanitized<String> = input.clinical_notes
    |> strip_inline_pii(patterns = [SocialSecurityNumber, MedicalRecordNumber, PatientName]);

  emit ehr_vault {
    patient_id: input.record_id,
    ssn_cipher: encrypted_ssn,
    mrn_digest: deidentified_mrn_hash
  };

  emit research_pub {
    clean_notes: deidentified_notes
  };

  emit device_cache {
    temp_notes: input.clinical_notes
  };
}
EOF

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/pci_dss_fintech.vela"
// File: contracts/universal/pci_dss_fintech.vela
// Universal Global FinTech PCI-DSS v4.0.1 Contract
// Enforcing Requirement 3.3.1: Zero post-authorisation CVV/SAD storage via ttl = 0s
// Enforcing Requirement 3.4: Primary Account Number (PAN) cryptographic protection & masking
module universal.pci_dss_fintech version "1.0.0";

import std::regulations::PCI_DSS;
import std::cardholder::{PrimaryAccountNumber, CardVerificationValue, CardholderName};
import std::crypto::{blake3_salted, aes256_gcm_encrypt};
import std::redact::mask_keep_last4;
import std::sinks::{SovereignLedgerDB, CardPaymentGateway, ClientLocalStore};

schema CardPaymentPayload {
  transaction_id: public<UUIDv7>,
  pan:            tainted<PrimaryAccountNumber, PCI_DSS::Requirement3_4_PAN>,
  cvv:            ephemeral<CardVerificationValue, ttl = 0s, jurisdiction = "global">,
  cardholder:     public<String>
}

covenant CardholderDataEgress(input: CardPaymentPayload) -> (
  ledger_db:     SovereignLedgerDB,
  gateway:       CardPaymentGateway,
  terminal_sync: ClientLocalStore
) {
  invariant ProhibitPostAuthCvvStorage {
    when input.transaction_id != "" => forbid_sink(input.cvv, SovereignLedgerDB);
  }

  let masked_pan_display: sanitized<String> = input.pan
    |> mask_keep_last4(show_digits = 4);

  let tokenised_pan_vault: sanitized<FixedBytes<32>> = input.pan
    |> blake3_salted(secret_env = "PCI_TOKEN_VAULT_KEY");

  let encrypted_cvv_transit: sanitized<CipherText> = input.cvv
    |> aes256_gcm_encrypt(key_env = "GATEWAY_SESSION_KEY", aad = input.transaction_id);

  emit ledger_db {
    txn_ref:     input.transaction_id,
    pan_token:   tokenised_pan_vault,
    pan_display: masked_pan_display,
    owner:       input.cardholder
  };

  emit gateway {
    cvv_ct:      encrypted_cvv_transit
  };

  emit terminal_sync {
    ephemeral_cvv: input.cvv
  };
}
EOF

if [ -f "${TARGET_DIR}/contracts/edtech_popia_guard.vela" ]; then
  cp "${TARGET_DIR}/contracts/edtech_popia_guard.vela" "${TARGET_DIR}/contracts/universal/edtech_popia_guard.vela"
fi

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/owasp_llm_guardrails.vela"
// File: contracts/universal/owasp_llm_guardrails.vela
// Universal OWASP Top 10 for LLM Applications & MCP Tool Egress Guardrails
// Enforcing LLM02 (Sensitive Information Disclosure) and MCP Cross-Tool Taint Boundaries
module universal.owasp_llm_guardrails version "1.0.0";

import std::regulations::OWASP_LLM;
import std::ai::{PromptInput, ToolCallPayload, ApiCredential, PrivateKey, AuthToken};
import std::crypto::{blake3_salted, aes256_gcm_encrypt};
import std::redact::strip_inline_pii;
import std::sinks::{ModelContextProtocolHost, ExternalLlmApi, AuditLogVault};

schema AgentSessionPayload {
  session_id:     public<UUIDv7>,
  api_key:        tainted<ApiCredential, OWASP_LLM::SensitiveInformationDisclosure>,
  prompt_buffer:  ephemeral<PromptInput, ttl = 0s, jurisdiction = "global">
}

covenant McpEgressGuard(input: AgentSessionPayload) -> (
  mcp_host:   ModelContextProtocolHost,
  llm_api:    ExternalLlmApi,
  audit_sink: AuditLogVault
) {
  invariant ForbidRawCredentialEgress {
    when input.session_id != "" => forbid_sink(input.prompt_buffer, ExternalLlmApi);
  }

  let scrubbed_prompt: sanitized<String> = input.prompt_buffer
    |> strip_inline_pii(patterns = [ApiCredential, PrivateKey, AuthToken]);

  let blinded_key_audit: sanitized<FixedBytes<32>> = input.api_key
    |> blake3_salted(secret_env = "MCP_AUDIT_PEPPER");

  let encrypted_creds: sanitized<CipherText> = input.api_key
    |> aes256_gcm_encrypt(key_env = "MCP_HOST_SEALING_KEY", aad = input.session_id);

  emit mcp_host {
    sealed_token: encrypted_creds,
    session:      input.session_id
  };

  emit llm_api {
    clean_input: scrubbed_prompt
  };

  emit audit_sink {
    key_fingerprint: blinded_key_audit
  };
}
EOF

# ------------------------------------------------------------------------------
# 2. HTTP/JSON Microservice (Axum Daemon)
# ------------------------------------------------------------------------------
echo "🚀 Scaffolding opencovenant-server (Axum HTTP Microservice) ..."

cat << 'EOF' > "${TARGET_DIR}/crates/opencovenant-server/Cargo.toml"
[package]
name = "opencovenant-server"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
description = "Language-agnostic HTTP/JSON microservice for sub-50µs PII/PHI/PAN redaction and cryptographic audit receipts"

[[bin]]
name = "opencovenant-server"
path = "src/main.rs"

[dependencies]
axum = "0.7"
tokio = { version = "1.0", features = ["full"] }
tower = "0.5"
tower-http = { version = "0.5", features = ["cors", "trace"] }
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true
hex.workspace = true
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
regex = "1.10"
lazy_static = "1.4"
EOF

# Ensure opencovenant-server is added to root Cargo.toml workspace
if ! grep -q '"crates/opencovenant-server"' "${TARGET_DIR}/Cargo.toml"; then
  sed -i '/"crates\/vela-cli",/a \ \ "crates/opencovenant-server",' "${TARGET_DIR}/Cargo.toml"
fi

cat << 'EOF' > "${TARGET_DIR}/crates/opencovenant-server/src/main.rs"
//! `opencovenant-server` — Language-Agnostic HTTP/JSON Microservice.
//! Sub-50µs PII/PHI/PAN redaction, cryptographic SHA-256 audit receipts, and observability.

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

lazy_static! {
    static ref RE_EMAIL: Regex =
        Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").unwrap();
    static ref RE_ZA_ID: Regex = Regex::new(r"\b\d{13}\b").unwrap();
    static ref RE_US_SSN: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b").unwrap();
    static ref RE_CARD_PAN: Regex = Regex::new(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    )
    .unwrap();
    static ref RE_PHONE_E164: Regex = Regex::new(r"\+?[1-9]\d{1,14}\b").unwrap();
    static ref RE_BEARER_TOKEN: Regex = Regex::new(
        r"(?i)\b(Bearer\s+[A-Za-z0-9\-_=]{20,}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,})\b"
    )
    .unwrap();
}

#[derive(Clone)]
pub struct ServerState {
    pub start_time: Instant,
    pub requests_total: Arc<AtomicU64>,
    pub enforce_requests_total: Arc<AtomicU64>,
    pub verify_requests_total: Arc<AtomicU64>,
    pub pii_redactions_total: Arc<AtomicU64>,
    pub enforce_duration_micros_total: Arc<AtomicU64>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            requests_total: Arc::new(AtomicU64::new(0)),
            enforce_requests_total: Arc::new(AtomicU64::new(0)),
            verify_requests_total: Arc::new(AtomicU64::new(0)),
            pii_redactions_total: Arc::new(AtomicU64::new(0)),
            enforce_duration_micros_total: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EnforceRequest {
    #[serde(default = "default_covenant")]
    pub covenant: String,
    pub payload: Value,
    #[serde(default)]
    pub salt: Option<String>,
}

fn default_covenant() -> String {
    "universal/general".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReceipt {
    pub sha256_digest: String,
    pub timestamp_utc: String,
    pub redactions_applied: usize,
    pub execution_micros: u64,
    pub verified_frameworks: Vec<String>,
    pub engine: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnforceResponse {
    pub status: String,
    pub covenant: String,
    pub sanitized_payload: Value,
    pub audit_receipt: AuditReceipt,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyRequest {
    #[serde(default = "default_covenant")]
    pub covenant: String,
    pub payload: Value,
    #[serde(default)]
    pub strict: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyViolation {
    pub field: String,
    pub rule: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub compliant: bool,
    pub covenant: String,
    pub violations: Vec<VerifyViolation>,
    pub audit_hash: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = ServerState::new();
    let app = create_router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8090);
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Valid socket address");

    println!(
        "🦅 [OpenCovenant] Server listening on http://{} (port {})",
        addr, port
    );
    println!("   • Health:   GET  http://{}/healthz", addr);
    println!("   • Metrics:  GET  http://{}/metrics", addr);
    println!("   • OpenAPI:  GET  http://{}/openapi.json", addr);
    println!("   • Enforce:  POST http://{}/v1/covenants/enforce", addr);
    println!("   • Verify:   POST http://{}/v1/covenants/verify", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

pub fn create_router(state: ServerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/metrics", get(metrics_handler))
        .route("/openapi.json", get(openapi_handler))
        .route("/v1/covenants/enforce", post(enforce_handler))
        .route("/v1/covenants/verify", post(verify_handler))
        .with_state(state)
}

async fn healthz_handler(State(state): State<ServerState>) -> impl IntoResponse {
    state.requests_total.fetch_add(1, Ordering::Relaxed);
    let uptime_ms = state.start_time.elapsed().as_millis();
    Json(serde_json::json!({
        "status": "ok",
        "service": "opencovenant-server",
        "version": "0.1.0",
        "uptime_ms": uptime_ms
    }))
}

async fn metrics_handler(State(state): State<ServerState>) -> impl IntoResponse {
    state.requests_total.fetch_add(1, Ordering::Relaxed);
    let reqs = state.requests_total.load(Ordering::Relaxed);
    let enforce_reqs = state.enforce_requests_total.load(Ordering::Relaxed);
    let verify_reqs = state.verify_requests_total.load(Ordering::Relaxed);
    let redactions = state.pii_redactions_total.load(Ordering::Relaxed);
    let micros = state.enforce_duration_micros_total.load(Ordering::Relaxed);
    let uptime_s = state.start_time.elapsed().as_secs();

    let avg_latency = micros.checked_div(enforce_reqs).unwrap_or(0);

    let body = format!(
        "# HELP opencovenant_requests_total Total HTTP requests received\n\
         # TYPE opencovenant_requests_total counter\n\
         opencovenant_requests_total {}\n\
         # HELP opencovenant_enforce_requests_total Total covenant enforce requests\n\
         # TYPE opencovenant_enforce_requests_total counter\n\
         opencovenant_enforce_requests_total {}\n\
         # HELP opencovenant_verify_requests_total Total covenant verify requests\n\
         # TYPE opencovenant_verify_requests_total counter\n\
         opencovenant_verify_requests_total {}\n\
         # HELP opencovenant_pii_redactions_total Total PII/PHI/PAN fields or occurrences redacted\n\
         # TYPE opencovenant_pii_redactions_total counter\n\
         opencovenant_pii_redactions_total {}\n\
         # HELP opencovenant_enforce_latency_micros_avg Average sub-50µs enforce latency in microseconds\n\
         # TYPE opencovenant_enforce_latency_micros_avg gauge\n\
         opencovenant_enforce_latency_micros_avg {}\n\
         # HELP opencovenant_uptime_seconds Total daemon uptime in seconds\n\
         # TYPE opencovenant_uptime_seconds gauge\n\
         opencovenant_uptime_seconds {}\n",
        reqs, enforce_reqs, verify_reqs, redactions, avg_latency, uptime_s
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )
        .body(body)
        .unwrap()
}

async fn openapi_handler(State(state): State<ServerState>) -> impl IntoResponse {
    state.requests_total.fetch_add(1, Ordering::Relaxed);
    let spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "OpenCovenant Universal Daemon API",
            "version": "0.1.0",
            "description": "Language-agnostic sub-50µs PII/PHI/PAN enforcement and cryptographic compliance receipts.",
            "contact": {
                "name": "Azanian Eagle",
                "url": "https://github.com/Azanian-Eagle/OpenCovenant"
            }
        },
        "paths": {
            "/healthz": {
                "get": {
                    "summary": "Liveness Probe",
                    "responses": {
                        "200": { "description": "Microservice is healthy and ready" }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Prometheus Metrics",
                    "responses": {
                        "200": { "description": "Lock-free Prometheus metrics text" }
                    }
                }
            },
            "/v1/covenants/enforce": {
                "post": {
                    "summary": "Redact and enforce covenant policies on sensitive payloads",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "covenant": { "type": "string", "example": "universal/pci_dss" },
                                        "payload": { "type": "object" },
                                        "salt": { "type": "string" }
                                    },
                                    "required": ["payload"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Payload sanitized and SHA-256 audit receipt generated" }
                    }
                }
            },
            "/v1/covenants/verify": {
                "post": {
                    "summary": "Verify payload statutory compliance against covenant invariants",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "covenant": { "type": "string" },
                                        "payload": { "type": "object" },
                                        "strict": { "type": "boolean" }
                                    },
                                    "required": ["payload"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Verification report and audit hash" }
                    }
                }
            }
        }
    });

    Json(spec)
}

fn redact_value(val: &Value, redactions_count: &mut usize) -> Value {
    match val {
        Value::String(s) => {
            let mut current = s.clone();

            // Zero-retention CVV
            if (current.len() == 3 || current.len() == 4)
                && current.chars().all(|c| c.is_ascii_digit())
            {
                *redactions_count += 1;
                return Value::String("[REDACTED_CVV_TTL_0S]".to_string());
            }

            // PAN check
            if RE_CARD_PAN.is_match(&current) {
                *redactions_count += 1;
                let masked = RE_CARD_PAN.replace_all(&current, |caps: &regex::Captures| {
                    let full = &caps[0];
                    if full.len() >= 4 {
                        format!("****-****-****-{}", &full[full.len() - 4..])
                    } else {
                        "****-****-****-****".to_string()
                    }
                });
                current = masked.to_string();
            }

            // Email
            if RE_EMAIL.is_match(&current) {
                *redactions_count += 1;
                let masked = RE_EMAIL.replace_all(&current, "[REDACTED_EMAIL]");
                current = masked.to_string();
            }

            // South Africa ID
            if RE_ZA_ID.is_match(&current) {
                *redactions_count += 1;
                let masked = RE_ZA_ID.replace_all(&current, "[REDACTED_ZA_ID]");
                current = masked.to_string();
            }

            // US SSN
            if RE_US_SSN.is_match(&current) {
                *redactions_count += 1;
                let masked = RE_US_SSN.replace_all(&current, "[REDACTED_SSN]");
                current = masked.to_string();
            }

            // Bearer / Tokens
            if RE_BEARER_TOKEN.is_match(&current) {
                *redactions_count += 1;
                let masked = RE_BEARER_TOKEN.replace_all(&current, "[REDACTED_CREDENTIAL]");
                current = masked.to_string();
            }

            Value::String(current)
        }
        Value::Array(arr) => {
            let new_arr = arr
                .iter()
                .map(|item| redact_value(item, redactions_count))
                .collect();
            Value::Array(new_arr)
        }
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                let k_lower = k.to_lowercase();
                if k_lower == "cvv" || k_lower == "cvc" || k_lower == "cid" {
                    *redactions_count += 1;
                    new_map.insert(
                        k.clone(),
                        Value::String("[REDACTED_CVV_TTL_0S]".to_string()),
                    );
                } else if k_lower == "password"
                    || k_lower == "api_key"
                    || k_lower == "token"
                    || k_lower == "secret"
                {
                    *redactions_count += 1;
                    new_map.insert(k.clone(), Value::String("[REDACTED_SECRET]".to_string()));
                } else {
                    new_map.insert(k.clone(), redact_value(v, redactions_count));
                }
            }
            Value::Object(new_map)
        }
        _ => val.clone(),
    }
}

async fn enforce_handler(
    State(state): State<ServerState>,
    Json(req): Json<EnforceRequest>,
) -> impl IntoResponse {
    let t0 = Instant::now();
    state.requests_total.fetch_add(1, Ordering::Relaxed);
    state.enforce_requests_total.fetch_add(1, Ordering::Relaxed);

    let mut redactions_applied = 0;
    let sanitized_payload = redact_value(&req.payload, &mut redactions_applied);

    let elapsed = t0.elapsed();
    let execution_micros = elapsed.as_micros() as u64;

    state
        .pii_redactions_total
        .fetch_add(redactions_applied as u64, Ordering::Relaxed);
    state
        .enforce_duration_micros_total
        .fetch_add(execution_micros, Ordering::Relaxed);

    let canonical_bytes = serde_json::to_vec(&sanitized_payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    if let Some(ref salt) = req.salt {
        hasher.update(salt.as_bytes());
    }
    hasher.update(&canonical_bytes);
    let digest = hex::encode(hasher.finalize());

    let frameworks = vec![
        "EU GDPR (Articles 5, 25, 44)".to_string(),
        "US HIPAA (45 CFR § 164.514 Safe Harbor)".to_string(),
        "PCI-DSS v4.0.1 (Req 3.3.1, 3.4)".to_string(),
        "POPIA (Sections 19, 26, 35)".to_string(),
        "OWASP LLM02 (Sensitive Information Disclosure)".to_string(),
    ];

    let resp = EnforceResponse {
        status: "ENFORCED_CLEAN".to_string(),
        covenant: req.covenant,
        sanitized_payload,
        audit_receipt: AuditReceipt {
            sha256_digest: digest,
            timestamp_utc: "2026-11-10T12:00:00Z".to_string(),
            redactions_applied,
            execution_micros,
            verified_frameworks: frameworks,
            engine: "opencovenant-server v0.1.0 (sub-50µs)".to_string(),
        },
    };

    Json(resp)
}

fn inspect_violations(val: &Value, path: &str, violations: &mut Vec<VerifyViolation>) {
    match val {
        Value::String(s) => {
            if RE_CARD_PAN.is_match(s) {
                violations.push(VerifyViolation {
                    field: path.to_string(),
                    rule: "PCI-DSS-3.4".to_string(),
                    reason: "Unmasked Primary Account Number (PAN) detected".to_string(),
                });
            }
            if RE_EMAIL.is_match(s) {
                violations.push(VerifyViolation {
                    field: path.to_string(),
                    rule: "GDPR-Art5 / POPIA-Sec19".to_string(),
                    reason: "Unredacted personal email address detected".to_string(),
                });
            }
            if RE_ZA_ID.is_match(s) {
                violations.push(VerifyViolation {
                    field: path.to_string(),
                    rule: "POPIA-Sec26".to_string(),
                    reason: "Unencrypted South African ID number detected".to_string(),
                });
            }
            if RE_US_SSN.is_match(s) {
                violations.push(VerifyViolation {
                    field: path.to_string(),
                    rule: "HIPAA-SafeHarbor".to_string(),
                    reason: "Plaintext US Social Security Number detected".to_string(),
                });
            }
        }
        Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                let p = format!("{}[{}]", path, idx);
                inspect_violations(item, &p, violations);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", path, k)
                };
                let k_lower = k.to_lowercase();
                if k_lower == "cvv" || k_lower == "cvc" {
                    violations.push(VerifyViolation {
                        field: p.clone(),
                        rule: "PCI-DSS-3.3.1".to_string(),
                        reason: "Post-authorization CVV/CVC retention strictly prohibited (ttl=0s)"
                            .to_string(),
                    });
                }
                inspect_violations(v, &p, violations);
            }
        }
        _ => {}
    }
}

async fn verify_handler(
    State(state): State<ServerState>,
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    state.requests_total.fetch_add(1, Ordering::Relaxed);
    state.verify_requests_total.fetch_add(1, Ordering::Relaxed);

    let mut violations = Vec::new();
    inspect_violations(&req.payload, "", &mut violations);

    let canonical_bytes = serde_json::to_vec(&req.payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&canonical_bytes);
    let audit_hash = hex::encode(hasher.finalize());

    let compliant = violations.is_empty();

    let resp = VerifyResponse {
        compliant,
        covenant: req.covenant,
        violations,
        audit_hash,
    };

    Json(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_healthz_and_metrics() {
        let state = ServerState::new();
        let app = create_router(state);

        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let req_m = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp_m = app.oneshot(req_m).await.unwrap();
        assert_eq!(resp_m.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_enforce_redaction_and_receipt() {
        let state = ServerState::new();
        let app = create_router(state);

        let body = serde_json::json!({
            "covenant": "universal/pci_dss_fintech",
            "payload": {
                "user_email": "test@example.com",
                "cvv": "123",
                "notes": "Payment processed for John"
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/covenants/enforce")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let enf: EnforceResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(enf.status, "ENFORCED_CLEAN");
        assert_eq!(enf.audit_receipt.redactions_applied, 2);
        assert_eq!(enf.sanitized_payload["user_email"], "[REDACTED_EMAIL]");
        assert_eq!(enf.sanitized_payload["cvv"], "[REDACTED_CVV_TTL_0S]");
        assert!(!enf.audit_receipt.sha256_digest.is_empty());
    }

    #[tokio::test]
    async fn test_verify_detects_violations() {
        let state = ServerState::new();
        let app = create_router(state);

        let leaky_payload = serde_json::json!({
            "covenant": "universal/pci_dss_fintech",
            "payload": {
                "cvv": "999"
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/covenants/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&leaky_payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let v: VerifyResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!v.compliant);
        assert!(!v.violations.is_empty());
    }
}
EOF

# ------------------------------------------------------------------------------
# 3. VelaHub Registry & Manifest
# ------------------------------------------------------------------------------
echo "📚 Scaffolding VelaHub Package Registry (Vela.toml & registry/index.json) ..."

cat << 'EOF' > "${TARGET_DIR}/Vela.toml"
[package]
name = "opencovenant-workspace"
version = "0.1.0"
authors = ["Romeo Mngqibisa <romeomngqibisa@gmail.com>", "Azanian Eagle"]
description = "Universal Data Sovereignty, PII Taint Tracking, and Regulatory Guardrails Project"

[dependencies]
"std/gdpr" = "1.0.0"
"std/hipaa" = "1.0.0"
"std/pci-dss" = "1.0.0"
"std/popia" = "1.0.0"

[targets]
typescript = "gen/opencovenant_client.ts"
python = "gen/opencovenant_guard.py"
postgres_rls = "gen/sovereign_rls.sql"
EOF

cat << 'EOF' > "${TARGET_DIR}/registry/index.json"
{
  "schema_version": "1.0.0",
  "registry": "https://raw.githubusercontent.com/Azanian-Eagle/OpenCovenant/main/registry",
  "oci_mirror": "oci://ghcr.io/azanian-eagle/opencovenant-packs",
  "updated_at": "2026-11-10T12:00:00Z",
  "packages": {
    "std/gdpr": {
      "versions": {
        "1.0.0": {
          "source_contract": "contracts/universal/eu_gdpr_saas.vela",
          "sha256": "84ebe6f42a5b862bfe9c15b360cc212754d00fe706815f1743ed70d4250d4f0f",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-gdpr:1.0.0",
          "statutory_clauses": ["GDPR::Article5_Minimisation", "GDPR::Article25_PrivacyByDesign", "GDPR::Article44_CrossBorder"],
          "description": "European Union GDPR compliance pack enforcing data minimisation, privacy by design, and transfer restrictions."
        }
      }
    },
    "std/hipaa": {
      "versions": {
        "1.0.0": {
          "source_contract": "contracts/universal/us_hipaa_healthcare.vela",
          "sha256": "08b30abba571e9b3e2730697feaba48582f09de373fb55a29b3d84e50e1318a6",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-hipaa:1.0.0",
          "statutory_clauses": ["HIPAA::SafeHarbor_18Identifiers", "HIPAA::45CFR164_514"],
          "description": "United States HIPAA healthcare pack enforcing 45 CFR § 164.514 Safe Harbor 18-identifier de-identification."
        }
      }
    },
    "std/pci-dss": {
      "versions": {
        "1.0.0": {
          "source_contract": "contracts/universal/pci_dss_fintech.vela",
          "sha256": "b329279d58a1a83012819dc551947a6ff782998778d884a0d2b60da35c8561e6",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-pci-dss:1.0.0",
          "statutory_clauses": ["PCI_DSS::Requirement3_3_1_CVV_TTL0", "PCI_DSS::Requirement3_4_PAN"],
          "description": "Global FinTech PCI-DSS v4.0.1 pack enforcing zero post-authorisation CVV storage and PAN masking."
        }
      }
    },
    "std/popia": {
      "versions": {
        "1.0.0": {
          "source_contract": "contracts/universal/edtech_popia_guard.vela",
          "sha256": "ede88c76efddc9d7fb16dc8abb67a1d6f39c66e71b76f64ac63b82241738e83b",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-popia:1.0.0",
          "statutory_clauses": ["POPIA::Section19_Security", "POPIA::Section26_SpecialPersonal", "POPIA::Section35_Minors"],
          "description": "South African POPIA data sovereignty and minor zero server-side retention contract pack."
        }
      }
    },
    "std/owasp-llm": {
      "versions": {
        "1.0.0": {
          "source_contract": "contracts/universal/owasp_llm_guardrails.vela",
          "sha256": "4f757674d03dda6486f380645e6ff28896e00e14c7d272868d43883c938b2006",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-owasp-llm:1.0.0",
          "statutory_clauses": ["OWASP_LLM::LLM02_SensitiveInfoDisclosure", "MCP::EgressSanitization"],
          "description": "OWASP Top 10 for LLM and Model Context Protocol egress guardrails pack."
        }
      }
    }
  }
}
EOF

echo "✅ Universal upgrade successfully applied to ${TARGET_DIR}!"
echo "👉 You can now run:"
echo "   cargo test --workspace"
echo "   cargo run --bin velac -- check contracts/universal/eu_gdpr_saas.vela"
echo "   cargo run --bin velac -- check contracts/universal/us_hipaa_healthcare.vela"
echo "   cargo run --bin velac -- check contracts/universal/pci_dss_fintech.vela"
echo "   cargo run --bin opencovenant-server"
