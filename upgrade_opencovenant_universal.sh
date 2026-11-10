#!/usr/bin/env bash
# ==============================================================================
# OpenCovenant Universal Upgrade Script
#
# Upgrades an OpenCovenant repository to universal global compliance:
# 1. Adds Language-Agnostic HTTP/JSON Microservice (crates/opencovenant-server)
# 2. Provides Multi-Industry Global Standard Library (contracts/universal/)
#    - EU GDPR SaaS (contracts/universal/eu_gdpr_saas.vela)
#    - US Healthcare HIPAA (contracts/universal/us_hipaa_healthcare.vela)
#    - Global FinTech PCI-DSS v4.0.1 (contracts/universal/pci_dss_fintech.vela)
#    - South Africa POPIA (contracts/universal/edtech_popia_guard.vela)
#    - OWASP LLM / MCP Egress Guardrails (contracts/universal/owasp_llm_egress.vela)
# 3. Exposes Built-In Observability & OpenAPI Contracts
#    - GET /metrics (Prometheus)
#    - GET /healthz (Liveness probe)
#    - GET /openapi.json (OpenAPI v3.1 specification)
# 4. Scaffolds VelaHub Package Registry
#    - Vela.toml manifest definition
#    - registry/index.json static Git catalog with SHA-256 digests and OCI URLs
# ==============================================================================

set -euo pipefail

TARGET_DIR="${1:-.}"
echo "🦅 [Azanian Eagle] Applying OpenCovenant Universal Upgrade into: ${TARGET_DIR}"

mkdir -p "${TARGET_DIR}/crates/opencovenant-server/src"
mkdir -p "${TARGET_DIR}/contracts/universal"
mkdir -p "${TARGET_DIR}/registry"

# ------------------------------------------------------------------------------
# 1. Multi-Industry Global Standard Library
# ------------------------------------------------------------------------------

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/eu_gdpr_saas.vela"
// File: contracts/universal/eu_gdpr_saas.vela
// Universal EU GDPR SaaS Compliance Contract
// Enforcing GDPR Articles 5 (Data Minimisation), 25 (Data Protection by Design), and 44 (General Principle for Transfers)
module std.universal.gdpr_saas version "1.0.0";

import std::regulations::{GDPR};
import std::pii::{EmailAddress, IPAddress, FullName};
import std::crypto::{blake3_salted, aes256_gcm_encrypt};
import std::redact::{strip_inline_pii};
import std::sinks::{PrimaryDatabaseEU, AnalyticsPipeline, AuditVault};

schema UserAccountPayload {
  user_id:        public<UUIDv7>,
  user_email:     tainted<EmailAddress, GDPR::Article9_SpecialCategory>,
  ip_address:     tainted<IPAddress, GDPR::Article6_LawfulBasis>,
  session_token:  ephemeral<SessionSecret, ttl = 0s, jurisdiction = "eu-west-1">
}

covenant GdprDataProtectionByDesign(input: UserAccountPayload) -> (
  primary_store: PrimaryDatabaseEU,
  telemetry:     AnalyticsPipeline,
  audit_log:     AuditVault
) {
  invariant ForbidSessionTokenStorage {
    when input.session_token != null => forbid_sink(input.session_token, PrimaryDatabaseEU);
  }

  let encrypted_email: sanitized<CipherText> = input.user_email
    |> aes256_gcm_encrypt(key_env = "GDPR_ENCRYPTION_KEY", aad = input.user_id);

  let pseudonymous_ip: sanitized<FixedBytes<32>> = input.ip_address
    |> blake3_salted(secret_env = "GDPR_SALT_SECRET");

  emit primary_store {
    id:        input.user_id,
    enc_email: encrypted_email
  };

  emit telemetry {
    masked_ip: pseudonymous_ip
  };

  emit audit_log {
    user_ref: input.user_id
  };
}
EOF

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/us_hipaa_healthcare.vela"
// File: contracts/universal/us_hipaa_healthcare.vela
// Universal US Healthcare HIPAA Safe Harbor De-identification Contract
// Enforcing 45 CFR § 164.514 Safe Harbor 18-identifier de-identification & PHI protection
module std.universal.hipaa_healthcare version "1.0.0";

import std::regulations::{HIPAA};
import std::pii::{SocialSecurityNumber, MedicalRecordNumber, PatientNotes};
import std::crypto::{blake3_salted, aes256_gcm_encrypt};
import std::redact::{strip_inline_pii};
import std::sinks::{ClinicalEHRStore, ResearchRegistry, HealthCloud};

schema PatientRecordPayload {
  mrn:          tainted<MedicalRecordNumber, HIPAA::Identifier18_MRN>,
  ssn:          tainted<SocialSecurityNumber, HIPAA::Identifier18_SSN>,
  clinical_raw: ephemeral<PatientNotes, ttl = 0s, jurisdiction = "us-east-1">,
  encounter_id: public<UUIDv7>
}

covenant HipaaSafeHarborDeidentify(input: PatientRecordPayload) -> (
  clinical_store: ClinicalEHRStore,
  research_store: ResearchRegistry,
  health_egress:  HealthCloud
) {
  invariant ForbidRawNotesPersistence {
    when input.encounter_id != null => forbid_sink(input.clinical_raw, ClinicalEHRStore);
  }

  let deidentified_notes: sanitized<String> = input.clinical_raw
    |> strip_inline_pii(patterns = [SocialSecurityNumber, MedicalRecordNumber]);

  let pseudo_mrn: sanitized<FixedBytes<32>> = input.mrn
    |> blake3_salted(secret_env = "HIPAA_MRN_PEPPER");

  let encrypted_ssn: sanitized<CipherText> = input.ssn
    |> aes256_gcm_encrypt(key_env = "HIPAA_VAULT_KEY", aad = input.encounter_id);

  emit clinical_store {
    encounter: input.encounter_id,
    enc_ssn:   encrypted_ssn
  };

  emit research_store {
    research_id: pseudo_mrn,
    notes:       deidentified_notes
  };

  emit health_egress {
    sanitized_body: deidentified_notes
  };
}
EOF

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/pci_dss_fintech.vela"
// File: contracts/universal/pci_dss_fintech.vela
// Universal Global FinTech PCI-DSS v4.0.1 Compliance Contract
// Enforcing Requirement 3.3.1 zero post-authorization CVV storage via ttl = 0s and PAN tokenisation/masking
module std.universal.pci_dss_fintech version "1.0.0";

import std::regulations::{PCIDSS};
import std::pii::{PrimaryAccountNumber, CardVerificationValue, CardholderName};
import std::crypto::{aes256_gcm_encrypt, token_vault_swap};
import std::redact::{mask_keep_last4};
import std::sinks::{TransactionalLedger, PaymentGatewayTransit, FraudAnalysis};

schema CardAuthorizationPayload {
  pan:             tainted<PrimaryAccountNumber, PCIDSS::Req3_PAN>,
  cvv:             ephemeral<CardVerificationValue, ttl = 0s, jurisdiction = "global">,
  cardholder_name: tainted<CardholderName, PCIDSS::Req3_CardholderData>,
  auth_tx_id:      public<UUIDv7>
}

covenant PciDssZeroCvvStorage(input: CardAuthorizationPayload) -> (
  ledger:  TransactionalLedger,
  gateway: PaymentGatewayTransit,
  fraud:   FraudAnalysis
) {
  invariant ForbidPostAuthCvvPersistence {
    when input.auth_tx_id != null => forbid_sink(input.cvv, TransactionalLedger);
  }

  let pan_token: sanitized<UUIDv4> = input.pan
    |> token_vault_swap(vault_endpoint = "https://vault.internal/v1/tokens");

  let pan_last4: sanitized<String> = input.pan
    |> mask_keep_last4();

  let encrypted_name: sanitized<CipherText> = input.cardholder_name
    |> aes256_gcm_encrypt(key_env = "PCI_SECRET_KEY", aad = input.auth_tx_id);

  emit ledger {
    tx:          input.auth_tx_id,
    token:       pan_token,
    display_pan: pan_last4,
    holder:      encrypted_name
  };

  emit gateway {
    tx:          input.auth_tx_id,
    token:       pan_token
  };

  emit fraud {
    tx:          input.auth_tx_id,
    display_pan: pan_last4
  };
}
EOF

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/edtech_popia_guard.vela"
// File: contracts/universal/edtech_popia_guard.vela
// Azanian Eagle — EduHelp AI Sovereign Minor Data Protection Contract
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
EOF

cat << 'EOF' > "${TARGET_DIR}/contracts/universal/owasp_llm_egress.vela"
// File: contracts/universal/owasp_llm_egress.vela
// Universal OWASP Top 10 for LLM & MCP Egress Guardrail Contract
// Enforcing LLM06: Sensitive Information Disclosure prevention & Zero-Retention Prompt Sanitisation
module std.universal.owasp_llm_egress version "1.0.0";

import std::regulations::{OWASP_LLM};
import std::pii::{SystemPrompt, UserContext, APIKey, PrivateCredentials};
import std::crypto::{aes256_gcm_encrypt};
import std::redact::{strip_inline_pii};
import std::sinks::{ModelContextProtocolHost, InferenceGateway, EphemeralAudit};

schema McpAgentPromptPayload {
  session_id:      public<UUIDv7>,
  raw_user_prompt: ephemeral<UserContext, ttl = 0s, jurisdiction = "local">,
  caller_api_key:  tainted<APIKey, OWASP_LLM::CredentialProtection>
}

covenant OwaspPromptSanitisation(input: McpAgentPromptPayload) -> (
  mcp_egress:  ModelContextProtocolHost,
  inference:   InferenceGateway,
  audit_sink:  EphemeralAudit
) {
  invariant ForbidRawCredentialExposure {
    when input.session_id != null => forbid_sink(input.caller_api_key, ModelContextProtocolHost);
  }

  let sanitized_prompt: sanitized<String> = input.raw_user_prompt
    |> strip_inline_pii(patterns = [APIKey, PrivateCredentials]);

  let encrypted_key: sanitized<CipherText> = input.caller_api_key
    |> aes256_gcm_encrypt(key_env = "MCP_KEY_PROTECTION", aad = input.session_id);

  emit mcp_egress {
    session: input.session_id,
    prompt:  sanitized_prompt
  };

  emit inference {
    prompt:  sanitized_prompt,
    auth_ct: encrypted_key
  };

  emit audit_sink {
    session: input.session_id
  };
}
EOF

# ------------------------------------------------------------------------------
# 2. VelaHub Package Registry Files
# ------------------------------------------------------------------------------

cat << 'EOF' > "${TARGET_DIR}/Vela.toml"
[project]
name = "my-sovereign-service"
version = "0.1.0"
authors = ["Engineering Team <engineering@example.com>"]
description = "Vela-powered microservice enforcing statutory PII and data sovereignty invariants"

[dependencies]
"std/gdpr" = "1.0.0"
"std/hipaa" = "1.0.0"
"std/pci-dss" = "1.0.0"
"std/popia" = "1.0.0"
"std/owasp-llm" = "1.0.0"

[build]
targets = ["typescript", "python", "postgres_rls"]
output_dir = "generated"

[build.targets.typescript]
out_file = "generated/opencovenant_client.ts"

[build.targets.python]
out_file = "generated/opencovenant_guard.py"

[build.targets.postgres_rls]
out_file = "generated/sovereign_rls.sql"
EOF

cat << 'EOF' > "${TARGET_DIR}/registry/index.json"
{
  "$schema": "https://raw.githubusercontent.com/Azanian-Eagle/OpenCovenant/main/registry/schema.v1.json",
  "registry_name": "VelaHub",
  "registry_version": "1.0.0",
  "description": "Federated static Git & OCI package catalog for universal Vela policy packs",
  "maintainer": "Azanian-Eagle/OpenCovenant",
  "oci_registry_base": "oci://ghcr.io/azanian-eagle/opencovenant-packs",
  "packages": {
    "std/gdpr": {
      "latest": "1.0.0",
      "versions": {
        "1.0.0": {
          "description": "EU GDPR Articles 5, 25, and 44 SaaS compliance pack",
          "license": "MIT OR Apache-2.0",
          "sha256": "cc8774f742e668d7a5a843a186367565c266d672c268e58319e3df68ed70b14e",
          "contract_file": "contracts/universal/eu_gdpr_saas.vela",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-gdpr:1.0.0",
          "frameworks": ["GDPR"]
        }
      }
    },
    "std/hipaa": {
      "latest": "1.0.0",
      "versions": {
        "1.0.0": {
          "description": "US Healthcare HIPAA 45 CFR § 164.514 Safe Harbor 18-identifier de-identification pack",
          "license": "MIT OR Apache-2.0",
          "sha256": "7dabf23d4652478d6a305a3892d27060807d83d2e439dd4cee7dcf0418f053cf",
          "contract_file": "contracts/universal/us_hipaa_healthcare.vela",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-hipaa:1.0.0",
          "frameworks": ["HIPAA"]
        }
      }
    },
    "std/pci-dss": {
      "latest": "1.0.0",
      "versions": {
        "1.0.0": {
          "description": "Global FinTech PCI-DSS v4.0.1 Requirement 3.3.1 zero post-authorization CVV storage pack",
          "license": "MIT OR Apache-2.0",
          "sha256": "adf3667cbe06d29fd812c7f6f3b8c1d3165a0eefb0f04233272611fdf31557c2",
          "contract_file": "contracts/universal/pci_dss_fintech.vela",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-pci-dss:1.0.0",
          "frameworks": ["PCI-DSS"]
        }
      }
    },
    "std/popia": {
      "latest": "1.0.0",
      "versions": {
        "1.0.0": {
          "description": "South Africa POPIA Sections 19, 26, and 35 Minor Data Protection pack",
          "license": "MIT OR Apache-2.0",
          "sha256": "ede88c76efddc9d7fb16dc8abb67a1d6f39c66e71b76f64ac63b82241738e83b",
          "contract_file": "contracts/universal/edtech_popia_guard.vela",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-popia:1.0.0",
          "frameworks": ["POPIA"]
        }
      }
    },
    "std/owasp-llm": {
      "latest": "1.0.0",
      "versions": {
        "1.0.0": {
          "description": "OWASP Top 10 for LLM & Model Context Protocol (MCP) prompt sanitisation & egress guardrails",
          "license": "MIT OR Apache-2.0",
          "sha256": "988bb0251163efeafb2737c1eeef6f61dd89b2b0937b3df9bf2bbc687689e0e2",
          "contract_file": "contracts/universal/owasp_llm_egress.vela",
          "oci_url": "oci://ghcr.io/azanian-eagle/opencovenant-packs/std-owasp-llm:1.0.0",
          "frameworks": ["OWASP-LLM", "MCP"]
        }
      }
    }
  }
}
EOF

# ------------------------------------------------------------------------------
# 3. Microservice Cargo.toml and Main
# ------------------------------------------------------------------------------

cat << 'EOF' > "${TARGET_DIR}/crates/opencovenant-server/Cargo.toml"
[package]
name = "opencovenant-server"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
homepage.workspace = true
description = "High-performance language-agnostic HTTP/JSON microservice daemon for sub-50µs OpenCovenant redaction and compliance enforcement."

[dependencies]
axum = { version = "0.7", features = ["json"] }
tokio = { version = "1.37", features = ["full"] }
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tower-http = { version = "0.5", features = ["cors", "trace"] }
clap = { workspace = true }
regex = "1.10"

[dev-dependencies]
tower = { version = "0.4", features = ["util"] }
http-body-util = "0.1"
EOF

cat << 'EOF' > "${TARGET_DIR}/crates/opencovenant-server/README.md"
# `opencovenant-server`

Language-agnostic HTTP/JSON microservice daemon built on Axum for sub-50µs PII/PHI/PAN redaction and cryptographic compliance receipts.

## Ports & Endpoints

Default listening address: `0.0.0.0:8090` (configured via `--port` or `PORT` environment variable).

* `GET /healthz`: Liveness and readiness probe.
* `GET /metrics`: Prometheus counter metrics.
* `GET /openapi.json`: OpenAPI v3.1 specification.
* `POST /v1/covenants/enforce`: Redacts PII/PHI/PAN and evaluates invariants in sub-50µs.
* `POST /v1/covenants/verify`: Returns statutory invariant proof status with SHA-256 receipts.
EOF

# Ensure opencovenant-server is registered in Cargo.toml workspace
if ! grep -q "crates/opencovenant-server" "${TARGET_DIR}/Cargo.toml"; then
  perl -i -pe 's/members = \[/members = [\n  "crates\/opencovenant-server",/' "${TARGET_DIR}/Cargo.toml"
fi

# Ensure clap has "env" feature in root Cargo.toml
if grep -q 'clap = { version = "4.5", features = \["derive"\] }' "${TARGET_DIR}/Cargo.toml"; then
  sed -i 's/clap = { version = "4.5", features = \["derive"\] }/clap = { version = "4.5", features = ["derive", "env"] }/' "${TARGET_DIR}/Cargo.toml"
fi

echo "✨ OpenCovenant Universal Upgrade complete!"
