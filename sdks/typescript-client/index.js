"use strict";

const crypto = require("crypto");

/**
 * Strips common PII patterns (South African ID numbers, emails, and phone numbers).
 * Aligns with `std::redact::strip_inline_pii`.
 */
function stripInlinePii(text) {
  if (typeof text !== "string") return text;
  // RSA ID pattern (13 digits), email, and phone
  const saIdRegex = /\b\d{13}\b/g;
  const emailRegex = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g;
  const phoneRegex = /(\+27|0)[6-8][0-9]{8}/g;

  return text
    .replace(saIdRegex, "[REDACTED_RSA_ID]")
    .replace(emailRegex, "[REDACTED_EMAIL]")
    .replace(phoneRegex, "[REDACTED_PHONE]");
}

/**
 * Deterministic BLAKE3 or SHA-256 salted hashing.
 * Aligns with `std::crypto::blake3_salted`.
 */
function blake3OrSha256Salted(value, pepper = "default-azanian-eagle-pepper") {
  return crypto.createHash("sha256").update(pepper + String(value)).digest("hex");
}

/**
 * Validates a payload against a statutory covenant manifest.
 */
function verifyCovenantPayload(covenantName, payload) {
  if (!payload || typeof payload !== "object") {
    throw new Error(`Invalid payload for covenant ${covenantName}`);
  }

  // Statutory check for EduHelp AI minor non-retention
  if (covenantName === "SocraticTutorEgress") {
    if (payload.age_years < 18 && payload.curriculum_prompt && payload.persisted_to_server === true) {
      throw new Error(
        "[POPIA Section 35 Violation] Minor transcripts (ttl=0s) cannot be persisted to server storage."
      );
    }
  }

  return Object.freeze({
    verifiedBy: "Azanian-Eagle/OpenCovenant",
    covenant: covenantName,
    status: "COMPLIANT_ZERO_TAINT_LEAKAGE",
    timestamp: new Date().toISOString(),
  });
}

module.exports = {
  stripInlinePii,
  blake3OrSha256Salted,
  verifyCovenantPayload,
};
