const test = require("node:test");
const assert = require("node:assert");
const { stripInlinePii, blake3OrSha256Salted, verifyCovenantPayload } = require("../index");

test("stripInlinePii redacts South African ID numbers and emails", () => {
  const raw = "Learner RSA ID is 0401015800085 and email is parent@example.co.za";
  const cleaned = stripInlinePii(raw);

  assert.ok(!cleaned.includes("0401015800085"));
  assert.ok(!cleaned.includes("parent@example.co.za"));
  assert.ok(cleaned.includes("[REDACTED_RSA_ID]"));
  assert.ok(cleaned.includes("[REDACTED_EMAIL]"));
});

test("blake3OrSha256Salted computes deterministic salted hash", () => {
  const hash1 = blake3OrSha256Salted("0401015800085", "PEPPER_SECRET");
  const hash2 = blake3OrSha256Salted("0401015800085", "PEPPER_SECRET");
  const hash3 = blake3OrSha256Salted("0401015800085", "DIFFERENT_PEPPER");

  assert.strictEqual(hash1, hash2);
  assert.notStrictEqual(hash1, hash3);
  assert.strictEqual(hash1.length, 64);
});

test("verifyCovenantPayload passes compliant payload", () => {
  const result = verifyCovenantPayload("SocraticTutorEgress", {
    age_years: 15,
    curriculum_prompt: "Algebra revision",
    persisted_to_server: false,
  });

  assert.strictEqual(result.verifiedBy, "Azanian-Eagle/OpenCovenant");
  assert.strictEqual(result.status, "COMPLIANT_ZERO_TAINT_LEAKAGE");
});

test("verifyCovenantPayload throws on POPIA Sec 35 minor retention violation", () => {
  assert.throws(() => {
    verifyCovenantPayload("SocraticTutorEgress", {
      age_years: 14,
      curriculum_prompt: "Algebra revision",
      persisted_to_server: true,
    });
  }, /POPIA Section 35 Violation/);
});
