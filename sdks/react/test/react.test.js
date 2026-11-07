const test = require("node:test");
const assert = require("node:assert");
const { createCovenantGuard } = require("../index");

test("createCovenantGuard sanitizes prompts and submits successfully", async () => {
  const guard = createCovenantGuard({
    covenant: "SocraticTutorEgress",
    enforceMinorZeroRetention: true,
  });

  const res = await guard.sanitizeAndSubmit({
    age_years: 15,
    curriculum_prompt: "My RSA ID is 0401015800085. Help me with Grade 10 calculus.",
  });

  assert.strictEqual(res.success, true);
  assert.ok(!res.data.curriculum_prompt.includes("0401015800085"));
  assert.ok(res.data.curriculum_prompt.includes("[REDACTED_RSA_ID]"));
  assert.strictEqual(guard.getError(), null);
});

test("createCovenantGuard blocks minor server persistence", async () => {
  const guard = createCovenantGuard({
    covenant: "SocraticTutorEgress",
    enforceMinorZeroRetention: true,
  });

  await assert.rejects(async () => {
    await guard.sanitizeAndSubmit({
      age_years: 12,
      curriculum_prompt: "Minor chat",
      persisted_to_server: true,
    });
  }, /POPIA Section 35 Violation/);

  assert.ok(guard.getError() !== null);
});
