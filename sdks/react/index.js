"use strict";

const { stripInlinePii, verifyCovenantPayload } = require("../typescript-client/index");

/**
 * React hook simulation for sovereign covenant enforcement.
 */
function createCovenantGuard({ covenant, enforceMinorZeroRetention = true }) {
  let isCompliant = true;
  let lastError = null;

  async function sanitizeAndSubmit(payload) {
    try {
      if (enforceMinorZeroRetention && payload.age_years < 18) {
        if (payload.persisted_to_server === true) {
          throw new Error(
            `[POPIA Section 35 Violation] Cannot persist minor transcript in covenant '${covenant}'.`
          );
        }
      }

      const sanitizedPayload = {
        ...payload,
        curriculum_prompt: payload.curriculum_prompt
          ? stripInlinePii(payload.curriculum_prompt)
          : payload.curriculum_prompt,
      };

      const verification = verifyCovenantPayload(covenant, sanitizedPayload);
      lastError = null;
      return { success: true, verification, data: sanitizedPayload };
    } catch (err) {
      lastError = err;
      throw err;
    }
  }

  return {
    isCompliant,
    sanitizeAndSubmit,
    getError: () => lastError,
  };
}

module.exports = {
  createCovenantGuard,
};
