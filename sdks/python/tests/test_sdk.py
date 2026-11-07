import unittest
from azanian_eagle_opencovenant import (
    strip_inline_pii,
    blake3_or_sha256_salted,
    CovenantGuard,
)


class TestOpenCovenantPythonSdk(unittest.TestCase):
    def test_strip_inline_pii_removes_rsa_id_and_email(self):
        text = "Learner RSA ID: 0401015800085 and parent email: parent@example.co.za"
        redacted = strip_inline_pii(text)
        self.assertNotIn("0401015800085", redacted)
        self.assertNotIn("parent@example.co.za", redacted)
        self.assertIn("[REDACTED_RSA_ID]", redacted)
        self.assertIn("[REDACTED_EMAIL]", redacted)

    def test_blake3_or_sha256_salted_deterministic(self):
        h1 = blake3_or_sha256_salted("0401015800085", "PEPPER_A")
        h2 = blake3_or_sha256_salted("0401015800085", "PEPPER_A")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_covenant_guard_sanitizes_compliant_payload(self):
        guard = CovenantGuard("SocraticTutorEgress")
        result = guard.verify_and_sanitize(
            {
                "learner_sa_id": "0401015800085",
                "age_years": 15,
                "curriculum_prompt": "Help me with math homework. Contact me at student@school.co.za",
                "persisted_to_server": False,
            }
        )
        self.assertIn("learner_hash", result)
        self.assertNotIn("student@school.co.za", result["curriculum_prompt"])
        self.assertEqual(
            result["_statutory_verification"]["status"],
            "COMPLIANT_ZERO_TAINT_LEAKAGE",
        )

    def test_covenant_guard_raises_on_popia_sec35_violation(self):
        guard = CovenantGuard("SocraticTutorEgress")
        with self.assertRaises(ValueError) as ctx:
            guard.verify_and_sanitize(
                {
                    "age_years": 14,
                    "curriculum_prompt": "Grade 9 math session",
                    "persisted_to_server": True,
                }
            )
        self.assertIn("POPIA Section 35 Violation", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
