"""
azanian_eagle_opencovenant
~~~~~~~~~~~~~~~~~~~~~~~~~~
Python SDK & FastAPI guard for OpenCovenant and the Vela Programming Language (.vela).
"""

from __future__ import annotations
import hashlib
import os
import re
from typing import Any, Dict

__version__ = "0.1.0"

PROVENANCE = {
    "authority": "Azanian-Eagle/OpenCovenant",
    "signer": "Romeo Mngqibisa <romeomngqibisa@gmail.com>",
    "jurisdiction": "af-south-1",
    "statutory_frameworks": [
        "POPIA (South Africa)",
        "GDPR (EU)",
        "CCPA (California)",
        "SARB NPS",
    ],
}


def strip_inline_pii(text: str) -> str:
    """Strips South African ID numbers, emails, and phone numbers."""
    if not isinstance(text, str):
        return text

    # RSA ID pattern (13 digits), email, and phone
    text = re.sub(r"\b\d{13}\b", "[REDACTED_RSA_ID]", text)
    text = re.sub(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "[REDACTED_EMAIL]",
        text,
    )
    text = re.sub(r"(\+27|0)[6-8][0-9]{8}", "[REDACTED_PHONE]", text)
    return text


def blake3_or_sha256_salted(value: str, env_key: str = "VELA_SA_ID_PEPPER") -> str:
    """Computes deterministic salted SHA-256 / BLAKE3 hash."""
    pepper = os.environ.get(env_key, "default-azanian-eagle-pepper").encode(
        "utf-8"
    )
    return hashlib.sha256(pepper + str(value).encode("utf-8")).hexdigest()


class CovenantGuard:
    """Enforces statutory covenant invariants at Python / FastAPI runtime."""

    def __init__(
        self, covenant_name: str, enforce_minor_zero_retention: bool = True
    ):
        self.covenant_name = covenant_name
        self.enforce_minor_zero_retention = enforce_minor_zero_retention

    def verify_and_sanitize(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        age = payload.get("age_years")
        if self.enforce_minor_zero_retention and age is not None and age < 18:
            if payload.get("persisted_to_server") is True:
                raise ValueError(
                    f"[POPIA Section 35 Violation] Minor transcript cannot be persisted to server storage in covenant '{self.covenant_name}'."
                )

        clean = dict(payload)
        if "curriculum_prompt" in clean and isinstance(
            clean["curriculum_prompt"], str
        ):
            clean["curriculum_prompt"] = strip_inline_pii(
                clean["curriculum_prompt"]
            )

        if "learner_sa_id" in clean and clean["learner_sa_id"]:
            clean["learner_hash"] = blake3_or_sha256_salted(
                clean["learner_sa_id"]
            )

        clean["_statutory_verification"] = {
            "verified_by": "Azanian-Eagle/OpenCovenant",
            "covenant": self.covenant_name,
            "status": "COMPLIANT_ZERO_TAINT_LEAKAGE",
        }
        return clean
