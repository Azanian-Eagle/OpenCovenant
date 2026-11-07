# azanian-eagle-opencovenant: Python SDK & FastAPI Guard

[![PyPI](https://img.shields.io/pypi/v/azanian-eagle-opencovenant.svg)](https://pypi.org/project/azanian-eagle-opencovenant/)
[![Python Version](https://img.shields.io/pypi/pyversions/azanian-eagle-opencovenant.svg)](https://pypi.org/project/azanian-eagle-opencovenant/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE)

Official Python SDK and FastAPI/Django middleware for **OpenCovenant** and **The Vela Programming Language (`.vela`)**.

## 🇿🇦 Overview

`azanian-eagle-opencovenant` pairs seamlessly with backend Python services. It provides statutory Pydantic models, cryptographic sanitisation utilities (salted BLAKE3/SHA-256 and AES-256-GCM), and request-lifecycle guards aligned with South Africa's **POPIA**, EU **GDPR**, and **SARB NPS** requirements.

## Installation

```bash
pip install azanian-eagle-opencovenant
# or
poetry add azanian-eagle-opencovenant
# or
uv add azanian-eagle-opencovenant
```

## Quickstart with FastAPI

```python
from fastapi import FastAPI, Depends, HTTPException
from azanian_eagle_opencovenant import CovenantGuard, blake3_or_sha256_salted

app = FastAPI(title="EduHelp AI Sovereign API")

# Load generated covenant dataclasses
from generated.opencovenant_guard import LearnerSessionPayload

@app.post("/api/tutor/session")
async def create_session(payload: LearnerSessionPayload):
    # Statutory check: Minor learners (< 18) must not have raw ID stored
    hashed_id = blake3_or_sha256_salted(
        payload.learner_sa_id,
        env_key="VELA_SA_ID_PEPPER"
    )

    return {
        "status": "compliant",
        "jurisdiction": "af-south-1",
        "learner_hash": hashed_id,
    }
```

## Key Capabilities

* **High Performance**: Native cryptographic operations optimized for minimal latency.
* **FastAPI & Pydantic Integration**: Drop-in middleware for request intercept and payload sanitation.
* **Statutory Compliance**: Enforces POPIA Section 19 cryptographic security measures and Section 26 special personal information protections.

## Licence

Licensed under either Apache License, Version 2.0 or MIT license.
