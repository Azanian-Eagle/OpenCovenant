# `opencovenant-server`

Language-agnostic HTTP/JSON microservice daemon built on Axum for sub-50µs PII/PHI/PAN redaction and cryptographic compliance receipts.

## Ports & Endpoints

Default listening address: `0.0.0.0:8090` (configured via `--port` or `PORT` environment variable).

* `GET /healthz`: Liveness and readiness probe.
* `GET /metrics`: Prometheus counter metrics.
* `GET /openapi.json`: OpenAPI v3.1 specification.
* `POST /v1/covenants/enforce`: Redacts PII/PHI/PAN and evaluates invariants in sub-50µs.
* `POST /v1/covenants/verify`: Returns statutory invariant proof status with SHA-256 receipts.
