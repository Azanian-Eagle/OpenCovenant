# opencovenant-server

Stateless language-agnostic HTTP/JSON microservice daemon (Axum) running on port `8090` as a Docker or Kubernetes sidecar.

## Endpoints

* `GET /healthz` — Liveness probe.
* `GET /metrics` — Prometheus metrics (total requests, enforce latency, redactions).
* `GET /openapi.json` — Machine-readable OpenAPI v3.1 specification.
* `POST /v1/covenants/enforce` — Sub-50µs redaction of PII/PHI/PAN payloads with SHA-256 cryptographic audit receipt.
* `POST /v1/covenants/verify` — Compliance invariant verification.

## Running

```bash
cargo run --bin opencovenant-server
```
