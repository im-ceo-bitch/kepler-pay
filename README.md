# SpyderPay Core v0.2 — Payment Security Foundation

**Status:** pre-license engineering platform; NOT licensed, audited, bank-connected or approved to hold/pay out real money. No real UZS or SPYDER Coin can be issued by this code. No production deployment.

This is the independent **payment core** repository for the proposed SpyderPay application. The mobile app (`kepler-spider`, Fiat/Crypto switch) and the blockchain client/node live in separate repositories. One frontend can call different backends; fiat and cryptocurrency must not share balances, keys, or settlement accounting.

## Delivered in v0.2

- **PostgreSQL 16 reference core:** transactional zero-sum double-entry postings (multi-leg-ready schema), ledger consistency constraints, account balances, idempotent operations, accounts scoped to tenant and owner, invoice expiry/payment/refund, frozen accounts and 24h velocity limits.
- **Defense in depth:** immutable posting and journal triggers, PostgreSQL row locking for concurrent debits, conditional balance updates, reconciliation query, append-only audit table, transactional outbox.
- **Private service API:** FastAPI endpoints and signed HMAC-SHA256 service requests, timestamp+nonce replay prevention, DB-backed per-key request quotas, strict request schemas, non-public documentation endpoints, HTTP response headers and operator-only sandbox credits.
- **Bank adapter boundary:** typed integration contract and example signed callback verifier — **no actual bank integration or automatic UZS crediting from webhooks**.
- **CI:** PostgreSQL 16 service tests for concurrent withdrawals, idempotency, isolation, refunds and integrity triggers; unit, HTTP and negative security tests; Bandit check; safe ZIP installer and conservative generated-junk cleanup.
- **Operational documentation:** threat model, recovery plan, production readiness checklist, explicit deployment and license-dependent gaps.

### Contents

| Path | Purpose |
|---|---|
| `spyderpay_core/ledger.py` | Previous SQLite sandbox reference, still available for smoke tests |
| `spyderpay_core/server.py` | Previous localhost-only sandbox API (non-production) |
| `spyderpay_core/postgres/migrations/001_core.sql` | PostgreSQL schema and immutable accounting triggers |
| `spyderpay_core/postgres/store.py` | PostgreSQL transaction processor |
| `spyderpay_core/postgres/auth.py` | Server-to-server HMAC auth and anti-replay |
| `spyderpay_core/postgres/api.py` | Private FastAPI router |
| `spyderpay_core/postgres/bank_adapter.py` | Provider adapter contract and test-only signed webhook format |
| `tests/postgres/` | PostgreSQL integration and concurrency tests |
| `docs/security/` | Security baseline and threat modelling |
| `.github/workflows/` | Security CI and safe ZIP updates |

## Local validation

Python 3.11+ (3.13 used in CI), PostgreSQL 16 for the database tests. For a local disposable PostgreSQL service run `docker compose -f compose.test.yaml up -d` (127.0.0.1:5436, database `spyderpay_test`, test-only password `local-test-only-do-not-reuse`). On a developer machine:

```bash
python -m pip install -e '.[dev]'
python -m pytest -q tests --ignore=tests/postgres
# POSTGRESQL is mandatory for real database test coverage:
export SPYDERPAY_TEST_PG_DSN='postgresql://spyder_test:local-test-only-do-not-reuse@127.0.0.1:5436/spyderpay_test'
python -m pytest -q tests/postgres
```

`SPYDERPAY_ENV=prelicense` and `SPYDERPAY_PG_DSN` are mandatory for the private API. Initial schema migration:

```bash
export SPYDERPAY_ENV=prelicense
export SPYDERPAY_PG_DSN='postgresql://<user>:<secret>@127.0.0.1:5432/<db>'
python tools/migrate_postgres.py
```

**Never** paste credentials from the examples into deployed systems. The API requires `SPYDERPAY_SERVICE_KEYS_JSON` from a secret manager; see [API_V2_RU.md](docs/API_V2_RU.md). It binds to **127.0.0.1** and refuses to run unless `SPYDERPAY_ENV=prelicense`. The signing secrets belong to trusted backend services ONLY, never iOS/Android apps. Mobile user authentication must be integrated through an OIDC/step-up identity gateway before any consumer rollout.

## Repository / GitHub ZIP installation

1. For a **new** `spyderpay-core` repository, upload the entire `spyderpay-core-v02-initial-repo.zip` contents once. Keep GitHub Actions and `scripts/` committed as normal tracked files.
2. For an **existing v0.1** repository, first commit the contents of `spyderpay-core-v02-actions-bootstrap.zip` (workflow, package manifest, tools) as a reviewed change, because source ZIPs may not modify workflow and scripts.
3. Then upload the single large **`spyderpay-core-update-v002.zip`** file to repo root. The Action installs only `spyderpay_core`, `tests`, `docs`, `integrations`, runs tests including PostgreSQL and removes the consumed ZIP from the committed branch. It does not delete unrelated project source files.
4. If branch protection disallows Actions pushes, run installation via a reviewed PR; do not relax branch protection just for ZIP automation.

**Release gates still missing:** hardened OIDC customer authentication, bank certification & contracts, full payment settlement lifecycle, external KYC/AML/sanctions systems, PCI scope determination, HSM/key custody, step-up transaction approval, secure NFC hardware attestation, audit/penetration tests, independent recovery tests, privacy/legal approvals and regulator clearance. See `docs/security/PRODUCTION_GATE_RU.md`.
