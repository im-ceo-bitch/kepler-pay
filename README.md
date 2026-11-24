# SpyderPay Core 0.10.0 — pre-license / cumulative blocks 1–3

Private payment core with immutable double-entry ledger, signed v3 service API,
OIDC transaction authorization, sandbox banking, compliance review, consent and
reviewed statement batches. Durable single-issue dispatch, runtime preflight, merchant fee accounting, internal chargebacks, signed POS invoice preview, and backup/restore verification added.
No live money, bank connections, production activation or security certification.

## Installation
Existing permanent `.github/workflows/spyderpay-unpack.yml` remains unchanged.
Upload only `spyderpay-core-update-v010.zip` to the repository root. The workflow
selects the newest cumulative ZIP, installs dependencies and runs required tests
before applying the archive. Workflows cannot be modified by an update ZIP.

## Local checks
Python 3.11+, PostgreSQL 16. Install `.[dev]`. Run:
`python -m pytest -q tests --ignore=tests/postgres` and
`python -m unittest discover -s scripts/security_gate -v`.
With disposable PostgreSQL and `SPYDERPAY_TEST_PG_DSN`, run
`python -m pytest -q tests/postgres`. Never target a production database.
Migration and DB privilege scripts must be run by a separate owner/admin.

## Docs
- `docs/RELEASE_V07_RU.md`: fees, chargebacks, POS and recovery.
- `docs/RELEASE_V06_RU.md`: current release and limitations.
- `docs/API_V06_RU.md`: private dispatch API.
- `docs/RELEASE_V05_RU.md`: implementation, migration and remaining gaps.
- `docs/API_V5_RU.md`: new private API.
- `docs/API_V3_RU.md`, `docs/API_V4_BANK_RU.md`: prior security/bank contracts
  (v5 overrides direct statement ingestion and requires compliance/consent).
- `infrastructure/operations/staging-runbook.md`: block 3 start.

- `docs/RELEASE_V07_R1_RU.md`: durable sandbox rail and offline reconciliation; outstanding partner acceptance gates.

- `docs/RELEASE_V08_RU.md`: amount refunds, schema 8 and block 2 acceptance checklist.

## Block 3 — infrastructure and controls
- `docs/RELEASE_V09_RU.md`: release scope, evidence and mandatory acceptance gates.
- `docs/CARD_PROTOCOL_V09_RU.md`: card possession and merchant POS API, no financial authority.
- `infrastructure/operations/production-acceptance-v09.md`: staging deployment, incident stop, external signing, backup/restore and HA requirements.
- `integrations/merchant-sdk/merchant.mjs`: merchant API client using supplied OIDC access token. Test with `node --test integrations/merchant-sdk/merchant.test.mjs`.
- `infrastructure/systemd/`: hardened Linux API and separate encrypted backup timer; requires real service accounts and credentials.
- `tools/staging_probe.py`: bounded loopback read-only readiness smoke test. Not a production load test.

## Block 3 v0.10
- `docs/RELEASE_V10_RU.md` and `infrastructure/operations/acceptance-v10.md`: current delivery and mandatory acceptance.
- `python -m tools.release_acceptance`: reports actual results, does not enable production.
- `python -m spyderpay_core.postgres.ops.merchant_gui`: private POS (external IdP token agent + `.[terminal]` + Tk).
