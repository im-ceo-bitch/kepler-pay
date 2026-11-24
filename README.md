# SpyderPay Core 0.4.0 — pre-license / blocks 1 and 2

Cumulative source release. Not approved for real money. No bank credentials, real bank integrations or production activation. See `docs/RELEASE_V04_RU.md` for actual implementation and remaining gates. Security controls are described in `docs/API_V3_RU.md`; sandbox bank lifecycle in `docs/API_V4_BANK_RU.md`.

## Installation

Install the permanent `spyderpay-unpack.yml` manually at `.github/workflows/spyderpay-unpack.yml` once (replace the old workflow). Upload `spyderpay-core-update-v004-r1.zip` to the repository root. The permanent workflow chooses the highest release/revision, tests it without write credentials, and applies the same archive only after the gates pass. Older matching update ZIPs are removed only after successful verification. GitHub workflows are never supplied or changed by the ZIP. See `docs/INSTALL_V04_RU.md`.

## Local checks

Python 3.11+, PostgreSQL 16. Install `.[dev]`. Run `python -m pytest -q tests --ignore=tests/postgres` and `python -m unittest discover -s scripts/security_gate -v`. Run `python -m pytest -q tests/postgres` with a disposable database and `SPYDERPAY_TEST_PG_DSN`. Never use a shared or production database for test fixtures. See `docs/security/PRODUCTION_GATE_RU.md`. Block 2 is not yet complete.
