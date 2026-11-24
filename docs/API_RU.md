# SpyderPay sandbox API — v0.1

Base URL: `http://127.0.0.1:8765`. **Only loopback; NEVER expose on internet.**

All endpoints except `GET /health` require `X-Demo-Token: <runtime dev token>`. POST endpoints additionally require `Idempotency-Key` (8–128 ASCII characters, unique per logical request). Request JSON only, max 16 KB. Amount = positive INTEGER UZS, not floating-point. Every successful financial response remains sandbox-only.

| Method | Endpoint | Body | Result |
|---|---|---|---|
| GET | `/health` | — | environment sandbox, real_money false |
| POST | `/sandbox/accounts` | `{ "label": "Demo", "category": "customer" }` | account with id |
| GET | `/v1/accounts/{id}` | — | account and demo balance |
| POST | `/sandbox/credits` | `{ "account_id":"acc_...", "amount":100000 }` | sandbox_credit journal |
| POST | `/v1/transfers` | `{ "source":"acc_...", "target":"acc_...", "amount":15000 }` | atomic journal |
| POST | `/v1/invoices` | `{ "merchant_account":"acc_...", "amount":45000 }` | pending invoice |
| GET | `/v1/invoices/{id}` | — | invoice state |
| POST | `/v1/invoices/{id}/pay` | `{ "payer_account":"acc_..." }` | paid invoice |
| POST | `/v1/invoices/{id}/refund` | `{}` | full refund |
| GET | `/sandbox/audit` | — | ledger invariant check |

**No identity permissions:** Any holder of the sandbox token controls all demo accounts. Do not expose token to a public app or reuse this auth design in production.

The merchant QR, NFC APDUs, signed payment intents, exchange routes, and blockchain RPC are **future contracts**, not currently exposed endpoints. There are no real tokens or card numbers.
