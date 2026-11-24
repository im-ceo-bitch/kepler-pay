# SpyderPayKit — iOS 17+ pre-license client

The Swift package is compiled and unit-tested on Linux. The conditional Core NFC
adapter requires an actual iOS build and a compatible secure-element applet.
The matching v0.12 Wallet overlay integrates this exact package into the existing
Console target. Install core v0.12 before the Wallet overlay. No HMAC service
secrets or crypto private keys belong in this client.

The app uses system-browser OIDC Authorization Code + PKCE, an explicitly
configured HTTPS origin, in-memory access tokens and a fresh same-session MFA
step-up. Configuration is not bundled with live credentials or invented URLs.
The account directory must explicitly advertise customer, sandbox and real_money
false; an incompatible or unavailable backend blocks Fiat operations.

API contract: `GET /v3/accounts`, owner-scoped `GET /v3/accounts/{id}/activity`,
QR preview and challenge/confirm/pay, `POST /v3/invoices/{id}/resolution`,
`POST /v3/transfers/resolution` and `/v3/transfers/cancel`. Use the actual paths
in WalletAPI.swift as authoritative. Persist the original operation identity
in protected device-local storage before issuing a financial request. Never
interpret a timeout or unknown state as a failed debit. The server alone
confirms final state. A transfer cancellation seals the same idempotency slot.

For NFC, use a connected ISO7816 tag, registered AID and Apple entitlement.
Card proof is possession only, not debit authorization.

## Reference APDU contract (not installed firmware)
CLA 0x80, P2=0, P1=0. GET_PUBLIC_KEY 0x20 returns 65 bytes SEC1 P-256.
BEGIN 0x30 takes 2-byte big-endian transcript length (<=2048), resets previous
state; UPDATE 0x31 takes 1..200 bytes; FINISH 0x32 returns DER ECDSA over
SHA-256 of exactly those bytes. Every success is 9000. An approved card applet
must enforce length, state, retry/PIN, anti-relay and lifecycle rules; it must
clear partial state on error, deselect and power loss. No key import/export.
Applet provisioning, registered AID, manufacturer certificate trust, hardware
attestation and physical tests are not supplied here. This protocol is not EMV
or Tangem-compatible and cannot authorize direct terminal debits.

Run `swift test` on Linux/macOS for portable SDK and transport tests. Run an
actual Xcode build, test IdP MFA, QR camera and NFC on iPhone separately.
