# SpyderPayKit — iOS 17+ pre-license client

The Swift package is compiled and unit-tested on Linux. The conditional Core NFC
adapter requires an actual iOS build and a compatible secure-element applet.
No wallet source, existing navigation, signing identity or Keychain is modified.

1. In the actual `kepler-spider` checkout, add this package as a local Swift package
   and link the `SpyderPayKit` product to the existing app target. Do not remove
   crypto views or change existing wallet keys. Place the Fiat flow behind the
   existing Fiat/Crypto mode selector.
2. Configure an explicit HTTPS origin for an isolated pre-license API. Supply an
   access-token closure from the app's external OIDC Authorization Code + PKCE
   implementation. Store tokens in the platform Keychain, not in code or logs.
   The SDK does not implement login. Never use service HMAC keys on the phone.
3. Call `accounts`, `preview(qr:)`, show the server-returned amount, merchant and
   payer, then construct a `PaymentIntent`. Persist its non-secret operation
   reference in app-private protected storage before issuing the first request.
   Call `challenge`, perform fresh step-up at the IdP in the same server session,
   then `confirm`, `pay`. Recover using the same `PaymentIntent` and `recover`
   if a response is lost; 404 means no receipt visible yet, NOT permission to
   retry a different payment. Use the exact same idempotency key if retrying.
4. On physical NFC, connect to the selected ISO7816 tag in a foreground session
   with the registered application AID and iOS NFC entitlement. Construct
   `ISO7816CardChannel` only from that connected tag. Use `CardProtocol.publicKey`,
   `enroll`/`cardPreview`, verify the intended transaction on the phone, then
   `CardProtocol.sign` and `proof`. Do not treat proof as money authorization.

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
