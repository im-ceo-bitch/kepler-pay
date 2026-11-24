# Spider Card + POS — протокол v0.9 (pre-license)

Сервер проверяет владение отдельным P-256 ключом; не заявляет аппаратную аттестацию. Это не банковская карта EMV, не готовый JavaCard applet и не механизм списания. Криптографический ключ Spider Blockchain отдельно, не передаётся в SpyderPay. В текущем релизе нельзя платить непосредственно прикладыванием карты без штатного OIDC/MFA и денежной авторизации. Реальные деньги закрыты.

## API
Все POST — `application/json`, OIDC access token от утверждённого IdP, никаких HMAC-секретов у клиента. Пользовательская роль customer, привязка сервером.

- `POST /v3/cards/enroll` `{public_key: "04..."}` — 65-байтная некомпрессированная SEC1 точка P-256 в lowercase hex. Требуется свежая MFA. Возвращает `challenge_id`, `card_id`, `message_hex`, `expires_at`, `algorithm`, `sandbox`, `payment_authority:false`.
- `POST /v3/cards/challenges/{challenge_id}/proof` `{signature: "..."}` — DER ECDSA P-256 SHA-256 в lowercase hex. Подписываются точные байты, полученные декодированием `message_hex`; при SHA256withECDSA не хешировать повторно. Для enrollment повторная проверка свежести MFA.
- `GET /v3/cards` — список идентификаторов и статусов, только своего пользователя.
- `POST /v3/cards/{card_id}/preview` `{invoice_id: "uuid"}` — выдаёт challenge на конкретный счёт. Proof возвращает сверенную сумму и merchant_account, `requires_payment_approval:true`.
- `POST /v3/cards/{card_id}/revoke` `{}` — отзыв с MFA, необратимый для этого ключа в текущем контуре.
- 90 секунд, nonce 256 бит, одно использование, максимум 10 challenge в минуту на владельца, максимум 5 активных ключей. DB owner lock сериализует выдачу и потребление, в том числе между API replicas. Отзыв не отменяет уже совершённый перевод. Для потери карты без доступа к IdP нужен отдельный проверенный процесс восстановления через поддержку.

Подписывается канонический JSON array `spyderpay-card-proof-v1-prelicense`, challenge UUID, tenant, owner, SHA-256 от issuer/sub/sid, purpose, card UUID, публичный ключ, nonce, invoice UUID или null, merchant UUID или null, amount или null, UZS, expiry epoch seconds. Клиент не составляет transcript сам. Он проверяет показанные параметры и передаёт exact message на карту. Не подписывать произвольные APDU запросы из непроверенного терминала. Протокол требует отдельной реализации card applet и защищённого транспорта между телефонным клиентом и чипом.

## Merchant POS
Merchant OIDC → `POST /v3/invoices` с идемпотентностью → `POST /v3/pos/invoices/{id}/token` → отобразить QR токена. Customer OIDC → `POST /v3/pos/preview` → сверка живого счёта → `/v3/approvals` (operation=pay_invoice), повторная MFA `/confirm`, `/v3/invoices/{id}/pay` с тем же ключом идемпотентности и `X-Spyder-Approval`. Не доверять статусу клиента: merchant проверяет `GET /v3/invoices/{id}`. Платёж всегда проходит ledger, compliance и текущий emergency gate. QR — подписанный короткоживущий JWT, не PAN и не секретный ключ.

`integrations/merchant-sdk` — минимальный JS клиент создания/чтения счёта и получения QR payload. Вызывающее приложение обязано реализовать доверенный OIDC/PKCE, QR-рендеринг, защищённый UX, polling/recovery, возвраты и авторизацию, не сохранять bearer token в localStorage. Для браузера размещать приложение на согласованном same-origin reverse proxy либо разработать строгое CORS policy; не добавлять wildcard CORS. SDK не включает самостоятельную POS-кассу.

## Acceptance gates
- Реальный P-256 Secure Element и JavaCard applet: non-exportable keys, trusted provisioning/attestation, PIN retry, anti-relay threat model, power loss, rollback, cloning и tamper tests.
- iOS Core NFC / Android ISO-DEP APDU: проверка на физических устройствах, сертификация, согласованные команды и форматы. Не считать эту схему совместимой с Tangem или EMV автоматически.
- Подтверждение суммы и продавца на доверенном устройстве: экран смартфона может быть скомпрометирован. Независимый аудит протокола и hardware supply chain.
