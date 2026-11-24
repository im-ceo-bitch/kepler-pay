# API v3 — блок 1

Только изолированный prelicense/staging. Все суммы в текущей схеме — целые тестовые UZS; дробные суммы запрещены. Уровень точности и лимиты должны быть согласованы с банком в блоке 2. `/v2` не обслуживается новым CLI; прежняя фабрика API сохраняется исключительно для локальной регрессии.

## Доверенная идентификация

`SPYDERPAY_OIDC_JSON`: JSON с `issuer` (HTTPS), `audience`, `client_id`, `mfa_acr_values` (доверенные значения именно настроенного IdP), `jwks: {keys:[...]}`. Только публичные RSA JWKS 2048–4096 бит, RS256, `typ=at+jwt`, claims iss/aud/sub/exp/iat/jti/sid/client_id. Максимум 600 секунд между iat и exp. Для step-up нужны `auth_time` и `acr`. Нет удалённой загрузки ключей из токена. Ротация JWKS сейчас производится управляемым обновлением секрет-конфигурации и перезапуском; не считать автоматической OIDC discovery. IdP должен сохранять sid во время step-up, выдавать новый jti и честно обновлять auth_time только при новой аутентификации.

Роли и tenant из JWT не используются. Отдельный администратор идентичности вносит запись через `tools/identity_admin.py`; операции disable/revoke-session выполняются под отдельным DSN. В production нужен интегрированный процесс отзыва от IdP и защищённый onboarding; пока это административный контракт.

## Перевод (Bearer)

1. Клиент входит через IdP с Authorization Code + PKCE (настраивается в IdP и клиентском приложении, не реализовано в данном backend).
2. `GET /v3/accounts` возвращает счета только локально сопоставленного субъекта.
3. Покажите человеку получателя и сумму. `POST /v3/approvals`, `Idempotency-Key: unique-transfer-0001`, body `{"operation":"transfer","source":"<uuid>","target":"<uuid>","amount":25000}`. Ответ содержит `approval_id`, детали, срок и `state=mfa_required`.
4. Запустите реальный step-up у IdP, новый access token с тем же sid, новым jti, auth_time строго позже секунды выдачи challenge и разрешённым acr. `POST /v3/approvals/<approval_id>/confirm`, body `{}`, Bearer нового токена. Подтверждение действует не более 90 секунд и не дольше времени действия MFA/токена.
5. `POST /v3/transfers`, Bearer, `X-Spyder-Approval: <uuid>`, тот же `Idempotency-Key`, body `{"source":"<uuid>","target":"<uuid>","amount":25000}`. Изменение параметров, сессии или idempotency не допускается. Повтор успешной операции тем же субъектом и ключом возвращает прежний результат.

Это серверный transaction-bound step-up, а не независимое доказательство физического согласия человека и не FAPI/DPoP-сертификация. Компрометация устройства или IdP остаётся угрозой. Требуются защищённый UX и sender-constrained credentials/аппаратная подпись до коммерческого запуска.

## Merchant invoices

- `POST /v3/invoices` (merchant): `merchant_account`, `amount`, `ttl_minutes`, idempotency header.
- `GET /v3/invoices/<uuid>/preview` (customer в том же tenant, только pending): сумма и merchant_account. UUID должен передаваться через защищённый merchant QR/API; этот релиз не реализует подписанный QR.
- Challenge оплаты: `operation=pay_invoice`, `invoice_id`, `payer`, `expected_amount`, `expected_merchant`. Затем confirm и `POST /v3/invoices/<uuid>/pay`, body `{"payer_account":"<uuid>"}` с исходным ключом и approval.
- Challenge возврата (merchant): `operation=refund_invoice`, `invoice_id`, `expected_amount`, `expected_merchant`. Затем confirm и `POST /v3/invoices/<uuid>/refund` body `{}`.

## Сервисные операции (не для телефона)

`SPYDERPAY_SERVICE_KEYS_JSON`: массив `{key_id,secret_b64,tenant_id,subject,roles:["ops"],not_before,not_after}`. Секрет 32–128 байт из криптографического RNG, разные ключи для каждого ID; окно действия <=90 суток. Подпись HMAC-SHA256 hex по UTF-8 canonical JSON массиву `['spyderpay-s2s-v3',key_id,METHOD,raw_path,sha256_hex(body),timestamp,nonce,idempotency_key_or_empty]` без пробелов, `ensure_ascii=true`. Заголовки `X-Spyder-Key-Id`, `X-Spyder-Timestamp`, `X-Spyder-Nonce`, `X-Spyder-Signature`; для мутаций `Idempotency-Key` также подписан. Timestamp ±120 сек, durable nonce. Подпись v2 не принимается v3. `tools/sign_request_v3.py` читает секрет из переменной окружения. Не хранить его в приложении или истории shell.

`POST /v3/ops/accounts`, `/v3/ops/accounts/<uuid>/freeze`, `GET /v3/ops/reconciliation`, `/v3/ops/ready`. Тестовое зачисление `/v3/ops/sandbox/credits` выключено по умолчанию. HMAC ops не может вызывать клиентские переводы/подтверждения. Настроить частный ingress и mTLS, ключи через secret manager; HSM/KMS интеграция ещё не реализована.

## HTTP

Нет query string/закодированного пути; POST JSON object max 16 KiB; дубли ключей JSON, security headers, конфликт framing, неверный content type отклоняются. Ответы с request-id, no-store, без raw payload/SQL/token. Временная недоступность 503: клиент повторяет с прежним idem; нельзя создавать новый платёжный идентификатор после неопределённого результата. Rate limits не заменяют WAF/DDoS protection.
