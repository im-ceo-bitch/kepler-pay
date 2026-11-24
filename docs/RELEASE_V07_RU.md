# SpyderPay Core v0.7 — Financial controls / recovery / POS

Накопительный релиз 0.7.0, схема 7, только prelicense. Не содержит workflow.

## Блок 2
- Независимые роли `fee_maker`, `fee_review`. Тариф продавца в basis points (0–1000), округление вниз целыми UZS. По умолчанию нулевой тариф; применяется только независимо утверждённый тариф, последний по времени создания, и фиксируется при создании счёта. Смена тарифа не меняет старые счета.
- Клиент платит исходную сумму, комиссия вычитается из выручки продавца в той же транзакции, отдельный ledger-счёт комиссии. При полном возврате комиссия возвращается продавцу перед обратной проводкой покупателю, всё атомарно. Неизменяемые связи проводок, отложенная проверка согласованности с состоянием invoice.
- Внутренний полный chargeback: maker → reviewer → executor. Три разные личности, доказательства как непрозрачные ссылки, tenant isolation, идемпотентность, один кейс на invoice. До решения/исполнения обычный возврат блокируется. При отклонении обычный возврат снова разрешён. При нехватке средств или заморозке операция остаётся неисполненной для ручного расследования; не выпускаются искусственные деньги. Это НЕ внешний card-scheme chargeback, не арбитраж и не частичные возвраты. Нет автоматического дебетования банка.
- Операционные метрики: несогласованные комиссии/chargeback, зависшие кейсы.

## Блок 3
- POS short-lived signed invoice token (Ed25519/JWT, отдельный issuer/audience, ключи с периодами действия, смена kid), получатель, сумма, tenant и invoice зафиксированы. Токен для QR только preview, не полномочие на списание. Списание через существующее OIDC/MFA и ledger. Внешний KMS/HSM пока не подключён, аппаратный NFC не реализован.
- Проверка подписи manifest и SHA-256 зашифрованного backup, отдельная read-only проверка восстановленной БД по всем tenants, no auto restore. Проверяются инварианты ledger, holds, fees и chargebacks. Реальные backup/restore drills, сравнение с исходной копией, PITR и измерение RTO/RPO ещё не выполнены.

## API (v3; существующая service signature)
- POST `/v3/finance/fees` (`merchant`, `bps`, `evidence`) — fee_maker.
- POST `/v3/finance/fees/{sid}/approve` (`{}`) — fee_review.
- POST `/v3/finance/invoices/{iid}/chargeback` (`reason`, `evidence`) — dispute_maker.
- POST `/v3/finance/chargebacks/{cid}/decide` (`decision`: approve/reject, `evidence`) — dispute_review.
- POST `/v3/finance/chargebacks/{cid}/execute` (`{}`) — dispute_execute.
- POST `/v3/pos/invoices/{iid}/token` (`{}`) — merchant OIDC.
- POST `/v3/pos/preview` (`token`) — customer OIDC, preview; use invoice approval/pay routes after review.

## Migration and operations
Deploy only in isolated staging. Apply migration 006 through existing migration runner (schema 7), apply canonical runtime_roles.sql separately via DB administrator. Back up before migration. No downgrade. The permanent installer runs source checks and PostgreSQL CI but does not deploy the DB or create partner credentials.

## Open production gates
Real partner API contracts (bank sandbox, settlement windows, external reconciliation/chargeback, fees and taxes), real KYC/AML/sanctions sources and evidence workflows, device security, real IdP/MFA integration, independent audit, physical Secure Element/NFC, merchant mobile app, external KMS/HSM, HA, load/chaos tests, encrypted managed backup/PITR, WAF/DDoS/SIEM, regulatory review, and partner certification. No real-money activation. Passing local tests does not certify a payment system.
