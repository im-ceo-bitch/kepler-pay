# Дополнительные закрытые маршруты /v3
Все запросы аутентифицированы service protocol v3, включая ключ идемпотентности;
каждый сервис имеет один role, отдельный subject и ключи. Не использовать
сервисные секреты в iOS/Android. Все операции — sandbox/prelicense.

| Метод и маршрут | Роль | JSON поля |
|---|---|---|
| POST /v3/compliance/accounts/{account}/reviews | compliance_maker | kyc, screening, tier, evidence_ref |
| POST /v3/compliance/reviews/{review}/decide | compliance_review | decision |
| POST /v3/bank/consents | bank_consent | account, provider, direction, amount, beneficiary_ref, consent_ref, evidence_digest |
| POST /v3/clearing/batches | bank_statement | provider, batch_ref, opening, closing, credits, debits, rows |
| POST /v3/clearing/batches/{batch}/approve | clearing_review | digest |
| GET /v3/clearing/reconciliation | clearing_review | none |
| GET /v3/ops/health | ops | none |

KYC: verified/rejected/pending. Screening: clear/hit/pending. Tier:
standard/enhanced. Decision: approved/rejected. Batch row: event_ref,
provider_ref, direction (deposit/withdrawal), amount, beneficiary_ref, status
(settled/failed). Digest — SHA-256 нормализованного содержимого, вычисляет API.
Подтверждение batch должно использовать digest из отдельной независимой сверки,
а не автоматически копировать его из ответа импортера. Реальные первичные
файлы и их подписи не хранятся и не проверяются этим API.

## Последовательность
1. Создать account (ops), записать KYC и screening (maker), принять решение (review).
2. Выполнить bank risk review (risk_ops); аттестовать consent (bank_consent).
3. Создать intent (bank_ops), проверить и зарезервировать (bank_review),
   записать dispatch sandbox (bank_ops). При неоднозначности unknown; не повторять debit.
4. Записать callback (bank_callback), импортировать пакет выписки (bank_statement),
   отдельно подтвердить пакет (clearing_review).
5. Bank review выполняет settle с идентификаторами callback и statement evidence.
   Только согласованные записи и корректный ledger могут завершить операцию.
6. Проверить reconciliation и health. Конфликты эскалировать через case workflow.

Лимиты и алгоритмы являются внутренними правилами sandbox, не заменяют
лицензионные процедуры. Не применять к настоящим платежам.
