# SpyderPay — архитектура и границы

## Репозитории

1. `kepler-spider` — пользовательское SwiftUI-приложение Wallet/Chats; новый режим Fiat/ Crypto через собственный UI host.
2. `spyderpay-core` — ledger + платежный домен + merchant + провайдерские адаптеры.
3. `spider-blockchain` — ноды, сеть, RPC и криптография цифрового актива; отдельный сервис.

## Карта модулей

```text
Spider Wallet iOS -- authenticated API (future) --> SpyderPay API
           |                                      |
           |                              Accounts/Payments
           |                                      |
           |                              Double-entry Ledger
           |                                      |
           |                         Bank/EMI adapter (future)
           |
           +-- Crypto signing + RPC --> Spider Blockchain (separate)
           |
           +-- NFC authorization --> Spider Card (future)

SpyderPay POS -- authenticated Merchant API (future) --> SpyderPay API
```

## Реализовано v0.1

- Только UZS-модель для симуляции (нет реального электронного счёта клиента).
- Транзакционное списание и зачисление в одной SQLite-транзакции.
- Защита от повторного API-выполнения по `Idempotency-Key` + SHA-256 полного входного payload.
- Инвойсы со строгими переходами `pending -> paid -> refunded`.
- Строгая сумма (положительное целое), запрет овердрафта клиентских счетов.
- Технический системный clearing-счёт с отрицательным сальдо только внутри тестовой модели.
- Self-audit: баланс каждой записи, сумма по журналу = 0, неотрицательные клиентские остатки.

## Предполагаемые будущие сервисы

- Identity + individual customer authentication / authorization
- Bank adapter with signed webhooks, replay protection and reconciliation
- Merchant onboarding & payout settlement / reserves / partial refunds
- KYC/AML + antifraud + limits + sanctions
- Card NFC lifecycle / challenge-response / PIN
- Separate crypto client adapter + custody/security review
- Observability, DB backup/restore, DR, security certification

## Важная модель регулирования

Код можно разрабатывать и тестировать до получения лицензии. Реальные расчёты в сумах требуют корректной юридической модели и сотрудничества с разрешёнными финансовыми институтами либо собственной авторизации. Выпуск тестового кода не является разрешением обслуживать денежные обязательства. Криптоплатежи в Узбекистане требуют отдельной правовой проверки и разрешённого режима.
