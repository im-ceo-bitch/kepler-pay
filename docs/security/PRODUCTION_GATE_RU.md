# Готовность SpyderPay к запуску — обязательные ворота

**Актуализация v0.3:** см. `BLOCK1_OPERATIONS_RU.md` и `../ROADMAP_RU.md`. Ниже сохранён исторический baseline v0.2, не текущий перечень реализованных механизмов.

Статусы: ✅ код/схема доступны и локально проверены; 🧪 написано, но проверка потребует CI PostgreSQL; ⛔ отсутствует.

| Блок | Статус v0.2 | Критерий полного завершения |
|---|---|---|
| Ledger (двойная запись) | ✅ SQLite; 🧪 PostgreSQL | Независимая сверка, авторитетный банк/электронные деньги, целостность на нагрузке |
| Атомарные списания | 🧪 | PostgreSQL concurrency tests + chaos + performance tests на целевых нагрузках |
| Сервисная подпись запросов | ✅ | Ротация, HSM/KMS, mTLS, нагрузочный rate-limit, аудит ключей |
| Клиентская аутентификация | ⛔ | OIDC/FAPI, MFA, step-up, lifecycle токенов, auth device binding |
| KYC / AML / sanctions / fraud | ⛔ | Провайдеры, risk rules, manual review, regulatory retention |
| Банковский интерфейс | ⛔ | Реальные контракты, sandbox банка, сертификация, settlement report |
| Удержания / клиринг / расчёты | ⛔ | Мультистатусные funds flow, beneficiary payout, reconciliation |
| Merchant onboarding | ⛔ | Верификация продавца, тарифы, возвраты, disputes, tax accounting |
| NFC Spider Card | ⛔ | Сертифицированный Secure Element, PIN, replay/relay resistance, independent test |
| Приватность и PCI scope | ⛔ | Data classification, PII encryption, retention, DSS assessment as applicable |
| SRE/HA/backup/DR | ⛔ | SLO, PITR, failure injection, RPO/RTO proof, security monitoring |
| Penetration test и audit | ⛔ | Отчёты независимых специалистов и закрытие critical/high findings |
| Регуляторная/юридическая готовность | ⛔ | Юридическая модель, лицензии/партнёры, согласованные правила деятельности |

**Запрет:** не принимать настоящие UZS, не эмитировать денежный баланс и не оплачивать SPYDER Coin в магазинах на основе этого релиза. Функция `/v2/sandbox/credits` существует исключительно как симулятор, по умолчанию отключена. Любая следующая версия, которая включает реальные деньги, требует отдельного архитектурного и правового review.
