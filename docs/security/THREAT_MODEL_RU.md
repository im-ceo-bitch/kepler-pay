# SpyderPay — модель угроз STRIDE, версия 0.2

**Область:** частный API, бухгалтерский реестр, инструменты разработчика, архивный CI, схема взаимодействия с банковским партнёром. Не распространяется на безопасность будущей NFC-карты или работающих банковских систем.

| Актив и риск | Что может пойти не так | Уже предусмотрено | Что ещё необходимо |
|---|---|---|---|
| Идентичность платёжного запроса | Подмена отправителя / фальсификация транзакции | HMAC подпись body/path/method/timestamp/nonce, scopes | OIDC/FAPI для конечного клиента, mTLS для партнёра, HSM/KMS и ротация |
| Повтор запроса | Double charge через retry/replay | Уникальность nonce, долговечная idempotency-запись, транзакция БД | Установить TTL/политику архивирования, повторные тесты на стороне PSP |
| Изменение суммы | Смена счёта/суммы на пути | Сервисная подпись raw body, строгие типы integer | Trusted confirmation на устройстве, binding подписываемой суммы/получателя |
| Многократные списания | Race при параллельном запросе | `SELECT ... FOR UPDATE`, условное списание, уникальный invoice state | Load/chaos tests, многорегиональная стратегия и нагрузочные сценарии |
| Изменение истории | Стирание/переписывание проводок | DB triggers prohibit UPDATE/DELETE postings/journals/audit; cross-check | Внешний WORM audit trail, DB separation of duties, immutable backups |
| Кросс-tenant | Доступ к чужому кошельку или счёту | tenant+owner проверяются на сервере | Row-level security, ABAC audit, auth gateway negative tests |
| Внутренняя злоупотребление | Зачисление денег оператором | sandbox credit только `ops` и feature gate, production exit fail-close | Для реальных UZS — банк-эмитент, 4-eyes approvals, dual control, сверка по выпискам |
| Поддельный банковский callback | Выдуманное зачисление | Контракт провайдера, пример проверки HMAC; автоматической проводки из callback нет | Подписанный mTLS provider adapter, независимая выписка, matched settlement |
| Утечка персональных/ключевых данных | Credential theft / privacy breach | Нет card PAN, seed, private keys или паспортов в ledger; нет логирования raw body | Сегментация PII, шифрование на хранении, политики retention, secrets manager |
| DDoS/ресурсное истощение | Массовые запросы и блокировки | 16KB body, SQL statement/lock timeouts, DB per-key rate window | WAF, CDN, gateway limiter, network policies, autoscaling, backpressure |
| Supply chain/CI | Вредоносный ZIP изменяет workflow/ключи | Allowlist, no symlinks, no traversal, no workflows/scripts in ZIP, tests before commit | Signed releases, pinned GitHub Actions SHAs, secret scanning, code owners |
| Availability/data loss | Региональный outage, corruption | PostgreSQL транзакции, ledger reconciliation | PITR, HA, restores, disaster simulations, RPO/RTO/SLO |
| Compliance | Незаконный приём платежей | Sandbox-only разделение фиата и крипто | Партнёры, лицензии, режимы ответственности, AML/KYC, аудит ЦБ/НАПП |

## Security invariants

1. Для каждой фактической проводки сумма всех ног (минимум двух) равна 0 и валюта UZS.
2. Внешний счёт никогда не становится отрицательным вследствие перевода.
3. На один invoice может быть только одна успешная оплата. Перевод атомарен с журналом и outbox.
4. Любой клиент может списать только средства своего счёта после проверки полномочий.
5. Фиатный ledger не импортирует и не конвертирует SPYDER Coin.
6. Холодная Spider Card никогда не передаёт серверу приватный ключ.
7. Прямой банковский callback не является разрешением выпустить собственные обязательства в сумах.

## Ограничения текущей защиты

Схема без бэкенд-пула соединений и без реальных банковских интеграций — исследовательская. Аудит только внутри той же PostgreSQL БД не является независимым/неизменяемым доказательством против привилегированного администратора. Контроль реквизитов на NFC-карте без дисплея требует отдельного threat model. Нельзя объявлять «защита от всех кибератак» даже после тестов: нужны внешние пентесты, red-team, независимый аудитор и работающий security operations процесс.
