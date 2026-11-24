# SpyderPay 0.10 — эксплуатационная приёмка до лицензии

## Установка в изолированной среде
1. Использовать проверенный исходный commit после успешного постоянного GitHub
   Actions. Собрать образ, получить SBOM и зафиксировать digest зависимостей/образа;
   подпись и provenance проверить вне исходного ZIP. Не публиковать API наружу.
2. Развернуть отдельную приватную PostgreSQL 16+, на чистой БД применить текущие
   миграции и оба набора ролей, проверить `runtime_preflight` от runtime login.
   Сделать это также на копии данных предыдущей схемы. Никогда не давать API роль owner.
3. Настроить `infrastructure/edge/nginx-isolated-v10.conf` вместо старого общего
   ingress (не одновременно). Установить сертификаты с SAN для фактических имён,
   отдельный CA клиентских сертификатов сервиса, firewall и private ingress.
   Закрыть прямой доступ к API и БД. При необходимости настроить separate IP/
   private gateway в реальном окружении. NGINX rate limit не защищает upstream от
   насыщения канала; провайдер WAF/DDoS обязателен для реального запуска.
4. IdP с RFC9068 токенами, MFA и проверенным жизненным циклом пользователей;
   внешняя ротация JWKS, отзыв и контроль доступа. Проверить реальные сценарии.
   Vault Transit: независимые ключи для POS и backup, разные роли и сертификаты;
   HSM-backed storage подтверждается инфраструктурой, не наличием адаптера.
5. Мониторинг — отдельный пользователь `spyderpay-monitor`, сертификат mTLS,
   сервисный HMAC principal с единственной ролью `monitor`, отдельный credential
   на tenant. `SPYDERPAY_MONITOR_ORIGIN` — служебный HTTPS origin, также задать
   `SPYDERPAY_MONITOR_KEY_ID`, `SPYDERPAY_MONITOR_SECRET_FILE` (base64 секрет, файл
   0600), `SPYDERPAY_MONITOR_CA`, `SPYDERPAY_MONITOR_CERT`, `SPYDERPAY_MONITOR_KEY`.
   Установить службу и таймер, связать stdout journal с независимым SIEM.
   Проверить, что ошибка TLS/ответа, пауза и критический ledger fault дают alert.
   Отсутствие события дольше двух интервалов должно давать отдельный alert.
6. POS: установить `pip install '.[terminal]'`; для GUI — системный Python Tk.
   Приватный терминал с доверенным агентом IdP: переменные `SPYDERPAY_ENV=prelicense`,
   `SPYDERPAY_TERMINAL_ORIGIN` (клиентский HTTPS), `SPYDERPAY_TERMINAL_TOKEN_FILE`
   (короткоживущий access token 0600, не сервисный секрет), `SPYDERPAY_TERMINAL_CA_FILE`,
   `SPYDERPAY_TERMINAL_STATE_DIR` (0700 на доверенном локальном диске).
   Запуск `python -m spyderpay_core.postgres.ops.merchant_gui`.
   CLI: `python -m spyderpay_core.postgres.ops.merchant_terminal accounts`,
   затем `new-reference`, `create SALE_UUID MERCHANT_UUID AMOUNT`, `status SALE_UUID`,
   `qr SALE_UUID`. Если ответ потерян — `pending`, `resume SALE_UUID`, не новая продажа.
   Не хранить IdP токены в git, не передавать покупателю сервисные ключи.
   При сканировании покупатель подтверждает фактический счёт в доверенном Wallet,
   а продавец принимает только проверенный серверный статус `paid` с корректной суммой.
   Аппаратная карта и attestation ещё не испытаны; QR — только preview, не debit.

## Автоматическая проверка
В disposable server с БД `spyderpay_test`, `SPYDERPAY_TEST_PG_DSN`, установленными
`.[dev]`, pip-audit, Node, NGINX и OpenSSL:
`python -m tools.release_acceptance --disposable-postgres`.
Это destructive-тесты исключительно в выделенном тестовом экземпляре. Без
флага PostgreSQL не запускается и итог не будет положительным. Runner фиксирует
только фактические результаты; внешний аудит/лицензия не могут быть заменены им.

## Проверки инфраструктуры (evidence обязательно)
| Проверка | Критерий принятия |
|---|---|
| PostgreSQL CI + upgrade rehearsal | Все тесты и миграции успешны на актуальном релизе; 0 пропущенных тестов, restricted roles, контроль двойной записи |
| IdP/KMS | Реальный MFA, revoke, key rotation, отказ signer без fallback, документированная HSM защита при требовании |
| Encrypted backup / restore | Изолированный `sp_restore_*`, подписанный manifest v3, совпадают counts и SHA всех таблиц, sequences_ok, независимая проверка ролей, функций и DDL; ни одного нарушения |
| PITR и failover | На копии финансовой нагрузки: отключение primary, fencing, отсутствие двойного writer, сохранность подтверждённых операций, замер RPO/RTO, без ручного изменения балансов |
| Нагрузка | Целевые TPS/p95/p99 утверждаются по банковскому контракту. Устойчивость 60 мин на согласованном пике и 24 ч soak, измерить saturation; 0 нарушений ledger/повторов. Не тестировать боевой сервис без согласования |
| Network security | WAF/DDoS и TLS/mTLS проверены в выбранном окружении; отсутствует прямой public ingress к API, БД или банковскому адаптеру |
| Incident response | Реальная доставка алертов, дежурство, stop, reconciliation и dual-control resume; экспорт независимых audit evidence |
| Physical card + POS | Выбор SE, аппаратная генерация и attestation, защита от relay/replay, совместимость iOS/Android, потеря/отзыв и резервные карты, внешний hardware review |
| Security / release | Независимый пентест и remediation критических/high findings, SBOM и provenance, утверждённая политика данных, PCI scope если применимо |
| Bank/AML integration | Реальные спецификации и договоры; provider sandbox, внешние выписки, комиссии, chargebacks, сверка и сертификация |
| Regulatory | Лицензия/правовой режим, согласованная модель средств, контроль регулятора и финансового партнёра |

Для восстановления использовать инструкции v09, но проверять новый format 3.
`ops.recovery inspect --manifest ... --backup ... --signature ...` проверяет
отпечаток восстановленных строк и последовательности. Хранить зашифрованный файл
и manifest в независимом immutable storage, не держать age private key на API.
Сортировка строк при backup может быть ресурсоёмкой; измерить время и влияние
на изолированном экземпляре. Отпечатки не заменяют проверку DDL/ACL/ключей.

Коммерческий запуск запрещён до всех внешних gates. Не существует кнопки,
переменной или CLI для автоматического разрешения real money в этой версии.
