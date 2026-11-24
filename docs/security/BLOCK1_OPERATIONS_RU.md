# Эксплуатация блока 1 (prelicense)

## Разделение ролей

1. Отдельный PostgreSQL 16 database, приватная сеть, владелец схемы не используется API. Перед миграцией резервная копия, пробное восстановление, остановка всех legacy writers и окно обслуживания.
2. `SPYDERPAY_ENV=prelicense SPYDERPAY_PG_DSN=... python tools/migrate_postgres.py` — через migration DSN. Runner хранит версии 2/3, не переисполняет предыдущую схему. При расхождениях старая база не исправляется автоматически.
3. Администратор БД выполняет `infrastructure/postgres/runtime_roles.sql`, создаёт login роли с секретами вне Git и выдаёт membership в NOLOGIN группах `spyderpay_runtime` и `spyderpay_identity_admin`. Не использовать superuser/owner для API. Владелец выделенной БД должен отдельно проверить все grants/роль и отсутствие PUBLIC write privilege. Привилегии runtime ограничены по таблицам и колонкам, но он всё ещё доверенный процесс, не полноценный DB RLS. Компрометация runtime может инициировать согласованные мошеннические проводки; требуется изоляция и отдельные service boundaries.
4. Настроить IdP согласно API_V3_RU, передать публичные JWKS, настроить срок токена и step-up, provision реального тестового пользователя. API: `python -m spyderpay_core.postgres.api_v3`. Бинд loopback; отдельный защищённый proxy, TLS/mTLS, приватный subnet. Пример NGINX только локальный.
5. Отдельные учётные записи секрет-менеджера, ограниченная сеть, отсутствие публичного доступа к БД. Отключить sandbox credits по умолчанию. Не принимать настоящие деньги.

## Угрозы и остаточные риски

| Угроза | Механизм блока 1 | Остаточный риск / внешний контроль |
|---|---|---|
| Подмена JWT | RS256, фиксированный issuer/aud/client/JWKS, access token typ | компрометация IdP, rotation и sender binding |
| Украденный bearer | короткий lifetime, revocation, новая MFA после challenge | вредоносное устройство, IdP phishing, реальная passkey policy |
| Подмена суммы/получателя | digest operation + idem + session, одноразовое атомарное consumption | доверенный UI, transaction signing устройства |
| Replay S2S | подписанные raw target/body/idem/key_id, durable nonce | mTLS/KMS, ротация, многоузловые часы |
| Двойное списание | row locks, unique idem, rollback, sealed ledger | нагрузка, chaos, неизвестный результат банка |
| Изменение истории | immutable journals/postings, DB guards, restricted role | owner/DBA compromise, WORM export, независимый reconciliation |
| Изменение баланса | deferred account vs postings check | полный scan истории на изменяемый счет; benchmark и оптимизация до high-scale |
| HTTP abuse | body/time/slot limits, per-identity quotas, reject ambiguity | edge WAF, distributed rate limit, volumetric DDoS |
| Мошенничество сотрудника | ops/client split, separate identity admin | maker/checker, role scopes, SOC, legal/fraud controls |

## Восстановление и мониторинг

- В staging сохранять зашифрованные backup/WAL вне primary host; проверить PITR на отдельном хосте, результат reconciliation для каждого tenant.
- Алерты: 5xx, quota errors, invalid signature, revoked session, ledger mismatch, длительные блокировки, replication lag, outbox age, DB space. Логи не включают bearer, secret, PAN/seed или тела запросов. Данные аудита экспортировать в отдельное защищённое хранилище; текущая БД не WORM.
- При инциденте ограничить ingress, отозвать IdP сессии и service keys, изолировать подозрительные роли и счета, сохранить доказательства, выполнить сверку; не исправлять баланс прямым SQL.
- RPO/RTO, retention, capacity и SLA ещё не подтверждены. Миграция, backup restore и crash tests на реальной инфраструктуре обязательны.

## Release gates

Unit/regression + реальные PostgreSQL tests обязательны. Оценка ASVS/API security/FAPI и применимости PCI DSS, независимый аудит, security review банка, реальные KYC/AML и сертификация ещё не выполнены. Не выдавать эту версию за коммерческий production.
