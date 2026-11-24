# SpyderPay Core 0.9.0 — блок 3, крупный накопительный релиз

База: v0.8.0. Миграция schema 9 добавляет NFC possession challenge, отзыв карт, глобальный аварийный gate и независимый maker/reviewer resume. Сохраняются ранее созданные таблицы, платежи, комиссии, возвраты, KYC/AML и банковский dispatch. Не меняется .github/workflows.

- P-256 challenge с одноразовым использованием и проверкой подписи; не требует и не принимает приватный ключ карты. Proof не является разрешением на платёж.
- Vault Transit Ed25519 для QR signer, HTTPS/mTLS, версионированный ключ, local verify, fail-closed. Реальное подключение и HSM не подтверждены.
- Emergency stop на shared PostgreSQL row lock; ограниченная роль API не может возобновить трафик. Pause не отзывает ранее выданную команду отправки в банк.
- Зашифрованный logical backup через pg_dump + age, signed manifest v2, атомарная публикация, restore comparison.
- Hardened deployment policy (TLS, primary, remote signer, sandbox credit disabled), service units, readiness, logs, alerts policy, local bounded smoke probe.
- Merchant SDK для authenticated invoice/QR/status. Полноценный POS frontend, NFC applet, mobile integration, HA environment и независимый аудит ещё не выполнены.

## Поставка
Загрузить `spyderpay-core-update-v009.zip` в корень. Только ZIP, постоянный YAML не менять. Обязательный CI проверяет PostgreSQL, security gates, Bandit и pip-audit до применения. Исторические тесты сохранены, добавлены новые локальные и DB сценарии. Реальный PostgreSQL, Vault, pg_dump+age, системные службы и внешний WAF/SIEM в локальной среде не развёрнуты. См. инструкции в `infrastructure/operations/production-acceptance-v09.md`.
