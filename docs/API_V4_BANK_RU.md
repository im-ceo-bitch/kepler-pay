# Block 2 / SpyderPay банковский процессинг v0.4 (prelicense)

Банковские операции реализованы для тестовых UZS, без сетевых запросов к банкам.
Провайдеры ограничены префиксом `sandbox-`, как в API, так и в БД. Нет боевого режима.
Платёжная система не является эмитентом денег. Внешние реальные договоры, лицензия,
доказательство согласия клиента, KYC/AML, банковские сертификаты и независимые
испытания остаются обязательными. `consent_ref` — только уникальный идентификатор
ссылки на доказательство согласия в будущей интеграции, не само доказательство.

## Роли (подписанные v3 service credentials)

| role | действие |
|---|---|
| ops | старые операционные функции, не банковские переходы |
| risk_ops | выставление / отзыв статуса risk review |
| bank_ops | создание intent, регистрация отправки, unknown, открытие случая |
| bank_review | независимое согласование, отмена до отправки, settlement, сверка, закрытие случая |
| bank_callback | нормализованные доказательства callback |
| bank_statement | нормализованные записи независимой банковской выписки |

Отдельный subject на роль в tenant, отдельные секреты. Ключи клиентам не выдавать.
Все POST используют подписанный `Idempotency-Key`. Все тела — JSON, даже `{}`.
Формат HMAC и общие требования v3 см. `docs/API_V3_RU.md`. Клиенты OIDC не могут
вызывать bank API. Доступные банковские вызовы являются server-to-server, не
публичными маршрутами пользователя. Сервис, действующий от лица клиента, должен
сначала проверить согласие и привязать его к неизменным реквизитам.

## Запросы

| Метод и путь (prefix /v3/bank) | роль | тело |
|---|---|---|
| POST /risk/{account_id} | risk_ops | state, review_ref |
| POST /intents | bank_ops | account, direction, provider, amount, beneficiary_ref, consent_ref |
| GET /intents/{iid} | bank_ops, bank_review, risk_ops | — |
| POST /intents/{iid}/review | bank_review | {} |
| POST /intents/{iid}/submit | bank_ops | provider_ref |
| POST /intents/{iid}/unknown | bank_ops | {} |
| POST /intents/{iid}/cancel | bank_review | {} |
| POST /evidence/{callback или statement} | отдельная роль | provider,event_ref,provider_ref,direction,amount,beneficiary_ref,status,payload_digest |
| POST /intents/{iid}/settle | bank_review | callback_id, statement_id |
| GET /reconciliation | bank_review | — |
| POST /intents/{iid}/cases | bank_ops | reason |
| POST /cases/{cid}/close | bank_review | resolution |

`amount`: целые сумы 1..100 млн (временный тестовый лимит), `direction`: deposit/withdrawal.
`provider`: `sandbox-bank`, `provider_ref`: opaque reference. Не передавать PAN,
ПИН, паспортные данные, банковские ключи или seed. `payload_digest` — lowercase
SHA-256 исходного нормализованного сообщения; доверенный адаптер проверяет исходную
банковскую подпись до передачи. Настоящий формат подписи определяется конкретным
партнёром, текущие тестовые каналы не доказывают реальность внешнего перевода.

## Жизненный цикл

`created -> authorized -> submitted -> unknown (optional) -> settled/failed`
`created/authorized -> cancelled`; отмена после отправки запрещена. При withdrawal
согласование резервирует средства отдельной double-entry проводкой на отдельном
системном hold account. При окончательном success резерв уходит на clearing,
при подтверждённом failure возвращается на счёт (включая замороженный счёт, который
остаётся замороженным). При deposit только settlement с двумя совпадающими каналами
создаёт credit из тестового clearing. Одно событие или timeout никогда не создаёт
деньги и не возвращает резерв. Повторный settlement с тем же ключом возвращает
старый результат. Другой ключ не может повторно исполнить terminal intent.

Два доказательства должны совпадать по tenant, provider, provider_ref, direction,
amount, beneficiary_ref, status, иметь разные роли, акторов и ID; ранее принятые
противоречащие события блокируют автоматическое завершение. Settlement, потребление
evidence, журнал, аудит и outbox атомарны. Новый противоречивый факт после settlement
отображается в сверке и требует ручного расследования, а не несанкционированного
реверса. Неиспользованный конфликт не удаляется. Закрытие case не меняет баланс.

Сверка: итоги по состояниям/направлениям, unmatched evidence, conflicting intents,
несоответствие hold, зависшие >30 мин, открытые случаи. Базовая бухгалтерская сверка
ledger по-прежнему отдельная. Это не полноценная сверка банковского остатка/баланса
корреспондентского счёта. Внешняя выписка с начальным/конечным остатком и правилами
банка ещё обязательна.

Risk gate: ручное решение approved/review/blocked и срок freshness 24h, отдельное
аудитируемое действие; re-check до создания, согласования, отправки, входящего
зачисления. Это технический контур для будущего поставщика KYC/AML, не автоматическое
прохождение санкционных, PEP, document/liveness или transaction-monitoring проверок.
Порог и политики не утверждены регулятором. Полная risk интеграция с внутренними
P2P, KYC идентификацией и реальными платёжными рельсами ещё требуется.
