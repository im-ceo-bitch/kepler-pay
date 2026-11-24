# SpyderPay Bank Rail — интеграционная граница

Код `spyderpay_core/postgres/rail_contract.py` задаёт типизированную инструкцию,
стабильный idempotency reference, hash неизменных параметров, состояния dispatch и
правило восстановления. `sandbox_reference` детерминированный локальный reference.
Не предоставляет сетевой транспорт. Никакие live API credentials не нужны.

## Обязательное приложение к договору с банком

* Согласовать юридический тип счёта, держателя денег, атомарность и момент finality.
* Получить API спецификацию, sandbox credentials, правила idempotency, settlement
  windows, статусы и callback signature, signed statement format и SLA.
* Адаптер должен хранить dispatch reference **до** network call в durable outbox,
  возвращать unknown при неоднозначном результате, искать статус по исходному
  reference. Не повторять денежное поручение с новым reference.
* Нормализовать callback и statement независимо, проверять ключи, подпись, replay,
  tenant/routing ownership, account mapping, дату, валюту, комиссии, сумму и статус.
* Не создавать credits из callback. Сопоставлять подтверждённое движение и
  выписку, сверять opening/closing balances. Не удалять конфликтующие события.
* Предусмотреть проверку исходного consent, KYC/AML, transaction limits, sanctions,
  merchant onboarding, возвратов, partial refunds, chargeback и dispute SLA.
* Провести негативные сценарии, повторные/переставленные события, crash между
  commit и отправкой, outage, unknown, отмену до/после cut-off, mismatch и DR.

Для каждого банка отдельный адаптер, отдельная сертификация, мTLS/PKI/KMS и
операционные полномочия. Ключи API/DB не в мобильном кошельке. Режим production не
добавлять до прохождения внешних gates. Сейчас реальные каналы не подключены.
