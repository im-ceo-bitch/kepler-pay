#!/usr/bin/env python3
import os
from spyderpay_core.postgres.migrate import migrate

if __name__ == '__main__':
    if os.getenv('SPYDERPAY_ENV') not in ('prelicense','test'):
        raise SystemExit('Refusing migration outside prelicense/test')
    dsn = os.getenv('SPYDERPAY_PG_DSN')
    if not dsn:
        raise SystemExit('SPYDERPAY_PG_DSN required')
    print(f'SpyderPay PostgreSQL schema version={migrate(dsn)}')
