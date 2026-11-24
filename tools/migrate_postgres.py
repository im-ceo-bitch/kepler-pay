#!/usr/bin/env python3
"""Run on an isolated dev/staging database. Never migrate production without backup/change approval."""
from __future__ import annotations
import os
from pathlib import Path


def main():
    if os.getenv('SPYDERPAY_ENV') not in ('prelicense','test'):
        raise SystemExit('Refusing migration outside prelicense/test')
    dsn=os.getenv('SPYDERPAY_PG_DSN')
    if not dsn:raise SystemExit('SPYDERPAY_PG_DSN required')
    import psycopg
    sql=(Path(__file__).parents[1]/'spyderpay_core/postgres/migrations/001_core.sql').read_text()
    with psycopg.connect(dsn,autocommit=True) as conn:
        conn.execute(sql)
        result=conn.execute('SELECT max(version) FROM sp_schema_version').fetchone()[0]
    print(f'SpyderPay PostgreSQL schema version={result}')

if __name__=='__main__':main()
