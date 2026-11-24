"""Versioned migrations, serialized across cooperating migration runners."""
from pathlib import Path


def migrate(dsn: str) -> int:
    import psycopg
    root = Path(__file__).parent / 'migrations'
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute('SELECT pg_advisory_lock(8421778102)')
        try:
            exists = conn.execute("SELECT to_regclass('sp_schema_version') IS NOT NULL").fetchone()[0]
            version = conn.execute('SELECT coalesce(max(version),0) FROM sp_schema_version').fetchone()[0] if exists else 0
            if version not in (0, 2, 3, 4, 5, 6, 7, 8, 9):
                raise RuntimeError('unsupported_schema_version')
            for target, name in ((2, '001_core.sql'), (3, '002_security.sql'), (4, '003_banking.sql'), (5, '004_compliance_clearing.sql'), (6, '005_rail_dispatch.sql'), (7, '006_financial_controls.sql'), (8, '007_amount_refunds.sql'), (9, '008_card_proofs.sql')):
                if version < target:
                    conn.execute((root / name).read_text())
                    version = conn.execute('SELECT max(version) FROM sp_schema_version').fetchone()[0]
                    if version != target:
                        raise RuntimeError('migration_version_mismatch')
            return version
        finally:
            # Failed multi-statement migration may leave an aborted transaction.
            conn.rollback()
            conn.execute('SELECT pg_advisory_unlock(8421778102)')
