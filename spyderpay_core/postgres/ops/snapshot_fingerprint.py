"""Exact logical row digests for the schema-9 financial database.
Run in the SAME repeatable-read transaction as the exported backup snapshot.
No row values are returned or logged. Schema definitions/ACLs and sequences
are separate restore checks; a digest is not a replacement for WAL/PITR.
"""
import hashlib
import re

TABLES = tuple(sorted('''sp_schema_version sp_accounts sp_journals sp_postings sp_idempotency
sp_invoices sp_outbox sp_audit_events sp_api_replay sp_rate_windows sp_bank_inbox
sp_identity_members sp_revoked_sessions sp_payment_approvals sp_bank_risk sp_bank_intents
sp_bank_evidence sp_bank_evidence_use sp_bank_cases sp_compliance_reviews sp_compliance_decisions
sp_statement_batches sp_statement_rows sp_statement_approvals sp_bank_consents sp_rail_dispatch
sp_rail_dispatch_result sp_fee_schedules sp_fee_approvals sp_invoice_fees sp_fee_movements
sp_chargebacks sp_chargeback_decisions sp_chargeback_executions sp_amount_refunds sp_cards
sp_card_challenges sp_runtime_gate sp_gate_events sp_gate_resume_requests'''.split()))
HEX = re.compile(r'[0-9a-f]{64}')


def row_digest(table, rows):
    if table not in TABLES:
        raise ValueError('unknown_snapshot_table')
    h = hashlib.sha256(b'SPYDERPAY-ROW-SNAPSHOT-V1\0' + table.encode('ascii') + b'\0')
    count = 0
    for row in rows:
        if not isinstance(row, str):
            raise ValueError('invalid_snapshot_row')
        data = row.encode('utf-8')
        h.update(len(data).to_bytes(8, 'big'))
        h.update(data)
        count += 1
    return {'rows': count, 'sha256': h.hexdigest()}


def validate_fingerprints(value):
    if not isinstance(value, dict) or set(value) != set(TABLES):
        raise ValueError('invalid_snapshot_tables')
    for entry in value.values():
        if (not isinstance(entry, dict) or set(entry) != {'rows', 'sha256'} or
                type(entry['rows']) is not int or entry['rows'] < 0 or
                not isinstance(entry['sha256'], str) or not HEX.fullmatch(entry['sha256'])):
            raise ValueError('invalid_snapshot_fingerprint')
    return value


def fingerprint(conn):
    from psycopg import sql
    conn.execute("SET LOCAL TimeZone TO 'UTC'")
    conn.execute("SET LOCAL DateStyle TO 'ISO, YMD'")
    conn.execute("SET LOCAL IntervalStyle TO 'postgres'")
    conn.execute("SET LOCAL bytea_output TO 'hex'")
    # Fail closed if a migration introduces a table not covered by this release.
    found = conn.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n
        ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p')
        AND left(c.relname,3)='sp_'""").fetchall()
    if {r['relname'] for r in found} != set(TABLES):
        raise ValueError('snapshot_schema_table_mismatch')
    result = {}
    for index, table in enumerate(TABLES):
        # Identifier is quoted using psycopg, never supplied by a caller.
        query = sql.SQL('SELECT to_jsonb(t)::text AS value FROM {}.{} t ORDER BY (to_jsonb(t)::text) COLLATE "C"').format(sql.Identifier('public'), sql.Identifier(table))
        with conn.cursor(name=f'sp_digest_{index}') as cur:
            cur.itersize = 256
            cur.execute(query)
            result[table] = row_digest(table, (r['value'] for r in cur))
    return validate_fingerprints(result)
