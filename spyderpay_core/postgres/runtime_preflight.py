"""Fail startup on missing required runtime privileges or unsafe DB ownership."""
from spyderpay_core.release import SCHEMA_VERSION

READ_TABLES=(
    'sp_schema_version','sp_accounts','sp_journals','sp_postings','sp_invoices',
    'sp_idempotency','sp_outbox','sp_audit_events','sp_api_replay','sp_rate_windows',
    'sp_payment_approvals','sp_revoked_sessions','sp_bank_risk','sp_bank_intents',
    'sp_bank_evidence','sp_bank_evidence_use','sp_bank_cases','sp_compliance_reviews',
    'sp_compliance_decisions','sp_statement_batches','sp_statement_rows',
    'sp_statement_approvals','sp_bank_consents','sp_rail_dispatch','sp_rail_dispatch_result',
    'sp_fee_schedules','sp_fee_approvals','sp_invoice_fees','sp_fee_movements','sp_chargebacks','sp_chargeback_decisions','sp_chargeback_executions','sp_amount_refunds','sp_refund_integrity','sp_cards','sp_card_challenges','sp_runtime_gate',
)
REQUIRED_WRITE=(
    ('sp_accounts','balance','UPDATE'),('sp_journals','sealed','UPDATE'),
    ('sp_postings','signed_amount','INSERT'),('sp_idempotency','result','UPDATE'),
    ('sp_outbox','lease_token','UPDATE'),('sp_api_replay','nonce','INSERT'),
    ('sp_payment_approvals','consumed_at','UPDATE'),('sp_bank_intents','state','UPDATE'),
    ('sp_bank_evidence','provider_ref','INSERT'),('sp_bank_evidence_use','intent_id','INSERT'),
    ('sp_compliance_reviews','evidence_ref','INSERT'),('sp_statement_approvals','reviewer','INSERT'),
    ('sp_bank_consents','consent_ref','INSERT'),('sp_rail_dispatch','request_ref','INSERT'),
    ('sp_rail_dispatch_result','outcome','INSERT'),
    ('sp_fee_schedules','bps','INSERT'),('sp_fee_approvals','reviewer','INSERT'),('sp_invoice_fees','amount','INSERT'),('sp_fee_movements','journal_id','INSERT'),
    ('sp_chargebacks','reason','INSERT'),('sp_chargeback_decisions','decision','INSERT'),('sp_chargeback_executions','journal_id','INSERT'),('sp_amount_refunds','journal_id','INSERT'),('sp_cards','public_key','INSERT'),('sp_cards','revoked_at','UPDATE'),('sp_card_challenges','nonce','INSERT'),('sp_card_challenges','consumed_at','UPDATE'),
)
FINANCIAL_TABLES=tuple(t for t in READ_TABLES if t not in ('sp_api_replay','sp_rate_windows'))

def check_runtime(conn):
    version=conn.execute('SELECT max(version) AS version FROM sp_schema_version').fetchone()['version']
    if version!=SCHEMA_VERSION:raise RuntimeError('schema_not_ready')
    flags=conn.execute('''SELECT r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolbypassrls,r.rolreplication,
        has_schema_privilege(current_user,'public','CREATE') AS public_create,
        EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(%s) AND pg_has_role(current_user,c.relowner,'MEMBER')) AS owns_financial_table
        FROM pg_roles r WHERE r.rolname=current_user''',(list(FINANCIAL_TABLES),)).fetchone()
    if not flags or any(flags.values()):raise RuntimeError('unsafe_database_runtime_role')
    for name in READ_TABLES:
        if not conn.execute("SELECT has_table_privilege(current_user,%s,'SELECT') AS ok",(name,)).fetchone()['ok']:
            raise RuntimeError('missing_runtime_read:'+name)
    for table,column,privilege in REQUIRED_WRITE:
        if not conn.execute('SELECT has_column_privilege(current_user,%s,%s,%s) AS ok',(table,column,privilege)).fetchone()['ok']:
            raise RuntimeError('missing_runtime_write:'+table+':'+column)
    for name in FINANCIAL_TABLES:
        row=conn.execute("SELECT has_table_privilege(current_user,%s,'TRUNCATE') OR has_table_privilege(current_user,%s,'DELETE') AS unsafe",(name,name)).fetchone()
        if row['unsafe']:raise RuntimeError('unsafe_runtime_delete:'+name)
    if conn.execute("SELECT has_column_privilege(current_user,'sp_identity_members','enabled','UPDATE') OR has_table_privilege(current_user,'sp_revoked_sessions','INSERT') OR NOT has_function_privilege(current_user,'sp_lock_member(text,text)','EXECUTE') AS unsafe").fetchone()['unsafe']:
        raise RuntimeError('unsafe_identity_runtime_permissions')

    gate=conn.execute("""SELECT has_function_privilege(current_user,'sp_gate_open()','EXECUTE') AS can_read,
        has_function_privilege(current_user,'sp_gate_pause(text)','EXECUTE') OR
        has_function_privilege(current_user,'sp_gate_propose_resume(text)','EXECUTE') OR
        has_function_privilege(current_user,'sp_gate_confirm_resume(uuid,text)','EXECUTE') OR
        has_table_privilege(current_user,'sp_runtime_gate','UPDATE') OR
        has_column_privilege(current_user,'sp_runtime_gate','paused','UPDATE') OR
        has_column_privilege(current_user,'sp_runtime_gate','generation','UPDATE') OR
        has_table_privilege(current_user,'sp_runtime_gate','INSERT') AS unsafe""").fetchone()
    if not gate['can_read'] or gate['unsafe']:raise RuntimeError('unsafe_runtime_gate_permissions')
