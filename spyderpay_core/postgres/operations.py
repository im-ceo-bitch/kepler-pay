"""Internal operational snapshot. Counts only, no PII or payment details."""
from spyderpay_core.release import SCHEMA_VERSION,VERSION
from spyderpay_core.ledger import PaymentError

def operational_snapshot(processor,p):
    if p.identity is not None or p.roles not in (frozenset({'ops'}),frozenset({'monitor'})):
        raise PaymentError('monitor_service_role_required',403)
    with processor._connect() as conn,conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        schema=conn.execute('SELECT max(version) AS version FROM sp_schema_version').fetchone()['version']
        counts=conn.execute('''SELECT
          (SELECT count(*) FROM sp_journals j LEFT JOIN (SELECT journal_id,count(*) n,sum(signed_amount) total FROM sp_postings GROUP BY journal_id) x ON x.journal_id=j.id WHERE j.tenant_id=%s AND (NOT j.sealed OR coalesce(x.n,0)<2 OR coalesce(x.total,0)<>0)) AS invalid_journals,
          (SELECT count(*) FROM sp_accounts a LEFT JOIN (SELECT account_id,sum(signed_amount) total FROM sp_postings GROUP BY account_id) x ON x.account_id=a.id WHERE a.tenant_id=%s AND (a.balance<>coalesce(x.total,0) OR (a.kind<>'system' AND a.balance<0))) AS invalid_balances,
          (SELECT count(*) FROM sp_bank_intents i LEFT JOIN sp_accounts a ON a.id=i.hold_account WHERE i.tenant_id=%s AND i.direction='withdrawal' AND ((i.state IN ('authorized','submitted','unknown') AND (a.id IS NULL OR a.tenant_id<>i.tenant_id OR a.balance<>i.amount)) OR (i.state IN ('settled','failed','cancelled') AND coalesce(a.balance,0)<>0))) AS invalid_holds,
          (SELECT count(*) FROM sp_postings p JOIN sp_journals j ON j.id=p.journal_id JOIN sp_accounts a ON a.id=p.account_id WHERE j.tenant_id=%s AND (a.tenant_id<>j.tenant_id OR a.currency<>p.currency OR j.currency<>p.currency)) AS invalid_posting_scope,
          (SELECT count(*) FROM sp_bank_intents WHERE tenant_id=%s AND state IN ('submitted','unknown') AND updated_at<now()-interval '30 minutes') AS stale_bank_intents,
          (SELECT count(*) FROM sp_outbox WHERE tenant_id=%s AND delivered_at IS NULL AND created_at<now()-interval '5 minutes') AS stale_outbox,
          (SELECT count(*) FROM sp_statement_batches b LEFT JOIN sp_statement_approvals a ON a.batch_id=b.id WHERE b.tenant_id=%s AND a.batch_id IS NULL AND b.created_at<now()-interval '30 minutes') AS stale_statements,
          (SELECT count(*) FROM sp_rail_dispatch d JOIN sp_bank_intents i ON i.id=d.intent_id LEFT JOIN sp_rail_dispatch_result r ON r.intent_id=d.intent_id WHERE d.tenant_id=%s AND i.state IN ('submitted','unknown') AND r.intent_id IS NULL AND d.created_at<now()-interval '2 minutes') AS stale_dispatch,
          (SELECT count(*) FROM sp_outbox WHERE tenant_id=%s AND delivered_at IS NULL AND attempts>=25) AS exhausted_outbox,
          (SELECT count(DISTINCT i.id) FROM sp_bank_intents i JOIN sp_bank_evidence e ON e.tenant_id=i.tenant_id AND e.provider=i.provider AND e.provider_ref=i.provider_ref WHERE i.tenant_id=%s AND (e.amount<>i.amount OR e.direction<>i.direction OR e.beneficiary_ref<>i.beneficiary_ref OR (i.state IN ('settled','failed') AND e.status<>i.state))) AS conflicting_bank_evidence,
          (SELECT count(*) FROM sp_bank_evidence e LEFT JOIN sp_bank_intents i ON i.tenant_id=e.tenant_id AND i.provider=e.provider AND i.provider_ref=e.provider_ref WHERE e.tenant_id=%s AND i.id IS NULL) AS unmatched_bank_evidence,
          (SELECT count(*) FROM sp_refund_integrity WHERE tenant_id=%s AND NOT valid) AS invalid_fees,
          (SELECT count(*) FROM sp_chargebacks c JOIN sp_invoices i ON i.id=c.invoice_id LEFT JOIN sp_chargeback_decisions d ON d.case_id=c.id LEFT JOIN sp_chargeback_executions e ON e.case_id=c.id WHERE c.tenant_id=%s AND ((i.state='refunded' AND d.decision IS DISTINCT FROM 'reject' AND e.case_id IS NULL) OR (e.case_id IS NOT NULL AND (d.decision IS DISTINCT FROM 'approve' OR i.state<>'refunded' OR e.journal_id IS DISTINCT FROM i.refund_journal)))) AS invalid_chargebacks,
          (SELECT count(*) FROM sp_chargebacks c LEFT JOIN sp_chargeback_decisions d ON d.case_id=c.id LEFT JOIN sp_chargeback_executions e ON e.case_id=c.id WHERE c.tenant_id=%s AND d.decision IS DISTINCT FROM 'reject' AND e.case_id IS NULL AND c.created_at<now()-interval '24 hours') AS stale_chargebacks''',(p.tenant_id,)*14).fetchone()
        result=classify_snapshot(schema,dict(counts))
        gate=conn.execute('SELECT paused,generation FROM sp_runtime_gate WHERE singleton').fetchone()
        if not gate:raise RuntimeError('runtime_gate_missing')
        return {**result,'financial_traffic_paused':gate['paused'],'gate_generation':gate['generation']}

def classify_snapshot(schema,counts):
    integrity=('invalid_journals','invalid_balances','invalid_holds','invalid_posting_scope','invalid_fees','invalid_chargebacks')
    backlog=('stale_bank_intents','stale_outbox','stale_statements','stale_dispatch','exhausted_outbox','conflicting_bank_evidence','unmatched_bank_evidence','stale_chargebacks')
    # A critical integrity fault takes precedence over a queue warning.
    critical=schema!=SCHEMA_VERSION or any(counts.get(k,0) for k in integrity)
    return {'version':VERSION,'schema':schema,'status':'critical' if critical else 'degraded' if any(counts.get(k,0) for k in backlog) else 'ok','counts':counts,'real_money':False}
