"""Shared durable emergency stop. Fail closed for unknown money mutations.

Evidence ingestion, incident reporting and account freezing remain available.
This gate is not a network firewall and cannot retract already issued bank sends.
"""
from spyderpay_core.ledger import PaymentError

SAFE_WHILE_PAUSED=frozenset({'freeze','bank_risk','bank_evidence','bank_unknown','bank_case_open','bank_case_close','statement_ingest','statement_approve','dispatch_result','compliance_record','compliance_decide','chargeback_open','chargeback_decide'})


def require_open_for(conn,operation):
    if operation in SAFE_WHILE_PAUSED:return
    row=conn.execute('SELECT sp_gate_open() AS allowed').fetchone()
    if not row or row['allowed'] is not True:raise PaymentError('financial_traffic_paused',503)
