"""Reliable outbox lifecycle with leased deliveries (at-least-once semantics).

No outgoing network calls here. Integrators implement a validated signed webhook transport.
Consumers MUST deduplicate by event ID; retry can cause duplicate delivery.
"""
from __future__ import annotations
import uuid
from datetime import datetime,timedelta,timezone
from spyderpay_core.ledger import PaymentError
from .store import Principal, PgProcessor, _jsonable


class Outbox:
    MAX_ATTEMPTS = 25  # Undelivered events must be escalated, never discarded.
    def __init__(self,processor: PgProcessor):self.processor=processor

    def claim(self,p:Principal,limit:int=25,seconds:int=30)->list[dict]:
        p.require('ops')
        if type(limit) is not int or not (1<=limit<=100) or type(seconds) is not int or not (10<=seconds<=300):
            raise PaymentError('invalid_lease',422)
        with self.processor._connect() as conn:
            with conn.transaction():
                records=conn.execute('''SELECT id,event_type,aggregate_id,payload,attempts
                    FROM sp_outbox WHERE tenant_id=%s AND delivered_at IS NULL AND next_attempt_at<=now()
                    AND (leased_until IS NULL OR leased_until<=now()) AND attempts < 25
                    ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT %s''',(p.tenant_id,limit)).fetchall()
                result=[]
                for item in records:
                    token=str(uuid.uuid4())
                    conn.execute('''UPDATE sp_outbox SET lease_token=%s,leased_until=now()+(%s * interval '1 second'),
                        attempts=attempts+1 WHERE id=%s''',(token,seconds,item['id']))
                    result.append({**_jsonable(item),'lease_token':token})
                return result

    def ack(self,p:Principal,event_id:str,lease_token:str)->bool:
        p.require('ops')
        try:uid=str(uuid.UUID(event_id));tok=str(uuid.UUID(lease_token))
        except (ValueError,TypeError):raise PaymentError('invalid_lease_id',422) from None
        with self.processor._connect() as conn:
            with conn.transaction():
                row=conn.execute('''UPDATE sp_outbox SET delivered_at=now(),leased_until=NULL,lease_token=NULL
                  WHERE id=%s AND lease_token=%s AND tenant_id=%s AND delivered_at IS NULL
                  AND leased_until>now() RETURNING id''',(uid,tok,p.tenant_id)).fetchone()
                return row is not None

    def retry(self,p:Principal,event_id:str,lease_token:str,after_seconds:int=30)->bool:
        p.require('ops')
        if type(after_seconds) is not int or not (1<=after_seconds<=3600):
            raise PaymentError('invalid_retry',422)
        try:uid=str(uuid.UUID(event_id));tok=str(uuid.UUID(lease_token))
        except (ValueError,TypeError):raise PaymentError('invalid_lease_id',422) from None
        with self.processor._connect() as conn:
            with conn.transaction():
                row=conn.execute('''UPDATE sp_outbox SET leased_until=NULL,lease_token=NULL,
                  next_attempt_at=now()+(%s * interval '1 second')
                  WHERE id=%s AND lease_token=%s AND tenant_id=%s AND delivered_at IS NULL RETURNING id''',
                  (after_seconds,uid,tok,p.tenant_id)).fetchone()
                return row is not None
