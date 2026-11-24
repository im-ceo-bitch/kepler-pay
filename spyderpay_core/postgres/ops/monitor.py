"""Least-privilege signed health poller. Outputs only bounded operational counts.
Dedicated monitor role, independently provisioned mTLS credentials, no writes.
The external log forwarder and alert receiver must be deployed separately.
"""
import base64
import http.client
import json
import os
import secrets
import ssl
import time
from urllib.parse import urlsplit
from spyderpay_core.release import SCHEMA_VERSION, VERSION
from ..auth import KEY_ID
from ..service_v3 import sign_v3
from ..operations import classify_snapshot
from ..remote_signer import read_secret

PATH='/v3/ops/health'
FIELDS={'invalid_journals','invalid_balances','invalid_holds','invalid_posting_scope','invalid_fees','invalid_chargebacks','stale_bank_intents','stale_outbox','stale_statements','stale_dispatch','exhausted_outbox','conflicting_bank_evidence','unmatched_bank_evidence','stale_chargebacks'}


def headers(kid,secret,stamp=None,nonce=None):
    if not isinstance(kid,str) or not KEY_ID.fullmatch(kid) or not isinstance(secret,bytes) or not 32<=len(secret)<=128:
        raise ValueError('invalid_monitor_credentials')
    stamp=str(int(time.time())) if stamp is None else str(stamp)
    nonce=secrets.token_urlsafe(24) if nonce is None else nonce
    return {'Accept':'application/json','X-Spyder-Key-Id':kid,'X-Spyder-Timestamp':stamp,'X-Spyder-Nonce':nonce,'X-Spyder-Signature':sign_v3(secret,kid,'GET',PATH,b'',stamp,nonce)}


def validate_report(report):
    if not isinstance(report,dict) or set(report)!={'version','schema','status','counts','real_money','financial_traffic_paused','gate_generation'}:
        raise ValueError('invalid_monitor_report')
    if report['real_money'] is not False or report['version']!=VERSION or report['schema']!=SCHEMA_VERSION or type(report['financial_traffic_paused']) is not bool or type(report['gate_generation']) is not int or report['gate_generation']<0:
        raise ValueError('invalid_monitor_context')
    counts=report['counts']
    if not isinstance(counts,dict) or set(counts)!=FIELDS or any(type(v) is not int or not 0<=v<=2**63-1 for v in counts.values()):
        raise ValueError('invalid_monitor_counts')
    severity=classify_snapshot(report['schema'],counts)['status']
    if severity!=report['status']:raise ValueError('inconsistent_monitor_status')
    return {'event':'spyderpay.health','severity':'critical' if report['financial_traffic_paused'] else severity,'counts':counts,'gate_generation':report['gate_generation'],'financial_traffic_paused':report['financial_traffic_paused'],'version':VERSION,'schema':SCHEMA_VERSION,'real_money':False}


def poll(origin,kid,secret,ca,certificate,key,transport=http.client.HTTPSConnection):
    u=urlsplit(origin)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:raise ValueError('invalid_monitor_origin')
    ctx=ssl.create_default_context(cafile=ca);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(certificate,key)
    conn=transport(u.hostname,u.port or 443,timeout=8,context=ctx)
    try:
        conn.request('GET',PATH,headers=headers(kid,secret));r=conn.getresponse()
        if r.status!=200:raise RuntimeError('monitor_http_failure')
        data=r.read(16385)
        if len(data)>16384:raise ValueError('monitor_response_too_large')
        return validate_report(json.loads(data))
    finally:conn.close()


def main():
    if os.getenv('SPYDERPAY_ENV')!='prelicense':raise SystemExit('Prelicense only')
    try:
        secret=base64.b64decode(read_secret(os.environ['SPYDERPAY_MONITOR_SECRET_FILE']),validate=True)
        result=poll(os.environ['SPYDERPAY_MONITOR_ORIGIN'],os.environ['SPYDERPAY_MONITOR_KEY_ID'],secret,os.environ['SPYDERPAY_MONITOR_CA'],os.environ['SPYDERPAY_MONITOR_CERT'],os.environ['SPYDERPAY_MONITOR_KEY'])
    except Exception:
        # Do not expose URLs, TLS/key paths, secrets or payloads in logs.
        result={'event':'spyderpay.health','severity':'critical','reason':'monitor_unavailable_or_invalid','real_money':False}
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if result['severity']=='ok' else 2)

if __name__=='__main__':main()
