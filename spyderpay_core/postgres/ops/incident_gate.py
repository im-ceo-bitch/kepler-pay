"""Emergency control plane; run only using separate named incident logins."""
import argparse
import os
import re
import uuid


def main():
    if os.getenv('SPYDERPAY_ENV') not in ('test','prelicense'):raise SystemExit('prelicense only')
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['pause','propose-resume','confirm-resume']);parser.add_argument('incident_ref');parser.add_argument('--request-id')
    a=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{6,96}',a.incident_ref):parser.error('invalid incident reference')
    import psycopg
    with psycopg.connect(os.environ['SPYDERPAY_INCIDENT_DSN'],connect_timeout=5,options='-c statement_timeout=30000 -c lock_timeout=25000') as c:
        if a.action=='pause':result=c.execute('SELECT sp_gate_pause(%s)',(a.incident_ref,)).fetchone()[0]
        elif a.action=='propose-resume':result=c.execute('SELECT sp_gate_propose_resume(%s)',(a.incident_ref,)).fetchone()[0]
        else:
            if not a.request_id:parser.error('request ID required')
            result=c.execute('SELECT sp_gate_confirm_resume(%s,%s)',(uuid.UUID(a.request_id),a.incident_ref)).fetchone()[0]
    print(result)

if __name__=='__main__':main()
