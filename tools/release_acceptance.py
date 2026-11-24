"""Run pre-license acceptance suites and emit an explicit pass/fail report.
Never authorizes real money. PostgreSQL tests are destructive to their test DB;
only use a dedicated disposable isolated instance, never staging or production.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from spyderpay_core.release import VERSION

ROOT=Path(__file__).resolve().parents[1]


def run(label,argv,env):
    start=time.monotonic()
    try:
        done=subprocess.run(argv,cwd=ROOT,env=env,timeout=1200,stdout=sys.stderr,stderr=sys.stderr,check=False)
        return {'check':label,'status':'passed' if done.returncode==0 else 'failed','seconds':round(time.monotonic()-start,2),'exit':done.returncode}
    except (OSError,subprocess.TimeoutExpired):
        return {'check':label,'status':'unavailable_or_timed_out','seconds':round(time.monotonic()-start,2)}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--disposable-postgres',action='store_true',help='I explicitly confirm a dedicated disposable test database and server');a=p.parse_args()
    env={**os.environ,'SPYDERPAY_ENV':'test'};py=sys.executable
    results=[run('unit',[py,'-m','pytest','-q','tests','--ignore=tests/postgres'],env),run('protected_release_gates',[py,'-m','unittest','discover','-s','scripts/security_gate','-v'],env),run('merchant_sdk',['node','--test','integrations/merchant-sdk/merchant.test.mjs'],env),run('nginx_mtls',[py,'tools/edge_acceptance.py'],env),run('static_security',[py,'-m','bandit','-q','-r','spyderpay_core'],env),run('dependency_audit',[py,'-m','pip_audit','--local'],env)]
    if a.disposable_postgres:
        try:
            from psycopg.conninfo import conninfo_to_dict
            dsn=conninfo_to_dict(env['SPYDERPAY_TEST_PG_DSN'])
            # Name is an additional guard, not a proof of isolation. The explicit
            # operator flag confirms the server is disposable and separate.
            if dsn.get('dbname')!='spyderpay_test' or 'service' in dsn:raise ValueError()
        except (ImportError,KeyError,ValueError):results.append({'check':'postgres','status':'unsafe_or_missing_test_configuration'})
        else:
            import tempfile,xml.etree.ElementTree as ET
            with tempfile.TemporaryDirectory() as d:
                xml=Path(d)/'pg.xml';r=run('postgres',[py,'-m','pytest','-q','tests/postgres','--junitxml='+str(xml)],env)
                if r['status']=='passed':
                    suites=ET.parse(xml).getroot().findall('testsuite')
                    if sum(int(s.attrib.get('tests',0)) for s in suites)<90 or any(int(s.attrib.get('skipped',0)) for s in suites):r['status']='incomplete'
                results.append(r)
    else:results.append({'check':'postgres','status':'not_run'})
    external=['real_IdP_MFA','managed_KMS_HSM_and_rotation','hardware_card_and_mobile_POS','target_load_failover_PITR','WAF_DDoS_SIEM_deployment','independent_security_assessment','bank_and_AML_partner_certification','regulatory_approval']
    ok=all(x['status']=='passed' for x in results)
    print(json.dumps({'version':VERSION,'automated_checks':results,'automated_checks_passed':ok,'external_acceptance_required':external,'real_money_enabled':False,'commercial_production_approved':False},sort_keys=True,indent=2))
    raise SystemExit(0 if ok else 2)

if __name__=='__main__':main()
