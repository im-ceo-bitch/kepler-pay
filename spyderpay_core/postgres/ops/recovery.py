"""Read-only verification of an isolated restore. Never restores over a database.

A signed manifest binds the exact encrypted backup bytes to an externally trusted
Ed25519 key. The separate database check reports global counts and invariants.
Neither a signature nor these checks proves completeness against the source DB.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from spyderpay_core.release import SCHEMA_VERSION
from .snapshot_fingerprint import validate_fingerprints, fingerprint

DOMAIN=b'SPYDERPAY-BACKUP-MANIFEST-V1\x00'
SHA=re.compile(r'^[0-9a-f]{64}$')


def manifest_bytes(m):
    fields={'format','backup_id','sha256','size','schema','environment'}
    if not isinstance(m,dict) or type(m.get('format')) is not int or m['format'] not in (1,2,3):raise ValueError('invalid_backup_manifest')
    version=m['format']
    if set(m)!=(fields if version==1 else fields|{'counts'} if version==2 else fields|{'counts','fingerprints'}) or m['environment']!='prelicense' or not isinstance(m['backup_id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{12,96}',m['backup_id']) or not isinstance(m['sha256'],str) or not SHA.fullmatch(m['sha256']) or type(m['size']) is not int or m['size']<=0 or type(m['schema']) is not int or m['schema'] not in (2,3,4,5,6,7,8,9):raise ValueError('invalid_backup_manifest')
    if version>=2:
        if not isinstance(m['counts'],dict) or not classify_restore(m['schema'],m['counts'])['ok']:raise ValueError('invalid_backup_source_counts')
    if version==3:
        validate_fingerprints(m['fingerprints'])
        for label,table in {'accounts':'sp_accounts','journals':'sp_journals','postings':'sp_postings','intents':'sp_bank_intents','outbox':'sp_outbox','audit_events':'sp_audit_events'}.items():
            if m['counts'][label]!=m['fingerprints'][table]['rows']:
                raise ValueError('snapshot_count_mismatch')
    domain=DOMAIN if version==1 else b'SPYDERPAY-BACKUP-MANIFEST-V2\x00' if version==2 else b'SPYDERPAY-BACKUP-MANIFEST-V3\x00'
    return domain+json.dumps(m,sort_keys=True,separators=(',',':')).encode('ascii')


def compare_snapshot(manifest,restore):
    manifest_bytes(manifest)
    if manifest['format'] not in (2,3):raise ValueError('signed_snapshot_counts_required')
    if manifest['format']==3 and restore.get('fingerprints')!=manifest['fingerprints']:return False
    return bool(restore.get('ok') and restore.get('schema')==manifest['schema'] and restore.get('counts')==manifest['counts'])


def file_fingerprint(path):
    # Refuse links and non-regular inputs; no archive extraction.
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
    fd=os.open(path,flags)
    with os.fdopen(fd,'rb') as stream:
        initial=os.fstat(stream.fileno())
        if not stat.S_ISREG(initial.st_mode):raise ValueError('invalid_backup_file')
        h=hashlib.sha256();size=0
        while chunk:=stream.read(1024*1024):h.update(chunk);size+=len(chunk)
        final=os.fstat(stream.fileno())
        if initial.st_size!=size or final.st_size!=size or initial.st_mtime_ns!=final.st_mtime_ns or initial.st_ctime_ns!=final.st_ctime_ns:raise ValueError('backup_changed_during_read')
    return size,h.hexdigest()


def verify_backup(path,manifest,signature_b64,trusted_public_b64):
    msg=manifest_bytes(manifest)
    try:
        key=Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_public_b64,validate=True))
        key.verify(base64.b64decode(signature_b64,validate=True),msg)
    except (InvalidSignature,ValueError,TypeError):raise ValueError('invalid_backup_signature') from None
    size,digest=file_fingerprint(path)
    if size!=manifest['size'] or digest!=manifest['sha256']:raise ValueError('backup_integrity_failure')
    return {'verified':True,'backup_id':manifest['backup_id'],'schema':manifest['schema'],'size':size}


RESTORE_SQL='''SELECT
 (SELECT count(*) FROM sp_journals j LEFT JOIN (SELECT journal_id,count(*) n,sum(signed_amount) total FROM sp_postings GROUP BY journal_id) x ON x.journal_id=j.id WHERE NOT j.sealed OR coalesce(x.n,0)<2 OR coalesce(x.total,0)<>0) invalid_journals,
 (SELECT count(*) FROM sp_accounts a LEFT JOIN (SELECT account_id,sum(signed_amount) total FROM sp_postings GROUP BY account_id) x ON x.account_id=a.id WHERE a.balance<>coalesce(x.total,0) OR (a.kind<>'system' AND a.balance<0)) invalid_balances,
 (SELECT count(*) FROM sp_postings p JOIN sp_journals j ON j.id=p.journal_id JOIN sp_accounts a ON a.id=p.account_id WHERE a.tenant_id<>j.tenant_id OR a.currency<>p.currency OR j.currency<>p.currency) invalid_posting_scope,
 (SELECT count(*) FROM sp_bank_intents i LEFT JOIN sp_accounts a ON a.id=i.hold_account WHERE i.direction='withdrawal' AND ((i.state IN ('authorized','submitted','unknown') AND (a.id IS NULL OR a.balance<>i.amount)) OR (i.state IN ('settled','failed','cancelled') AND coalesce(a.balance,0)<>0))) invalid_holds,
 (SELECT count(*) FROM sp_refund_integrity WHERE NOT valid) invalid_fees,
 (SELECT count(*) FROM sp_chargebacks c JOIN sp_invoices i ON i.id=c.invoice_id LEFT JOIN sp_chargeback_decisions d ON d.case_id=c.id LEFT JOIN sp_chargeback_executions e ON e.case_id=c.id WHERE (i.state='refunded' AND d.decision IS DISTINCT FROM 'reject' AND e.case_id IS NULL) OR (e.case_id IS NOT NULL AND (d.decision IS DISTINCT FROM 'approve' OR i.state<>'refunded' OR e.journal_id IS DISTINCT FROM i.refund_journal))) invalid_chargebacks,
 (SELECT count(*) FROM sp_accounts) accounts,(SELECT count(*) FROM sp_journals) journals,(SELECT count(*) FROM sp_postings) postings,(SELECT count(*) FROM sp_bank_intents) intents,(SELECT count(*) FROM sp_outbox) outbox,(SELECT count(*) FROM sp_audit_events) audit_events'''


def classify_restore(schema,counts):
    required={'invalid_journals','invalid_balances','invalid_posting_scope','invalid_holds','invalid_fees','invalid_chargebacks','accounts','journals','postings','intents','outbox','audit_events'}
    if set(counts)!=required or any(type(v) is not int or v<0 for v in counts.values()):raise ValueError('invalid_restore_result')
    return {'schema':schema,'ok':schema==SCHEMA_VERSION and not any(v for k,v in counts.items() if k.startswith('invalid_')),'counts':counts,'real_money':False}


def inspect_restore(dsn, *, exact=False):
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(dsn,autocommit=True,row_factory=dict_row,connect_timeout=5,options='-c statement_timeout=120000 -c default_transaction_read_only=on') as conn,conn.transaction():
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        name=conn.execute('SELECT current_database() AS name').fetchone()['name']
        if not re.fullmatch(r'sp_restore_[a-z0-9_]{8,40}',name):raise ValueError('isolated_restore_database_required')
        schema=conn.execute('SELECT max(version) AS version FROM sp_schema_version').fetchone()['version']
        if schema!=SCHEMA_VERSION:raise ValueError('restore_schema_mismatch')
        result=classify_restore(schema,dict(conn.execute(RESTORE_SQL).fetchone()))
        if exact:
            result['fingerprints']=fingerprint(conn)
            seq=conn.execute('''SELECT
                (SELECT CASE WHEN is_called THEN last_value >= COALESCE((SELECT max(id) FROM sp_postings),0) ELSE last_value > COALESCE((SELECT max(id) FROM sp_postings),0) END FROM sp_postings_id_seq) AS postings,
                (SELECT CASE WHEN is_called THEN last_value >= COALESCE((SELECT max(id) FROM sp_audit_events),0) ELSE last_value > COALESCE((SELECT max(id) FROM sp_audit_events),0) END FROM sp_audit_events_id_seq) AS audit''').fetchone()
            result['sequences_ok']=bool(seq and all(v is True for v in seq.values()))
            result['ok']=result['ok'] and result['sequences_ok']
        return result


def main():
    if os.getenv('SPYDERPAY_ENV') not in ('test','prelicense'):raise SystemExit('Refusing non-prelicense environment')
    ap=argparse.ArgumentParser();sub=ap.add_subparsers(dest='command',required=True)
    v=sub.add_parser('verify');v.add_argument('backup');v.add_argument('manifest');v.add_argument('signature')
    inspect=sub.add_parser('inspect');inspect.add_argument('--manifest');inspect.add_argument('--backup');inspect.add_argument('--signature');a=ap.parse_args()
    if a.command=='verify':
        result=verify_backup(a.backup,json.loads(Path(a.manifest).read_text()),Path(a.signature).read_text().strip(),os.environ['SPYDERPAY_BACKUP_TRUSTED_PUBLIC_B64'])
    else:
        manifest=None
        if any((a.manifest,a.backup,a.signature)):
            if not all((a.manifest,a.backup,a.signature)):raise ValueError('all_snapshot_files_required')
            manifest=json.loads(Path(a.manifest).read_text())
            verify_backup(a.backup,manifest,Path(a.signature).read_text().strip(),os.environ['SPYDERPAY_BACKUP_TRUSTED_PUBLIC_B64'])
        result=inspect_restore(os.environ['SPYDERPAY_RESTORE_PG_DSN'],exact=bool(manifest and manifest['format']==3))
        if manifest:
            result['matches_signed_snapshot']=compare_snapshot(manifest,result)
            result['matches_signed_counts']=result['counts']==manifest.get('counts')
            result['ok']=result['ok'] and result['matches_signed_snapshot']
            result.pop('fingerprints',None)
            result['ok']=result['ok'] and result['matches_signed_counts']
    print(json.dumps(result,sort_keys=True));raise SystemExit(0 if result.get('verified') or result.get('ok') else 2)

if __name__=='__main__':main()
