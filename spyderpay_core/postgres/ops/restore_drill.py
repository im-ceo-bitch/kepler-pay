"""Operator-initiated restore drill into a dedicated EMPTY pre-license database.
Never drops, creates, cleans or restores over an existing financial database.
Requires operator-provisioned age identity, trusted backup key, TLS service and
an isolated restore server. Does not implement WAL/PITR or production failover.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess  # nosec B404 -- fixed command and validated operator inputs
import tempfile
import time
from .backup import SERVICE
from .recovery import verify_backup, inspect_restore, compare_snapshot
from spyderpay_core.release import SCHEMA_VERSION

NAME=re.compile(r'sp_restore_[a-z0-9_]{8,40}')


def target(service, database):
    if not isinstance(service,str) or not SERVICE.fullmatch(service) or not isinstance(database,str) or not NAME.fullmatch(database):
        raise ValueError('isolated_restore_target_required')
    return f'service={service} dbname={database} sslmode=verify-full gssencmode=disable connect_timeout=5'


def private_file(value):
    p=Path(value)
    st=p.lstat()
    if not p.is_absolute() or not stat.S_ISREG(st.st_mode) or st.st_mode&0o077 or st.st_uid!=os.getuid():raise ValueError('private_operator_file_required')
    return str(p)


def validate_empty(row,database):
    if row['name']!=database or row['superuser'] or row['relations'] or row['routines'] or row['extra_schemas'] or row['recovery'] or not row['owner']:
        raise ValueError('restore_target_not_empty_or_not_isolated')


def inspect_empty(dsn,database):
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(dsn,connect_timeout=5,row_factory=dict_row) as conn:
        row=conn.execute('''SELECT current_database() AS name, pg_is_in_recovery() AS recovery,
        (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS superuser,
        (SELECT d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_database d WHERE d.datname=current_database()) AS owner,
        (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AS relations,
        (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public') AS routines,
        (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','information_schema','pg_catalog','pg_toast') AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%') AS extra_schemas''').fetchone()
        validate_empty(row,database)


def copy_verified(source,dest,manifest,signature,trusted):
    # Freeze verified ciphertext in a private directory before giving it to age.
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as src,dest.open('xb') as out:
        if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):raise ValueError('invalid_backup_file')
        os.fchmod(out.fileno(),0o600)
        remaining=manifest['size']
        while remaining:
            chunk=src.read(min(1024*1024,remaining))
            if not chunk:raise ValueError('backup_truncated')
            out.write(chunk);remaining-=len(chunk)
        if src.read(1):raise ValueError('backup_size_mismatch')
    verify_backup(dest,manifest,signature,trusted)


def restore_ciphertext(path,identity,dsn,env):
    # No shell, no plaintext file, no --clean, --create or --disable-triggers.
    decrypt=['/usr/bin/age','--decrypt','--identity',identity,str(path)]
    restore=['/usr/bin/pg_restore','--format=custom','--exit-on-error','--single-transaction','--no-owner','--no-privileges','--no-password','--dbname='+dsn]
    a=subprocess.Popen(decrypt,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C'})  # nosec B603
    b=None
    try:
        b=subprocess.Popen(restore,stdin=a.stdout,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)  # nosec B603
        a.stdout.close()
        if b.wait(timeout=3600)!=0 or a.wait(timeout=30)!=0:raise RuntimeError('restore_pipeline_failed_discard_target')
    finally:
        if a.stdout and not a.stdout.closed:a.stdout.close()
        for proc in (b,a):
            if proc is not None and proc.poll() is None:proc.kill();proc.wait()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('backup_directory');p.add_argument('--service',required=True);p.add_argument('--database',required=True)
    p.add_argument('--confirm-isolated-empty-target',action='store_true',required=True)
    args=p.parse_args()
    if os.getenv('SPYDERPAY_ENV')!='prelicense':raise SystemExit('prelicense_only')
    dsn=target(args.service,args.database)
    env={'PATH':'/usr/bin:/bin','LANG':'C','PGSERVICEFILE':private_file(os.environ['PGSERVICEFILE']),'PGPASSFILE':private_file(os.environ['PGPASSFILE']),'PGSSLMODE':'verify-full','PGGSSENCMODE':'disable'}
    # psycopg and pg_restore must resolve the exact same libpq config. Reject
    # environment variables that could make them connect to different servers.
    for k in tuple(os.environ):
        if k.startswith('PG') and k not in ('PGSERVICEFILE','PGPASSFILE','PGSSLMODE','PGGSSENCMODE'):raise ValueError('ambiguous_libpq_environment')
    identity=private_file(os.environ['SPYDERPAY_RESTORE_AGE_IDENTITY'])
    trusted=os.environ['SPYDERPAY_BACKUP_TRUSTED_PUBLIC_B64'];root=Path(args.backup_directory)
    manifest=json.loads((root/'manifest.json').read_text());signature=(root/'signature.txt').read_text().strip()
    if manifest.get('format')!=3 or manifest.get('schema')!=SCHEMA_VERSION:raise ValueError('exact_current_schema_snapshot_required')
    started=time.monotonic()
    verify_backup(root/'database.dump.age',manifest,signature,trusted)
    with tempfile.TemporaryDirectory(prefix='spyderpay-restore-') as tmp:
        ciphertext=Path(tmp)/'backup.age';copy_verified(root/'database.dump.age',ciphertext,manifest,signature,trusted)
        inspect_empty(dsn,args.database)
        restore_ciphertext(ciphertext,identity,dsn,env)
    result=inspect_restore(dsn,exact=True)
    ok=compare_snapshot(manifest,result)
    print(json.dumps({'backup_id':manifest['backup_id'],'database':args.database,'exact_snapshot_match':ok,'seconds':round(time.monotonic()-started,3),'real_money':False,'ok':ok},sort_keys=True))
    raise SystemExit(0 if ok else 2)

if __name__=='__main__':main()
