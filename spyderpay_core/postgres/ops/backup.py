"""Encrypted PostgreSQL logical backup with external signing and atomic publication.

Pre-license only. Requires trusted pg_dump/age binaries and a dedicated backup role.
Does not configure WAL/PITR, object storage, retention or production restore.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess  # nosec B404 -- fixed argv, no shell, trusted operator configuration
import tempfile
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from spyderpay_core.release import SCHEMA_VERSION
from ..remote_signer import VaultTransitSigner
from .recovery import file_fingerprint,manifest_bytes,verify_backup,RESTORE_SQL,classify_restore

from .snapshot_fingerprint import fingerprint, validate_fingerprints

AGE_RECIPIENT=re.compile(r'age1[023456789acdefghjklmnpqrstuvwxyz]{58}')
SERVICE=re.compile(r'[A-Za-z0-9_-]{1,64}')
SNAPSHOT=re.compile(r'[0-9A-Fa-f-]{8,128}')


def _sync_file(path,data):
    with path.open('xb') as f:
        os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())


def encrypted_dump(destination,service,snapshot,recipient,*,env):
    if not SERVICE.fullmatch(service) or not SNAPSHOT.fullmatch(snapshot) or not AGE_RECIPIENT.fullmatch(recipient):raise ValueError('invalid_backup_arguments')
    # Explicit env from operator-controlled service and passfiles; never put passwords on argv.
    dump=['/usr/bin/pg_dump','--format=custom','--no-password','--no-owner','--no-acl','--snapshot='+snapshot,'--dbname=service='+service+' sslmode=verify-full gssencmode=disable']
    encrypt=['/usr/bin/age','--encrypt','--recipient',recipient]
    with destination.open('xb') as out:
        first=subprocess.Popen(dump,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env)  # nosec B603
        second=None
        try:
            second=subprocess.Popen(encrypt,stdin=first.stdout,stdout=out,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LANG':'C'})  # nosec B603
            first.stdout.close()
            if second.wait(timeout=3600)!=0 or first.wait(timeout=30)!=0:raise RuntimeError('encrypted_dump_failed')
            out.flush();os.fsync(out.fileno())
        finally:
            if first.stdout and not first.stdout.closed:first.stdout.close()
            for proc in (second,first):
                if proc is not None and proc.poll() is None:
                    proc.kill();proc.wait()


def publish(root,producer,signer,trusted_public,counts,*,fingerprints=None):
    # Root must be trusted, private and on a filesystem supporting atomic rename.
    root=Path(root)
    if root.is_symlink() or not root.is_dir() or root.stat().st_mode & 0o077:raise ValueError('private_backup_directory_required')
    if not classify_restore(SCHEMA_VERSION,counts)['ok']:raise ValueError('source_integrity_failure')
    backup_id='backup_'+uuid.uuid4().hex
    with tempfile.TemporaryDirectory(dir=root,prefix='.pending-') as tmp:
        stage=Path(tmp)/backup_id;stage.mkdir(mode=0o700)
        target=stage/'database.dump.age';producer(target)
        target.chmod(0o600);size,digest=file_fingerprint(target)
        # Bind original financial snapshot counts to encrypted bytes and signature.
        manifest={'format':2,'backup_id':backup_id,'sha256':digest,'size':size,'schema':SCHEMA_VERSION,'environment':'prelicense','counts':counts}
        if fingerprints is not None:
            manifest['format']=3;manifest['fingerprints']=validate_fingerprints(fingerprints)
        signature=base64.b64encode(signer.sign(manifest_bytes(manifest))).decode('ascii')
        verify_backup(target,manifest,signature,trusted_public)
        _sync_file(stage/'manifest.json',json.dumps(manifest,sort_keys=True).encode('ascii'))
        _sync_file(stage/'signature.txt',signature.encode('ascii'))
        fd=os.open(stage,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        final=root/backup_id
        if final.exists():raise ValueError('backup_already_exists')
        stage.rename(final)
        fd=os.open(root,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    return manifest


def main():
    if os.getenv('SPYDERPAY_ENV')!='prelicense':raise SystemExit('Prelicense only')
    parser=argparse.ArgumentParser();parser.add_argument('output_directory');a=parser.parse_args()
    service=os.environ['SPYDERPAY_BACKUP_PGSERVICE'];recipient=os.environ['SPYDERPAY_BACKUP_AGE_RECIPIENT']
    if not SERVICE.fullmatch(service) or not AGE_RECIPIENT.fullmatch(recipient):raise SystemExit('invalid_backup_config')
    # Require explicit libpq files; a secret manager provisions them separately.
    env={'PATH':'/usr/bin:/bin','LANG':'C','PGSERVICEFILE':os.environ['PGSERVICEFILE'],'PGPASSFILE':os.environ['PGPASSFILE'],'PGSSLMODE':'verify-full','PGCONNECT_TIMEOUT':'5','PGGSSENCMODE':'disable'}
    for field in ('PGSERVICEFILE','PGPASSFILE'):
        p=Path(env[field]);st=p.stat()
        if p.is_symlink() or not p.is_file() or st.st_mode & 0o077:raise SystemExit('unsafe_libpq_file')
    # psycopg and pg_dump connect through the exact same service file and SSL mode.
    for name in tuple(os.environ):
        if name.startswith('PG'):del os.environ[name]
    for name,val in env.items():
        if name.startswith('PG'):os.environ[name]=val
    import psycopg
    from psycopg.rows import dict_row
    trusted=os.environ['SPYDERPAY_BACKUP_TRUSTED_PUBLIC_B64']
    signer=VaultTransitSigner(json.loads(os.environ['SPYDERPAY_BACKUP_SIGNER_JSON']),Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted,validate=True)))
    with psycopg.connect(service=service,sslmode='verify-full',gssencmode='disable',autocommit=True,row_factory=dict_row,connect_timeout=5,options='-c statement_timeout=120000 -c idle_in_transaction_session_timeout=3700000') as c,c.transaction():
        c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        role=c.execute('''SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR has_schema_privilege(current_user,'public','CREATE') OR EXISTS(SELECT 1 FROM pg_class cl JOIN pg_namespace ns ON ns.oid=cl.relnamespace WHERE ns.nspname='public' AND cl.relkind IN ('r','p') AND (pg_has_role(current_user,cl.relowner,'MEMBER') OR has_table_privilege(current_user,cl.oid,'INSERT,UPDATE,DELETE,TRUNCATE'))) AS unsafe FROM pg_roles WHERE rolname=current_user''').fetchone()
        if not role or role['unsafe']:raise ValueError('unsafe_backup_role')
        schema=c.execute('SELECT max(version) AS version FROM sp_schema_version').fetchone()['version']
        if schema!=SCHEMA_VERSION:raise ValueError('source_schema_mismatch')
        snapshot=c.execute('SELECT pg_export_snapshot() AS snapshot').fetchone()['snapshot']
        counts=dict(c.execute(RESTORE_SQL).fetchone())
        manifest=publish(a.output_directory,lambda path:encrypted_dump(path,service,snapshot,recipient,env=env),signer,trusted,counts,fingerprints=fingerprint(c))
    print(json.dumps({'backup_id':manifest['backup_id'],'schema':manifest['schema'],'size':manifest['size']},sort_keys=True))

if __name__=='__main__':main()
