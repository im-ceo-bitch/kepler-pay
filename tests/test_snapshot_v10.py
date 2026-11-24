import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from spyderpay_core.postgres.ops.snapshot_fingerprint import TABLES,row_digest,validate_fingerprints
from spyderpay_core.postgres.ops.recovery import compare_snapshot,verify_backup,classify_restore,manifest_bytes
from spyderpay_core.postgres.ops.backup import publish
from spyderpay_core.release import SCHEMA_VERSION
from test_pos_recovery_v7 import counts

def digests():return {t:row_digest(t,[]) for t in TABLES}

def test_same_count_different_rows_and_length_framing():
    assert row_digest('sp_accounts',['a','bc'])!=row_digest('sp_accounts',['ab','c'])
    assert row_digest('sp_accounts',['a'])!=row_digest('sp_accounts',['b'])
    assert row_digest('sp_accounts',['a'])!=row_digest('sp_invoices',['a'])
    assert row_digest('sp_accounts',['a','a'])['rows']==2

def test_complete_table_inventory():
    import re
    from pathlib import Path
    found=set()
    for f in (Path(__file__).parents[1]/'spyderpay_core/postgres/migrations').glob('*.sql'):
        found.update(re.findall(r'CREATE TABLE (?:IF NOT EXISTS )?(sp_[a-z_]+)',f.read_text(),re.I))
    assert set(TABLES)==found

@pytest.mark.parametrize('change',['missing','extra','wrong_hash','negative_rows','bool_rows'])
def test_invalid_fingerprint(change):
    d=digests();t=TABLES[0]
    if change=='missing':del d[t]
    elif change=='extra':d['extra']=d[t]
    elif change=='wrong_hash':d[t]['sha256']='x'*64
    elif change=='negative_rows':d[t]['rows']=-1
    else:d[t]['rows']=False
    with pytest.raises(ValueError):validate_fingerprints(d)

def test_v3_signed_snapshot_detects_same_count_mutation(tmp_path):
    tmp_path.chmod(0o700);k=Ed25519PrivateKey.generate();pub=base64.b64encode(k.public_key().public_bytes_raw()).decode();c=counts();d=digests()
    m=publish(tmp_path,lambda p:p.write_bytes(b'fixture encrypted bytes'),k,pub,c,fingerprints=d)
    path=tmp_path/m['backup_id'];s=(path/'signature.txt').read_text();assert m['format']==3
    assert verify_backup(path/'database.dump.age',m,s,pub)['verified']
    restored={**classify_restore(SCHEMA_VERSION,c),'fingerprints':digests()};assert compare_snapshot(m,restored)
    restored['fingerprints']['sp_accounts']['sha256']='a'*64
    assert not compare_snapshot(m,restored)
    m['fingerprints']['sp_accounts']['sha256']='b'*64
    with pytest.raises(ValueError,match='invalid_backup_signature'):verify_backup(path/'database.dump.age',m,s,pub)


def test_signed_counts_must_match_table_fingerprints():
    m={'format':3,'backup_id':'backup_000000001','sha256':'a'*64,'size':1,'schema':SCHEMA_VERSION,'environment':'prelicense','counts':counts(),'fingerprints':digests()}
    m['counts']['accounts']=1
    with pytest.raises(ValueError,match='snapshot_count_mismatch'):manifest_bytes(m)
