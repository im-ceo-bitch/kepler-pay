import base64
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from spyderpay_core.postgres.ops.backup import publish
from spyderpay_core.postgres.ops.recovery import compare_snapshot,verify_backup,classify_restore,manifest_bytes
from spyderpay_core.release import SCHEMA_VERSION
from test_pos_recovery_v7 import counts


def setup(tmp_path):
    tmp_path.chmod(0o700);k=Ed25519PrivateKey.generate();pub=base64.b64encode(k.public_key().public_bytes_raw()).decode();return k,pub


def test_backup_publish_and_compare(tmp_path):
    k,pub=setup(tmp_path);c=counts();c['accounts']=3;m=publish(tmp_path,lambda p:p.write_bytes(b'encrypted fixture'),k,pub,c)
    path=tmp_path/m['backup_id'];assert set(x.name for x in path.iterdir())=={'database.dump.age','manifest.json','signature.txt'}
    assert verify_backup(path/'database.dump.age',m,(path/'signature.txt').read_text(),pub)['verified']
    assert compare_snapshot(m,classify_restore(SCHEMA_VERSION,c))
    changed={**c,'accounts':4};assert not compare_snapshot(m,classify_restore(SCHEMA_VERSION,changed))
    m['counts']['accounts']=4
    with pytest.raises(ValueError,match='invalid_backup_signature'):verify_backup(path/'database.dump.age',m,(path/'signature.txt').read_text(),pub)


def test_backup_failure_does_not_publish(tmp_path):
    k,pub=setup(tmp_path)
    def failed(path):path.write_bytes(b'partial');raise RuntimeError('failed')
    with pytest.raises(RuntimeError):publish(tmp_path,failed,k,pub,counts())
    assert not list(tmp_path.iterdir())


def test_backup_signer_failure_does_not_publish(tmp_path):
    _,pub=setup(tmp_path);other=Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):publish(tmp_path,lambda p:p.write_bytes(b'encrypted fixture'),other,pub,counts())
    assert not list(tmp_path.iterdir())


def test_backup_source_corruption(tmp_path):
    k,pub=setup(tmp_path);c=counts();c['invalid_balances']=1
    with pytest.raises(ValueError,match='source_integrity_failure'):publish(tmp_path,lambda p:pytest.fail('must not run'),k,pub,c)


def test_backup_requires_private_directory(tmp_path):
    k,pub=setup(tmp_path);tmp_path.chmod(0o755)
    with pytest.raises(ValueError):publish(tmp_path,lambda p:pytest.fail('must not run'),k,pub,counts())
