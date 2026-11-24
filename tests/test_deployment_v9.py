import json
import pytest
from spyderpay_core.postgres.deployment import validate_hardened


def config():return {'SPYDERPAY_ENV':'prelicense','SPYDERPAY_ALLOW_SANDBOX_CREDIT':'no'}
def dsn():return {'host':'db.private.example','user':'runtime','dbname':'sp_test','sslmode':'verify-full','gssencmode':'disable','target_session_attrs':'read-write','sslrootcert':'/etc/ssl/sp-ca.crt'}

def test_hardened_accepts_explicit_tls():validate_hardened(config(),dsn())

@pytest.mark.parametrize('key,value',[('target_session_attrs','any'),('gssencmode','prefer'),('sslmode','require'),('sslmode','disable'),('host',''),('host','host1,host2'),('host','/run/postgresql'),('sslrootcert','ca.crt'),('hostaddr','127.0.0.1'),('service','other'),('user',''),('dbname','')])
def test_hardened_rejects_unsafe_db(key,value):
    c=dsn();c[key]=value
    with pytest.raises(ValueError):validate_hardened(config(),c)

@pytest.mark.parametrize('key,value',[('SPYDERPAY_ENV','production'),('SPYDERPAY_ALLOW_SANDBOX_CREDIT','yes'),('SPYDERPAY_POS_KEYS_JSON',json.dumps({'private_b64':'fixture'}))])
def test_hardened_rejects_unsafe_runtime(key,value):
    c=config();c[key]=value
    with pytest.raises(ValueError):validate_hardened(c,dsn())
