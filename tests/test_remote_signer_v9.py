import base64
import json
import os
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from spyderpay_core.postgres import remote_signer as rs
from spyderpay_core.postgres.pos import PosTokens
from spyderpay_core.ledger import PaymentError
from test_pos_recovery_v7 import cfg,invoice

class Context:
    def load_cert_chain(self,*args):self.cert=args

def config():return {'url':'https://vault.example.test:8200','mount':'transit','key_name':'pos-ed25519','key_version':3,'ca_file':'ca','token_file':'token','client_cert':'cert','client_key':'key'}

def setup(monkeypatch,mode='ok'):
    priv=Ed25519PrivateKey.generate();ctx=Context();monkeypatch.setattr(rs.ssl,'create_default_context',lambda **kw:ctx)
    monkeypatch.setattr(rs,'read_secret',lambda _: 'synthetic-test-token')
    requests=[]
    class Conn:
        def __init__(self,host,port,**kw):assert host=='vault.example.test' and port==8200 and kw['timeout']==3
        def request(self,method,path,body,headers):
            assert method=='POST' and path=='/v1/transit/sign/pos-ed25519';assert headers['X-Vault-Token']=='synthetic-test-token'
            data=json.loads(body);assert data['key_version']==3;message=base64.b64decode(data['input']);requests.append(message)
            self.message=message
        def getresponse(self):
            if mode=='io':raise OSError('simulated disconnect')
            sig=priv.sign(self.message if mode!='wrong-message' else b'other')
            if mode=='wrong-key':sig=Ed25519PrivateKey.generate().sign(self.message)
            prefix='vault:v2:' if mode=='wrong-version' else 'vault:v3:'
            data=json.dumps({'data':{'signature':prefix+base64.b64encode(sig).decode()}}).encode()
            if mode=='bad-json':data=b'not-json'
            if mode=='large':data=b'X'*(rs.MAX_REPLY+1)
            return SimpleNamespace(status=302 if mode=='redirect' else 500 if mode=='server-error' else 200,read=lambda n:data[:n])
        def close(self):pass
    monkeypatch.setattr(rs.http.client,'HTTPSConnection',Conn)
    return priv,requests

def test_remote_signer_jws(monkeypatch):
    priv,calls=setup(monkeypatch);c=cfg();c.pop('private_b64');c['remote_signer']=config();c['keys'][0]['public_b64']=base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    tokens=PosTokens(json.dumps(c));i=invoice();assert tokens.private is None
    assert tokens.verify(tokens.issue('tenant-alpha',i),'tenant-alpha')['invoice']==i['id'];assert len(calls)==1

@pytest.mark.parametrize('mode',['redirect','server-error','wrong-version','wrong-key','wrong-message','bad-json','large','io'])
def test_remote_signer_fails_closed(monkeypatch,mode):
    priv,_=setup(monkeypatch,mode);s=rs.VaultTransitSigner(config(),priv.public_key())
    with pytest.raises(RuntimeError,match='remote_signer_unavailable'):s.sign(b'message')

@pytest.mark.parametrize('url',['http://vault.example.test','https://user:pw@vault.example.test','https://vault.example.test/a','https://vault.example.test?x=1','https://vault.example.test#x'])
def test_remote_signer_rejects_untrusted_config(url):
    c=config();c['url']=url
    with pytest.raises(ValueError):rs.VaultTransitSigner(c,Ed25519PrivateKey.generate().public_key())

def test_secret_file_permissions(tmp_path):
    p=tmp_path/'token';p.write_text('test-only-secret-token');p.chmod(0o600);assert rs.read_secret(p)=='test-only-secret-token'
    p.chmod(0o644)
    with pytest.raises(ValueError):rs.read_secret(p)
    link=tmp_path/'link';link.symlink_to(p)
    with pytest.raises(OSError):rs.read_secret(link)

def test_pos_signer_failure_no_local_fallback(monkeypatch):
    priv,_=setup(monkeypatch,'wrong-message');c=cfg();c.pop('private_b64');c['remote_signer']=config();c['keys'][0]['public_b64']=base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    t=PosTokens(json.dumps(c))
    with pytest.raises(PaymentError,match='pos_signer_unavailable'):t.issue('tenant-alpha',invoice())
