"""Restricted Vault Transit Ed25519 signer. No untrusted URLs, redirects or local fallback.

Private staging only. A configured Vault transit key is not automatically an HSM;
actual HSM protection and operational controls require separate deployment evidence.
"""
import base64
import http.client
import json
import os
import re
import ssl
import stat
from urllib.parse import urlsplit
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

NAME=re.compile(r'[A-Za-z0-9_-]{1,64}')
TOKEN=re.compile(r'[\x21-\x7e]{16,4096}')
MAX_REPLY=16384


def read_secret(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:raise ValueError('unsafe_signer_token_file')
        value=f.read(4097).decode('ascii').strip()
    if not TOKEN.fullmatch(value):raise ValueError('invalid_signer_token')
    return value


class VaultTransitSigner:
    def __init__(self,config,public:Ed25519PublicKey):
        expected={'url','mount','key_name','key_version','ca_file','token_file','client_cert','client_key'}
        if not isinstance(config,dict) or set(config)!=expected:raise ValueError('invalid_vault_config')
        u=urlsplit(config['url'])
        if u.scheme!='https' or not u.hostname or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:raise ValueError('invalid_vault_url')
        if not all(isinstance(config[k],str) and NAME.fullmatch(config[k]) for k in ('mount','key_name')):raise ValueError('invalid_vault_key_name')
        version=config['key_version']
        if type(version) is not int or not 1<=version<=1000000:raise ValueError('invalid_vault_key_version')
        self.host=u.hostname;self.port=u.port or 443;self.version=version;self.public=public
        self.path=f"/v1/{config['mount']}/sign/{config['key_name']}"
        self.token_path=config['token_file']
        self.context=ssl.create_default_context(cafile=config['ca_file'])
        self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        # Explicit trust bundle and mTLS; no system proxy, no redirect handling.
        self.context.load_cert_chain(config['client_cert'],config['client_key'])
        self.token_reader=read_secret

    def sign(self,message):
        if not isinstance(message,bytes) or not 1<=len(message)<=8192:raise ValueError('invalid_signer_message')
        payload=json.dumps({'input':base64.b64encode(message).decode('ascii'),'key_version':self.version},separators=(',',':')).encode('ascii')
        connection=http.client.HTTPSConnection(self.host,self.port,timeout=3,context=self.context)
        try:
            connection.request('POST',self.path,body=payload,headers={'Content-Type':'application/json','X-Vault-Token':self.token_reader(self.token_path)})
            response=connection.getresponse()
            if response.status!=200:raise ValueError('vault_sign_failed')
            data=response.read(MAX_REPLY+1)
            if len(data)>MAX_REPLY:raise ValueError('vault_response_too_large')
            value=json.loads(data)['data']['signature']
            prefix=f'vault:v{self.version}:'
            if not isinstance(value,str) or not value.startswith(prefix):raise ValueError('wrong_vault_key_version')
            signature=base64.b64decode(value[len(prefix):],validate=True)
            if len(signature)!=64:raise ValueError('invalid_vault_signature')
            self.public.verify(signature,message)
            return signature
        except (OSError,http.client.HTTPException,ValueError,KeyError,TypeError,InvalidSignature) as exc:
            # Avoid surfacing remote payloads, host names, paths or tokens.
            raise RuntimeError('remote_signer_unavailable') from None
        finally:connection.close()
