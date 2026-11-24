#!/usr/bin/env python3
"""Local service signing helper. Secret is read from an injected environment variable."""
import argparse,base64,os,secrets,time
from pathlib import Path
from spyderpay_core.postgres.service_v3 import sign_v3

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('method',choices=['GET','POST']);p.add_argument('path');p.add_argument('--key-id',required=True);p.add_argument('--body-file',type=Path);p.add_argument('--idem',default='');a=p.parse_args()
    secret=base64.b64decode(os.environ['SPYDERPAY_SIGNING_SECRET_B64'],validate=True)
    stamp=str(int(time.time()));nonce=secrets.token_urlsafe(24);body=a.body_file.read_bytes() if a.body_file else b''
    print('X-Spyder-Key-Id:',a.key_id);print('X-Spyder-Timestamp:',stamp);print('X-Spyder-Nonce:',nonce);print('X-Spyder-Signature:',sign_v3(secret,a.key_id,a.method,a.path,body,stamp,nonce,a.idem))
    if a.idem:print('Idempotency-Key:',a.idem)
