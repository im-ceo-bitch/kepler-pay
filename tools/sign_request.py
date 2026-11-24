#!/usr/bin/env python3
"""Print headers for a local S2S test request. Never run in mobile apps."""
import argparse
import base64
import secrets
import time
from spyderpay_core.postgres.auth import sign


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('method')
    ap.add_argument('path')
    ap.add_argument('--key-id',required=True)
    ap.add_argument('--secret-b64',required=True,help='SERVICE TEST KEY (do not commit)')
    ap.add_argument('--body',default='')
    args=ap.parse_args()
    ts=str(int(time.time()))
    nonce=secrets.token_urlsafe(24)
    signature=sign(base64.b64decode(args.secret_b64),args.method,args.path,args.body.encode(),ts,nonce)
    print('X-Spyder-Key-Id:',args.key_id)
    print('X-Spyder-Timestamp:',ts)
    print('X-Spyder-Nonce:',nonce)
    print('X-Spyder-Signature:',signature)

if __name__=='__main__':main()
