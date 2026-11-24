#!/usr/bin/env python3
"""Provision or disable trusted IdP subjects; revoke a session. No passwords or secrets on CLI."""
import argparse
import os
from spyderpay_core.postgres.identity import ID, revoke_session
from spyderpay_core.postgres.store import _identity


def main():
    if os.getenv('SPYDERPAY_ENV') not in ('prelicense','test'):
        raise SystemExit('Prelicense/test only')
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['provision','disable','revoke-session'])
    parser.add_argument('--issuer',required=True)
    parser.add_argument('--subject',required=True)
    parser.add_argument('--tenant');parser.add_argument('--owner');parser.add_argument('--role',choices=['customer','merchant']);parser.add_argument('--sid')
    args=parser.parse_args()
    if not args.issuer.startswith('https://') or not ID.fullmatch(args.subject):parser.error('invalid issuer/subject')
    import psycopg
    with psycopg.connect(os.environ['SPYDERPAY_IDENTITY_ADMIN_DSN']) as conn:
        if args.action=='provision':
            if not all((args.tenant,args.owner,args.role)):parser.error('tenant, owner and role required')
            conn.execute('INSERT INTO sp_identity_members(issuer,external_sub,tenant_id,owner_id,role) VALUES(%s,%s,%s,%s,%s)',(args.issuer,args.subject,_identity(args.tenant),_identity(args.owner),args.role))
        elif args.action=='disable':
            row=conn.execute('UPDATE sp_identity_members SET enabled=false WHERE issuer=%s AND external_sub=%s RETURNING external_sub',(args.issuer,args.subject)).fetchone()
            if not row:raise SystemExit('member_not_found')
        else:
            if not args.sid or not ID.fullmatch(args.sid):parser.error('sid required')
            revoke_session(conn,args.issuer,args.subject,args.sid)
    print('Identity admin change committed')

if __name__=='__main__':main()
