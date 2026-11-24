"""Fail-closed policy for hardened pre-license deployments, not a production switch."""
import json
import re
from pathlib import Path


def validate_hardened(config,dsn_options):
    if config.get('SPYDERPAY_ENV')!='prelicense' or config.get('SPYDERPAY_ALLOW_SANDBOX_CREDIT','no')!='no':raise ValueError('hardened_requires_credit_disabled')
    # Explicit TLS hostname validation; don't allow local socket, multiple hosts,
    # or libpq service indirection in the application runtime config.
    host=dsn_options.get('host','');root=dsn_options.get('sslrootcert','')
    if (dsn_options.get('sslmode')!='verify-full' or dsn_options.get('gssencmode')!='disable' or dsn_options.get('target_session_attrs')!='read-write' or not root or not Path(root).is_absolute() or not host or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',host) or 'service' in dsn_options or 'hostaddr' in dsn_options or not dsn_options.get('dbname') or not dsn_options.get('user')):
        raise ValueError('hardened_requires_explicit_tls_database')
    pos=config.get('SPYDERPAY_POS_KEYS_JSON')
    if pos:
        c=json.loads(pos)
        if 'private_b64' in c or not isinstance(c.get('remote_signer'),dict):raise ValueError('hardened_requires_remote_pos_signer')


def check_hardened(config,dsn):
    from psycopg.conninfo import conninfo_to_dict
    validate_hardened(config,conninfo_to_dict(dsn))
