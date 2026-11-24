"""Durable LOCAL partner emulator for certification scenarios, never a live rail.

A separate SQLite file models the provider's own records; no customer ledger
writes, network, secrets from the environment, or production support. A caller
must use independently authorized callback and statement channels in the core.
"""
from contextlib import contextmanager
from hashlib import sha256
import hmac
import json
from pathlib import Path
import sqlite3
import time
from .banking import provider, reference
from .clearing import validate_batch
from .rail_contract import RailInstruction, DispatchResult
from spyderpay_core.ledger import PaymentError


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


class SandboxRail:
    def __init__(self, path, provider_id, callback_key, *, environment):
        if environment not in ('test', 'sandbox'):
            raise ValueError('sandbox_only')
        if type(callback_key) is not bytes or len(callback_key) < 32:
            raise ValueError('weak_callback_key')
        self.provider = provider(provider_id)
        self.path = Path(path)
        if self.path.is_symlink() or not self.path.parent.is_dir():
            raise ValueError('invalid_sandbox_path')
        self.key = callback_key
        with self._tx() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS rail_events (
                seq INTEGER PRIMARY KEY, ref TEXT UNIQUE NOT NULL,
                digest TEXT NOT NULL, direction TEXT NOT NULL, amount INTEGER NOT NULL,
                beneficiary TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('settled','failed')),
                CHECK(amount>0), CHECK(direction IN ('deposit','withdrawal')))''')
            db.execute('CREATE TABLE IF NOT EXISTS rail_meta (provider TEXT PRIMARY KEY)')
            row = db.execute('SELECT provider FROM rail_meta').fetchone()
            if row is None:
                db.execute('INSERT INTO rail_meta VALUES (?)', (self.provider,))
            elif row['provider'] != self.provider:
                raise ValueError('sandbox_provider_mismatch')

    @contextmanager
    def _tx(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def submit(self, instruction):
        return self.simulate(instruction)

    def simulate(self, instruction, *, fail=False, lose_response=False):
        if not isinstance(instruction, RailInstruction) or instruction.provider != self.provider:
            raise PaymentError('sandbox_instruction_mismatch', 422)
        if type(fail) is not bool or type(lose_response) is not bool:
            raise ValueError('invalid_fault_mode')
        ref = instruction.idempotency_reference
        with self._tx() as db:
            row = db.execute('SELECT digest FROM rail_events WHERE ref=?', (ref,)).fetchone()
            if row:
                if row['digest'] != instruction.digest:
                    raise PaymentError('sandbox_reference_conflict', 409)
            else:
                db.execute('INSERT INTO rail_events(ref,digest,direction,amount,beneficiary,status) VALUES(?,?,?,?,?,?)',
                           (ref, instruction.digest, instruction.direction, instruction.amount,
                            instruction.beneficiary_ref, 'failed' if fail else 'settled'))
        if lose_response:
            raise TimeoutError('simulated_lost_response_after_commit')
        return DispatchResult(ref, 'accepted')

    def lookup(self, idempotency_reference):
        ref = reference(idempotency_reference)
        with self._tx() as db:
            exists = db.execute('SELECT 1 FROM rail_events WHERE ref=?', (ref,)).fetchone()
        # An absent record is not proof of final failure to the processor.
        return DispatchResult(ref, 'accepted' if exists else 'unknown')

    @staticmethod
    def _row(row, channel):
        return dict(event_ref=f'{channel}-{row["seq"]:012d}', provider_ref=row['ref'],
                    direction=row['direction'], amount=row['amount'],
                    beneficiary_ref=row['beneficiary'], status=row['status'])

    def callback(self, ref, *, now=None):
        with self._tx() as db:
            row = db.execute('SELECT * FROM rail_events WHERE ref=?', (reference(ref),)).fetchone()
        if row is None:
            raise PaymentError('sandbox_reference_not_found', 404)
        raw = canonical({'provider': self.provider, **self._row(row, 'callback')})
        stamp = str(int(time.time()) if now is None else now)
        sig = hmac.new(self.key, stamp.encode()+b'.'+raw, sha256).hexdigest()
        return raw, {'x-sandbox-timestamp': stamp, 'x-sandbox-signature': sig}

    def verify_callback(self, raw_body, headers, *, now=None):
        if not isinstance(raw_body, bytes) or len(raw_body)>16384 or not isinstance(headers, dict):
            raise PaymentError('invalid_sandbox_callback', 422)
        norm = {}
        for k, v in headers.items():
            if not isinstance(k, str) or not isinstance(v, str) or k.lower() in norm:
                raise PaymentError('invalid_sandbox_headers', 400)
            norm[k.lower()] = v
        ts, sig = norm.get('x-sandbox-timestamp',''), norm.get('x-sandbox-signature','')
        if len(ts)!=10 or not ts.isascii() or not ts.isdecimal() or len(sig)!=64 or not sig.isascii():
            raise PaymentError('invalid_sandbox_signature', 401)
        if abs((int(time.time()) if now is None else now)-int(ts))>120:
            raise PaymentError('expired_sandbox_callback', 401)
        if not hmac.compare_digest(sig, hmac.new(self.key, ts.encode()+b'.'+raw_body, sha256).hexdigest()):
            raise PaymentError('invalid_sandbox_signature', 401)
        try:
            obj = json.loads(raw_body)
            if not isinstance(obj, dict) or canonical(obj)!=raw_body or obj.pop('provider')!=self.provider:
                raise ValueError('invalid_callback')
            a = obj['amount'] if obj['status']=='settled' else 0
            c, d = (a,0) if obj['direction']=='deposit' else (0,a)
            validate_batch(self.provider, 'callback-validation', 0, c-d, c, d, [obj])
        except (ValueError, KeyError, TypeError, RecursionError, PaymentError):
            raise PaymentError('invalid_sandbox_callback', 422) from None
        return {'provider': self.provider, **obj, 'payload_digest': sha256(raw_body).hexdigest()}

    def statement_batch(self, cursor=None, limit=25):
        if type(limit) is not int or not 1<=limit<=25:
            raise ValueError('invalid_batch_limit')
        if cursor is None:
            start=0
        elif isinstance(cursor,str) and cursor.isascii() and cursor.isdecimal() and len(cursor)<=15 and str(int(cursor))==cursor:
            start=int(cursor)
        else:
            raise ValueError('invalid_cursor')
        with self._tx() as db:
            if start and not db.execute('SELECT 1 FROM rail_events WHERE seq=?',(start,)).fetchone():
                raise ValueError('unknown_cursor')
            opening=db.execute("SELECT coalesce(sum(CASE WHEN direction='deposit' THEN amount ELSE -amount END),0) FROM rail_events WHERE seq<=? AND status='settled'",(start,)).fetchone()[0]
            records=db.execute('SELECT * FROM rail_events WHERE seq>? ORDER BY seq LIMIT ?', (start,limit)).fetchall()
        if not records:
            return None
        rows=[self._row(r,'statement') for r in records]
        c=sum(r['amount'] for r in rows if r['status']=='settled' and r['direction']=='deposit')
        d=sum(r['amount'] for r in rows if r['status']=='settled' and r['direction']=='withdrawal')
        end=str(records[-1]['seq']); batch_ref=f'batch-{start}-{end}'
        digest=validate_batch(self.provider,batch_ref,opening,opening+c-d,c,d,rows)
        return dict(provider=self.provider,batch_ref=batch_ref,opening=opening,closing=opening+c-d,
                    credits=c,debits=d,rows=rows,digest=digest,cursor=end,previous_cursor=str(start))

    def fetch_statement(self,cursor):
        batch=self.statement_batch(cursor)
        return (batch['rows'],batch['cursor']) if batch else ([],cursor)
