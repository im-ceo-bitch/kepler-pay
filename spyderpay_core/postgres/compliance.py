"""Pre-license decision workflow, not a sanctions data provider or AML certification."""
from datetime import datetime, timedelta, timezone
from spyderpay_core.ledger import PaymentError
from .banking import authorize_role, reference
from .store import _id, _jsonable, _amount

# Example conservative limits; partner policy requires approval before launch.
POLICY = {'standard': (10_000_000, 30_000_000, 10), 'enhanced': (50_000_000, 100_000_000, 30)}

def evaluate(review, amount, volume, count, now):
    if not review or review['decision'] != 'approved' or review['kyc'] != 'verified' or review['screening'] != 'clear':
        raise PaymentError('compliance_review_required', 403)
    if review['created_at'] < now - timedelta(hours=24) or review['created_at'] > now or review['decided_at'] > now:
        raise PaymentError('compliance_review_expired', 403)
    single, daily, velocity = POLICY[review['tier']]
    if amount > single or volume + amount > daily or (amount > 0 and count >= velocity):
        raise PaymentError('bank_velocity_or_amount_limit', 403)

class Compliance:
    def __init__(self, processor): self.p = processor

    @staticmethod
    def account(conn, p, account):
        row = conn.execute('SELECT id FROM sp_accounts WHERE tenant_id=%s AND id=%s AND kind IN (\'customer\',\'merchant\') FOR UPDATE', (p.tenant_id, account)).fetchone()
        if not row: raise PaymentError('account_not_found', 404)

    def record(self, p, account, kyc, screening, tier, evidence_ref, idem):
        authorize_role(p, 'compliance_maker'); account = _id(account); evidence_ref = reference(evidence_ref)
        if kyc not in ('verified','rejected','pending') or screening not in ('clear','hit','pending') or tier not in POLICY:
            raise PaymentError('invalid_compliance_review',422)
        data = dict(op='compliance_record', account=account, kyc=kyc, screening=screening, tier=tier, evidence_ref=evidence_ref)
        def run(conn):
            self.account(conn,p,account)
            row = conn.execute('''INSERT INTO sp_compliance_reviews(tenant_id,account_id,kyc,screening,tier,evidence_ref,maker) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *''',(p.tenant_id,account,kyc,screening,tier,evidence_ref,p.subject)).fetchone()
            if not row: raise PaymentError('compliance_evidence_reused',409)
            self.p._audit(conn,p,'compliance_record',str(row['id']),data)
            self.p._outbox(conn,p,'compliance.review.created',str(row['id']),{'account_id':account,'review_id':str(row['id'])})
            return _jsonable(row)
        return self.p._once(p,idem,data,run)

    def decide(self,p,review_id,decision,idem):
        authorize_role(p,'compliance_review'); review_id=_id(review_id)
        if decision not in ('approved','rejected'): raise PaymentError('invalid_compliance_decision',422)
        def run(conn):
            r=conn.execute('SELECT * FROM sp_compliance_reviews WHERE tenant_id=%s AND id=%s',(p.tenant_id,review_id)).fetchone()
            if not r: raise PaymentError('compliance_review_not_found',404)
            self.account(conn,p,str(r['account_id']))
            if r['maker']==p.subject or (decision=='approved' and (r['kyc']!='verified' or r['screening']!='clear')): raise PaymentError('invalid_compliance_decision',409)
            row=conn.execute('INSERT INTO sp_compliance_decisions(review_id,reviewer,decision) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *',(review_id,p.subject,decision)).fetchone()
            if not row: raise PaymentError('compliance_already_decided',409)
            self.p._audit(conn,p,'compliance_decision',review_id,{'decision':decision})
            return _jsonable(row)
        return self.p._once(p,idem,{'op':'compliance_decide','review_id':review_id,'decision':decision},run)

    def enforce(self,conn,p,account,amount,exclude=None,*,receive_only=False):
        # All banking creates and review changes serialize on the account row.
        self.account(conn,p,account)
        review=conn.execute('''SELECT r.*,d.decision,d.decided_at FROM sp_compliance_reviews r LEFT JOIN sp_compliance_decisions d ON r.id=d.review_id WHERE r.tenant_id=%s AND r.account_id=%s ORDER BY r.created_at DESC,r.id DESC LIMIT 1''',(p.tenant_id,account)).fetchone()
        if receive_only:
            evaluate(review,0,0,0,datetime.now(timezone.utc))
            return
        stats=conn.execute('''SELECT coalesce(sum(amount),0) AS volume,count(*) AS n FROM sp_bank_intents WHERE tenant_id=%s AND account_id=%s AND created_at>=now()-interval '24 hours' AND (%s::uuid IS NULL OR id<>%s::uuid)''',(p.tenant_id,account,exclude,exclude)).fetchone()
        internal=conn.execute("""SELECT coalesce(sum(-p.signed_amount),0) AS volume,count(*) AS n FROM sp_postings p JOIN sp_journals j ON j.id=p.journal_id WHERE j.tenant_id=%s AND p.account_id=%s AND p.signed_amount<0 AND j.kind IN ('transfer','merchant_payment','merchant_refund') AND j.created_at>=now()-interval '24 hours'""",(p.tenant_id,account)).fetchone()
        evaluate(review,_amount(amount),int(stats['volume'])+int(internal['volume']),stats['n']+internal['n'],datetime.now(timezone.utc))
