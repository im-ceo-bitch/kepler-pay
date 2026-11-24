"""Authenticated card possession endpoints; no NFC debit endpoint exists."""
from fastapi import Request
from pydantic import Field
from .api import _Base
from .cards import Cards

class Enrollment(_Base):
    public_key: str=Field(min_length=130,max_length=130)
class Preview(_Base):
    invoice_id: str=Field(min_length=36,max_length=36)
class Proof(_Base):
    signature: str=Field(min_length=16,max_length=144)

def mount_card_routes(app,processor,verifier):
    cards=Cards(processor,verifier)
    @app.get('/v3/cards')
    def list_cards(request: Request):return cards.list(request.state.principal)
    @app.post('/v3/cards/enroll')
    def enroll(request: Request,data: Enrollment):return cards.begin_enrollment(request.state.principal,data.public_key)
    @app.post('/v3/cards/{cid}/preview')
    def preview(request: Request,cid: str,data: Preview):return cards.begin_preview(request.state.principal,cid,data.invoice_id)
    @app.post('/v3/cards/challenges/{cid}/proof')
    def proof(request: Request,cid: str,data: Proof):return cards.finish(request.state.principal,cid,data.signature)
    @app.post('/v3/cards/{cid}/revoke')
    def revoke(request: Request,cid: str,data: _Base):return cards.revoke(request.state.principal,cid)
