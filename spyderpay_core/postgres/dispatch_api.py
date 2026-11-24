from typing import Literal
from fastapi import Request
from .api import _Base
from .bank_api import Idem
from .dispatch import Dispatch

class Report(_Base):
    outcome: Literal['accepted','unknown','not_dispatched']

def mount_dispatch_routes(app,processor):
    dispatch=Dispatch(processor)
    @app.post('/v3/rail/intents/{iid}/claim')
    def claim(request:Request,iid:str,data:_Base,idempotency_key:Idem):
        # Header is required and signed, but does not replay the send permission.
        return dispatch.claim(request.state.principal,iid)
    @app.get('/v3/rail/intents/{iid}')
    def status(request:Request,iid:str):
        return dispatch.status(request.state.principal,iid)
    @app.post('/v3/rail/intents/{iid}/result')
    def result(request:Request,iid:str,data:Report,idempotency_key:Idem):
        return dispatch.report(request.state.principal,iid,data.outcome,idempotency_key)
