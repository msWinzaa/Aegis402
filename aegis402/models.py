from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field, ConfigDict
Decision = Literal['ALLOW','BLOCK','REVIEW']
class PaymentRequirements(BaseModel):
    model_config=ConfigDict(extra='forbid')
    scheme:str='exact'; network:str='base-sepolia'; asset:str='USDC'; amount:str; pay_to:str; resource:str
    max_timeout_seconds:int=300; nonce:str|None=None; issued_at:float|None=None; request_fingerprint:str|None=None; extra:dict[str,Any]=Field(default_factory=dict)
class PaymentPayload(BaseModel):
    model_config=ConfigDict(extra='forbid')
    payer:str; resource:str; amount:str; pay_to:str; nonce:str; signature:str='demo-signature'; scheme:str='exact'; network:str='base-sepolia'; asset:str='USDC'
    valid_after:int|None=None; valid_before:int|None=None; idempotency_key:str|None=None; metadata:dict[str,Any]=Field(default_factory=dict)
class RequestContext(BaseModel):
    method:str; path:str; resource:str; merchant:str; request_id:str; body_hash:str=''; headers_fingerprint:str=''
class SecurityDecision(BaseModel):
    decision:Decision; reason:str; checks:dict[str,str]; fingerprint:str; event_id:str; risk_score:int=0; risk_level:str='LOW'; review_required:bool=False
class SettlementResult(BaseModel):
    success:bool; tx_hash:str|None=None; reason:str|None=None; settled_network:str|None=None; payer:str|None=None; settled_amount:str|None=None
