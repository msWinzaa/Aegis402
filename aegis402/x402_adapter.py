from __future__ import annotations
from dataclasses import dataclass
class X402IntegrationError(RuntimeError):pass
class X402Adapter:
    def verify(self,payload,requirements):raise NotImplementedError
    def settle(self,payload,requirements):raise NotImplementedError
    def status(self):return {'adapter':type(self).__name__,'mode':'UNKNOWN'}
@dataclass
class MockX402Adapter(X402Adapter):
    settlement_should_fail:bool=False
    def verify(self,payload,requirements):
        if payload.signature in {'','invalid','demo-invalid'}:return False,'invalid payment signature'
        return True,'mock verification passed'
    def settle(self,payload,requirements):
        from .models import SettlementResult
        if self.settlement_should_fail:return SettlementResult(success=False,reason='mock settlement failure')
        return SettlementResult(success=True,tx_hash='0xSIM_'+payload.nonce[:16],settled_network=payload.network,payer=payload.payer,settled_amount=payload.amount)
    def status(self):return {'adapter':'MockX402Adapter','mode':'SIMULATED','verification':'SIMULATED','settlement':'SIMULATED'}
class X402FacilitatorAdapter(X402Adapter):
    def __init__(self,facilitator_url,x402_version=2):self.facilitator_url=facilitator_url;self.x402_version=x402_version;self._client=None
    def _get_client(self):
        if self.x402_version!=2:raise X402IntegrationError('This v1.0 adapter targets x402 v2.')
        try:
            from x402.http import HTTPFacilitatorClientSync,FacilitatorConfig
        except ImportError as e:raise X402IntegrationError('Install the official x402 Python SDK with x402[httpx].') from e
        if self._client is None:self._client=HTTPFacilitatorClientSync(FacilitatorConfig(url=self.facilitator_url))
        return self._client
    def _objects(self,payload,requirements):
        try:from x402.schemas import PaymentPayload as P,PaymentRequirements as R,ResourceInfo
        except ImportError:
            try:from x402.schemas.payments import PaymentPayload as P,PaymentRequirements as R,ResourceInfo
            except ImportError as e:raise X402IntegrationError('Installed x402 SDK does not expose the required v2 schemas.') from e
        req=R(scheme=requirements.scheme,network=requirements.network,asset=requirements.asset,amount=requirements.amount,payTo=requirements.pay_to,maxTimeoutSeconds=requirements.max_timeout_seconds,extra=requirements.extra)
        resource=ResourceInfo(url=payload.resource);auth={'from':payload.payer,'to':payload.pay_to,'value':payload.amount,'validAfter':str(payload.valid_after or 0),'validBefore':str(payload.valid_before or 0),'nonce':payload.nonce};wire={'signature':payload.signature,'authorization':auth}
        return P(x402Version=2,payload=wire,accepted=req,resource=resource,extensions={}),req
    def verify(self,payload,requirements):
        try:r=self._get_client().verify(*self._objects(payload,requirements))
        except Exception as e:raise X402IntegrationError(f'x402 facilitator verification failed: {e}') from e
        return bool(getattr(r,'is_valid',getattr(r,'isValid',False))),getattr(r,'invalid_reason',getattr(r,'invalidReason','x402 verification failed')) or 'x402 verification passed'
    def settle(self,payload,requirements):
        from .models import SettlementResult
        try:r=self._get_client().settle(*self._objects(payload,requirements))
        except Exception as e:raise X402IntegrationError(f'x402 facilitator settlement failed: {e}') from e
        return SettlementResult(success=bool(r.success),tx_hash=getattr(r,'transaction',None) or None,reason=getattr(r,'error_reason',getattr(r,'errorReason',None)),settled_network=getattr(r,'network',None),payer=getattr(r,'payer',None),settled_amount=getattr(r,'amount',None))
    def supported(self):return self._get_client().get_supported().model_dump()
    def status(self):return {'adapter':'X402FacilitatorAdapter','mode':'REAL','facilitator_url':self.facilitator_url,'x402_version':self.x402_version,'supported':self.supported()}
