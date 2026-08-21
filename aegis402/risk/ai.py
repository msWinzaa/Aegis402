from __future__ import annotations
import json, os
from dataclasses import asdict
import httpx
from .engine import AIRiskResult

class AIRiskUnavailable(RuntimeError): pass

class HTTPAIRiskProvider:
    """Optional external AI risk service. The model is probabilistic; Aegis bounds its influence."""
    def __init__(self,url:str,timeout:float=2.0,model:str='external'):
        self.url=url; self.timeout=timeout; self.model=model
    def assess(self,payload,request,evidence):
        body={'model':self.model,'payment':{'payer':payload.payer,'amount':payload.amount,'pay_to':payload.pay_to,'network':payload.network,'asset':payload.asset,'resource':payload.resource},'request':request.model_dump(),'evidence':evidence}
        try:
            r=httpx.post(self.url,json=body,timeout=self.timeout)
            r.raise_for_status(); data=r.json()
            return AIRiskResult(float(data['score']),float(data.get('confidence',0.5)),str(data.get('model',self.model)),list(data.get('factors',[])))
        except Exception as e:
            raise AIRiskUnavailable(str(e)) from e

def configured_provider():
    url=os.getenv('AEGIS_AI_RISK_URL','').strip()
    if not url:return None
    return HTTPAIRiskProvider(url, float(os.getenv('AEGIS_AI_RISK_TIMEOUT','2.0')), os.getenv('AEGIS_AI_RISK_MODEL','external'))
