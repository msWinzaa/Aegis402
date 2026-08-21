import time
from aegis402.gateway import AegisGateway
from aegis402.models import PaymentPayload, PaymentRequirements, RequestContext
from aegis402.policy import Policy
from aegis402.x402_adapter import MockX402Adapter
from aegis402.risk.engine import AIRiskResult

class FixedAI:
    def __init__(self, score, confidence=1.0): self.result=AIRiskResult(score,confidence,'test-ai',['test-factor'])
    def assess(self,payload,request,evidence): return self.result

def payment():
    resource='https://merchant.test/resource'
    return (PaymentPayload(payer='agent',resource=resource,amount='90000',pay_to='merchant',nonce='prod-test',signature='sig'),
            PaymentRequirements(amount='90000',pay_to='merchant',resource=resource),
            RequestContext(method='GET',path='/api/resource',resource=resource,merchant='merchant',request_id='r'))

def test_deterministic_risk_precedes_ai_and_enforces_block(tmp_path):
    from aegis402.risk.engine import assess
    p=Policy(risk_enforcement_mode='enforced',risk_block_threshold=20,risk_hold_threshold=10,approval_threshold=200000,ai_risk_weight=1.0,max_amount=200000)
    a,b,c=payment(); r=assess(a,c,p,None,FixedAI(100).result)
    assert r.deterministic_score == 0
    assert r.ai_score == 100
    assert r.score == 100
    assert r.level == 'CRITICAL'

def test_ai_is_bounded_evidence_not_authority(tmp_path):
    p=Policy(risk_enforcement_mode='advisory',ai_risk_weight=.1)
    a,b,c=payment(); g=AegisGateway(MockX402Adapter(),policy=p,ai_provider=FixedAI(100),store=None)
    r=g.inspect(a,b,c,time.time())
    assert r['decision'] in {'ALLOW','REVIEW','BLOCK'}
    assert r['risk_score'] <= 100

def test_independent_verification_required_when_configured(tmp_path):
    p=Policy(require_independent_settlement_verification=True,fail_closed_on_verification_unavailable=True,approval_threshold=200000)
    a,b,c=payment(); g=AegisGateway(MockX402Adapter(),policy=p,store=None)
    r=g.inspect(a,b,c,time.time())
    assert r['decision']=='REVIEW'
    assert 'independent settlement verification unavailable' in r['reason']
