import time, threading
from aegis402.gateway import AegisGateway
from aegis402.models import PaymentPayload,PaymentRequirements,RequestContext
from aegis402.policy import Policy
from aegis402.storage.sqlite import SQLiteStore
from aegis402.ledger import ThreatLedger
from aegis402.x402_adapter import MockX402Adapter

def case(amount='1000'):
    resource='https://merchant.test/a';req=PaymentRequirements(amount=amount,pay_to='merchant',resource=resource);p=PaymentPayload(payer='0xabc',resource=resource,amount=amount,pay_to='merchant',nonce='n-'+str(time.time_ns()));c=RequestContext(method='GET',path='/api/resource',resource=resource,merchant='merchant',request_id='r');return p,req,c

def test_merchant_request_binding(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);p,r,c=case();c.merchant='evil';d=AegisGateway(MockX402Adapter()).inspect(p,r,c,time.time());assert d['decision']=='BLOCK'
def test_daily_limit(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);store=SQLiteStore('a.db');g=AegisGateway(MockX402Adapter(),policy=Policy(daily_limit=1000),store=store,ledger=ThreatLedger('l.jsonl'));p,r,c=case('1000');assert g.inspect(p,r,c,time.time())['decision']=='ALLOW';p2,r2,c2=case('1000');assert g.inspect(p2,r2,c2,time.time())['decision']=='BLOCK'
def test_persistent_replay_after_restart(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);store=SQLiteStore('a.db');p,r,c=case();g=AegisGateway(MockX402Adapter(),store=store,ledger=ThreatLedger('l.jsonl'));assert g.inspect(p,r,c,time.time())['decision']=='ALLOW';g2=AegisGateway(MockX402Adapter(),store=SQLiteStore('a.db'),ledger=ThreatLedger('l.jsonl'));assert g2.inspect(p,r,c,time.time())['decision']=='BLOCK'
def test_twenty_concurrent_same_nonce(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);store=SQLiteStore('a.db');p,r,c=case();g=AegisGateway(MockX402Adapter(),store=store,ledger=ThreatLedger('l.jsonl'));out=[];lock=threading.Lock()
    def w():
        d=g.inspect(p,r,c,time.time());
        with lock:out.append(d['decision'])
    ts=[threading.Thread(target=w) for _ in range(20)];[t.start() for t in ts];[t.join() for t in ts];assert out.count('ALLOW')==1

def test_signed_threat_report_tamper_detection():
    from aegis402.threats.reports import ThreatSigner, make_report
    signer=ThreatSigner('node','unit-test-secret')
    report=signer.sign(make_report('node','replay','merchant','event-1',0.9,'high'))
    assert signer.verify(report)
    report.target='changed'
    assert not signer.verify(report)

def test_review_policy_can_require_human_approval(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path); p,r,c=case(); policy=Policy(allowed_merchants={'trusted'},unknown_service_action='review'); g=AegisGateway(MockX402Adapter(),policy=policy,ledger=ThreatLedger('l.jsonl'))
    d=g.inspect(p,r,c,time.time()); assert d['decision']=='REVIEW'; assert d['review_required'] is True
