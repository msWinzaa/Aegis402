import time
from aegis402.identity import NodeIdentity
from aegis402.storage.sqlite import SQLiteStore
from aegis402.network.peer import PeerProtocol
from aegis402.network.reputation import ReputationNetwork
from aegis402.threats.reports import ThreatSigner,make_report,make_envelope

def ident(tmp_path,n): return NodeIdentity(n,key_path=str(tmp_path/f'{n}.pem'))
def test_identity_rotation(tmp_path):
 a=ident(tmp_path,'a');msg=b'challenge';sig=a.sign(msg);assert NodeIdentity.verify(a.public_key,msg,sig);old=a.public_key;r=a.rotate();assert r['new_public_key']!=old

def test_peer_auth_replay_and_tamper(tmp_path):
 s=SQLiteStore(str(tmp_path/'b.db'));a=ident(tmp_path,'a');b=ident(tmp_path,'b');p=PeerProtocol(s,b);r=make_report('a','replay','merchant');ThreatSigner(a).sign(r);e=make_envelope('a',r);e.signature=a.sign(e.canonical());assert p.verify_envelope(e)[0] is False
 s.peer('a',{'endpoint':'x','public_identity':a.public_key,'trusted':True,'revoked':False,'trust':.8});e=make_envelope('a',r);e.signature=a.sign(e.canonical());assert p.verify_envelope(e)[0];assert not p.verify_envelope(e)[0];e2=make_envelope('a',r);e2.signature=a.sign(e2.canonical());e2.report['target']='tampered';assert not p.verify_envelope(e2)[0]

def test_reputation_decay_and_sybil_bound(tmp_path):
 s=SQLiteStore(str(tmp_path/'r.db'));rep=ReputationNetwork(s,'local',half_life_seconds=100);a=ident(tmp_path,'issuer');s.peer('issuer',{'endpoint':'x','public_identity':a.public_key,'trusted':True,'revoked':False,'trust':.8});r=make_report('issuer','malware','target',evidence_ref='event-1',confidence=1,severity='critical',indicators=['hash']);ThreatSigner(a).sign(r);assert rep.ingest(r)[0];now=rep.score('target');rep.recalculate('target',r.issued_at+100);assert rep.score('target')>now
 for i in range(10):
  rr=make_report(f'sybil-{i}','malware','other',confidence=1,severity='critical');s.reputation_observation(report_id=rr.report_id,target=rr.target,reporter_node=rr.reporter_node,severity=rr.severity,confidence=1,evidence_quality=1,issuer_trust=0,issued_at=rr.issued_at)
 rep.recalculate('other');assert rep.score('other')==50

def test_expired_report_is_data_not_fresh_intelligence(tmp_path):
 s=SQLiteStore(str(tmp_path/'r.db'));a=ident(tmp_path,'issuer');s.peer('issuer',{'endpoint':'x','public_identity':a.public_key,'trusted':True,'revoked':False,'trust':.9});r=make_report('issuer','malware','target',expiration=time.time()-1);ThreatSigner(a).sign(r);assert r.expires_at<time.time()

def test_report_request_envelope_is_signed(tmp_path):
 s=SQLiteStore(str(tmp_path/'r.db'));a=ident(tmp_path,'a');b=ident(tmp_path,'b');s.peer('a',{'endpoint':'x','public_identity':a.public_key,'trusted':True,'revoked':False,'trust':.8});p=PeerProtocol(s,b);env=p.make_report_request('missing-report');assert NodeIdentity.verify(b.public_key,env.canonical(),env.signature)
