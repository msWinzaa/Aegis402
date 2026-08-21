
import time, json
from aegis402.identity import NodeIdentity
from aegis402.network.sybil import SybilResistance
from aegis402.network.consensus import BFTThreatConsensus
from aegis402.storage.sqlite import SQLiteStore
from aegis402.threats.reports import make_report,ThreatSigner,ThreatReport,validate_report
from aegis402.anchoring import merkle_root,merkle_proof,verify_proof
from aegis402.settlement_verify import EVMSettlementVerifier
from aegis402.secrets import FileSecretProvider

def ident(tmp,n):
    return NodeIdentity(n,key_path=str(tmp/f"{n}.pem"))

def test_sybil_newcomer_is_quarantined_and_bounded(tmp_path):
    s=SybilResistance(quarantine_age=1000,max_influence=.2)
    a=s.influence(created_at=time.time(),bootstrap=False,trust=1,evidence=1,corroboration=3,source_diversity=3)
    assert a.quarantined and a.influence<=.2

def test_sybil_influence_is_not_vote_weight(tmp_path):
    s=SybilResistance(max_influence=.2)
    one=s.influence(created_at=time.time()-100000,bootstrap=True,trust=1,evidence=1,corroboration=3,source_diversity=3)
    many=[s.influence(created_at=time.time()-100000,bootstrap=False,trust=1,evidence=1,corroboration=3,source_diversity=3,cluster_size=100) for _ in range(100)]
    assert sum(x.influence for x in many) <= .3
    assert one.influence <= .2

def test_identity_rotation_has_continuity_proof(tmp_path):
    a=ident(tmp_path,"n")
    old=a.public_key
    r=a.rotate()
    assert r["old_public_key"]==old and r["new_public_key"]!=old and r["continuity_proof"]
    assert NodeIdentity.verify(old,f"aegis-key-rotation:n:{old}:{r['new_public_key']}".encode(),r["continuity_proof"])

def test_consensus_quorum_and_byzantine_threshold(tmp_path):
    st=SQLiteStore(str(tmp_path/"db")); a=ident(tmp_path,"a")
    for i in range(3):
        b=ident(tmp_path,str(i)); st.peer(str(i),{"endpoint":"x","public_identity":b.public_key,"trusted":True,"revoked":False,"trust":1})
    c=BFTThreatConsensus(a,st)
    assert c.f()==1 and c.config.quorum(4)==3
    p=c.proposal({"target":"x"},1); assert c.verify(p)[0]
    p["signature"]="bad"; assert not c.verify(p)[0]

def test_merkle_proof_survives_without_database():
    events=[{"id":1,"x":"a"},{"id":2,"x":"b"},{"id":3,"x":"c"}]
    root=merkle_root(events); proof=merkle_proof(events,1)
    assert verify_proof(events[1],proof,root)
    events[1]["x"]="tampered"
    assert not verify_proof(events[1],proof,root)

def test_merkle_deleted_event_changes_proof():
    events=[{"id":1},{"id":2},{"id":3},{"id":4}]
    root=merkle_root(events)
    assert not verify_proof(events[0],merkle_proof(events[1:],0),root)

def test_report_schema_rejects_future_and_expired():
    r=make_report("n","x","t",expiration=time.time()-1)
    assert validate_report(r)[0] is False
    r=make_report("n","x","t"); r.issued_at=time.time()+1000
    assert validate_report(r,max_clock_skew=10)[0] is False

def test_report_signature_modification_fails(tmp_path):
    a=ident(tmp_path,"n"); r=make_report("n","x","t"); ThreatSigner(a).sign(r)
    assert ThreatSigner(a).verify(r)
    r.confidence=.1
    assert not ThreatSigner(a).verify(r)

def test_file_secret_requires_0600(tmp_path):
    p=tmp_path/"KEY"; p.write_text("secret"); p.chmod(0o644)
    try: FileSecretProvider(tmp_path).get("KEY")
    except PermissionError: pass
    else: assert False
