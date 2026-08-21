
from __future__ import annotations
import hashlib, json, math, time
from .sybil import SybilResistance

_SEV={"critical":1.0,"high":.8,"medium":.5,"low":.2}
class ReputationNetwork:
    def __init__(self,store,node_id,half_life_seconds=7*86400):
        self.store=store; self.node_id=node_id; self.half_life_seconds=half_life_seconds; self.sybil=SybilResistance()
    def issuer_trust(self,node_id):
        if node_id==self.node_id:return 1.0
        p=self.store.get_peer(node_id)
        return float((p or {}).get("trust",0)) if p and p.get("trusted") and not p.get("revoked") else 0
    def evidence_quality(self,r):
        score=.15 + (.25 if r.evidence_reference else 0) + min(.25,len(r.indicators)*.05) + (.10 if r.context else 0)
        return min(1,score)
    def publish(self,r):
        self.store.threat(r.report_id,r.model_dump(mode="json")); return r.report_id
    def ingest(self,r):
        if self.store.threat_exists(r.report_id): return False,"duplicate report"
        self.store.threat(r.report_id,r.model_dump(mode="json"))
        evidence=self.evidence_quality(r); trust=self.issuer_trust(r.reporter_node)
        self.store.reputation_observation(report_id=r.report_id,target=r.target,reporter_node=r.reporter_node,
            severity=r.severity,confidence=r.confidence,evidence_quality=evidence,issuer_trust=trust,issued_at=r.issued_at)
        self.recalculate(r.target); return True,"accepted"
    def recalculate(self,target,now=None):
        now=time.time() if now is None else now
        obs=self.store.observations(target); rows=[]; total=weighted=0.0
        reporters={o["reporter_node"] for o in obs}
        for o in obs:
            age=max(0,now-o["issued_at"]); decay=2**(-age/self.half_life_seconds)
            rep_reports=sum(1 for x in obs if x["reporter_node"]==o["reporter_node"])
            source_diversity=len(reporters)
            cluster_size=len({self.sybil.cluster_key(x) for x in reporters if self.sybil.cluster_key(x)==self.sybil.cluster_key(o["reporter_node"])})
            inf=self.sybil.influence(created_at=o["issued_at"],bootstrap=False,trust=o["issuer_trust"],
                evidence=o["evidence_quality"],corroboration=len(obs),source_diversity=source_diversity,
                cluster_size=cluster_size,now=now)
            w=o["confidence"]*o["evidence_quality"]*o["issuer_trust"]*decay*inf.influence
            val=_SEV.get(o["severity"].lower(),.45); weighted+=val*w; total+=w
            rows.append({"report_id":o["report_id"],"reporter":o["reporter_node"],"influence":round(w,8),"decay":round(decay,6),
                         "confidence":o["confidence"],"evidence_quality":o["evidence_quality"],"contradiction":False})
        # contradictory observations are bounded instead of first-report wins
        effective=min(1,total)
        risk=(weighted + .5*(1-effective))
        score=100*(1-risk)
        result={"score":round(max(0,min(100,score)),4),"risk":round(risk,4),"observations":len(obs),
                "model":"evidence-weighted-v2","explain":rows,"updated_at":now,
                "sources":sorted(reporters),"quarantined": total<.10}
        self.store.reputation(target,result); return result["score"]
    def explain(self,target):
        row=next((x for x in self.store.reputations() if x["target"]==target),None)
        return row or {"score":50.0,"risk":.5,"observations":0,"explain":[]}
    def score(self,target): return float(self.explain(target).get("score",50))
    def digest(self): return hashlib.sha256(json.dumps(self.store.reputations(),sort_keys=True).encode()).hexdigest()
