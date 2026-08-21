
from __future__ import annotations
import hashlib, math, time
from dataclasses import dataclass

@dataclass(frozen=True)
class Influence:
    identity_age: float
    bootstrap: float
    trust: float
    evidence: float
    corroboration: float
    diversity: float
    cluster_penalty: float
    influence: float
    quarantined: bool
    reasons: tuple[str,...]

class SybilResistance:
    """Deterministic, bounded admission/influence policy; not a proof of Sybil-freedom."""
    def __init__(self, min_age=3600.0, quarantine_age=86400.0, max_influence=.20):
        self.min_age=min_age; self.quarantine_age=quarantine_age; self.max_influence=max_influence
    @staticmethod
    def cluster_key(node_id:str)->str:
        return hashlib.sha256(node_id.encode()).hexdigest()[:12]
    def proof_of_resource(self, challenge:str, nonce:int, difficulty:int=16)->bool:
        digest=hashlib.sha256(f"{challenge}:{nonce}".encode()).digest()
        return int.from_bytes(digest,"big") < (1 << (256-difficulty))
    def influence(self, *, created_at:float, bootstrap:bool, trust:float,
                  evidence:float, corroboration:int, source_diversity:int,
                  cluster_size:int=1, now:float|None=None)->Influence:
        now=time.time() if now is None else now
        age=max(0,now-created_at)
        age_factor=min(1.0, math.log1p(age/max(self.min_age,1))/math.log1p(self.quarantine_age/max(self.min_age,1)))
        trust=max(0,min(1,trust)); evidence=max(0,min(1,evidence))
        corr=min(1,corroboration/3); diversity=min(1,source_diversity/3)
        cluster_penalty=1/(max(1,cluster_size)**2)
        base=(.25*age_factor+.20*(1 if bootstrap else 0)+.20*trust+.15*evidence+.10*corr+.10*diversity)
        value=min(self.max_influence, base*cluster_penalty)
        quarantine=age < self.quarantine_age and not bootstrap
        reasons=[]
        if quarantine: reasons.append("new identity quarantine")
        if cluster_size>1: reasons.append("correlated identity cluster")
        if source_diversity<.67: reasons.append("insufficient independent-source diversity")
        return Influence(age,1 if bootstrap else 0,trust,evidence,corr,diversity,cluster_penalty,value,quarantine,tuple(reasons))
