
from __future__ import annotations
import hashlib,json,time,uuid
from dataclasses import dataclass
from ..identity import NodeIdentity
from ..crypto import canonical_json

@dataclass(frozen=True)
class ConsensusConfig:
    epoch:int=1
    timeout_seconds:float=5
    def quorum(self,n:int)->int: return 2*((n-1)//3)+1

class BFTThreatConsensus:
    """Static-membership PBFT-style threat-state consensus.
    Safety holds for n >= 3f+1 with <= f Byzantine members and authenticated messages.
    It is advisory state only and is never consulted by the payment gate.
    """
    def __init__(self,identity,store,config=None):
        self.identity=identity; self.store=store; self.config=config or ConsensusConfig()
    def membership(self):
        ids=[self.identity.node_id]+[p["node_id"] for p in self.store.peers() if p.get("trusted") and not p.get("revoked")]
        return sorted(set(ids))
    def f(self): return max(0,(len(self.membership())-1)//3)
    def proposal(self,state,sequence:int,epoch=None):
        epoch=self.config.epoch if epoch is None else epoch
        body={"type":"PRE-PREPARE","version":1,"epoch":epoch,"sequence":sequence,"digest":self.digest(state),
              "proposer":self.identity.node_id,"state":state}
        return self._sign(body)
    def prepare(self,proposal):
        body={"type":"PREPARE","version":1,"epoch":proposal["epoch"],"sequence":proposal["sequence"],
              "digest":proposal["digest"],"voter":self.identity.node_id}
        return self._sign(body)
    def commit(self,proposal):
        body={"type":"COMMIT","version":1,"epoch":proposal["epoch"],"sequence":proposal["sequence"],
              "digest":proposal["digest"],"voter":self.identity.node_id}
        return self._sign(body)
    def verify(self,msg):
        if msg.get("version")!=1 or msg.get("epoch")!=self.config.epoch:return False,"unsupported epoch/version"
        node=msg.get("proposer") or msg.get("voter")
        p=self.store.get_peer(node)
        key=self.identity.public_key if node==self.identity.node_id else (p or {}).get("public_identity")
        if not key:return False,"unknown member"
        sig=msg.get("signature",""); body={k:v for k,v in msg.items() if k!="signature"}
        if not NodeIdentity.verify(key,canonical_json(body).encode(),sig):return False,"invalid signature"
        return True,"valid"
    @staticmethod
    def digest(state):return hashlib.sha256(canonical_json(state).encode()).hexdigest()
    def commit_rule(self,prepare_voters,commit_voters):
        q=self.config.quorum(len(self.membership()))
        return len(set(prepare_voters))>=q and len(set(commit_voters))>=q
    def state_digest(self,states): return sorted({self.digest(s) for s in states})
    def _sign(self,b): b=dict(b); b["signature"]=self.identity.sign(canonical_json(b).encode()); return b
