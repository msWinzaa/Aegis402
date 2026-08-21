from __future__ import annotations
import base64,time,uuid,hashlib
from typing import Any
from pydantic import BaseModel,ConfigDict,Field
from ..crypto import canonical_json
from ..identity import NodeIdentity
REPORT_VERSION=1
class ThreatReport(BaseModel):
    model_config=ConfigDict(extra='forbid')
    report_id:str; version:int=REPORT_VERSION; reporter_node:str; issued_at:float; expires_at:float|None=None; threat_type:str=Field(min_length=1,max_length=128); target:str=Field(min_length=1,max_length=2048); indicators:list[str]=Field(default_factory=list,max_length=64); evidence_reference:str=Field(default='',max_length=2048); confidence:float=Field(default=.5,ge=0,le=1); severity:str='medium'; context:dict[str,Any]=Field(default_factory=dict); sequence:int=Field(default=0,ge=0); previous_report:str|None=None; signature:str=''
    def signing_dict(self): d=self.model_dump(mode='json'); d['signature']=''; return d
    def canonical(self): return canonical_json(self.signing_dict()).encode()
class PeerEnvelope(BaseModel):
    model_config=ConfigDict(extra='forbid')
    message_id:str; version:int=1; sender_node:str; sent_at:float; ttl:int=Field(ge=0,le=8); report:dict[str,Any]; signature:str=''
    def signing_dict(self): d=self.model_dump(mode='json'); d['signature']=''; return d
    def canonical(self): return canonical_json(self.signing_dict()).encode()
def validate_report(r:ThreatReport, *, now=None, max_clock_skew=120, max_bytes=65536, last_sequence=None):
    now=time.time() if now is None else now
    if len(r.canonical())>max_bytes: return False,"report too large"
    if r.expires_at is not None and r.expires_at < now: return False,"expired report"
    if r.issued_at > now + max_clock_skew: return False,"future-dated report"
    if last_sequence is not None and r.sequence <= last_sequence: return False,"invalid report sequence"
    return True,"valid"

class ThreatSigner:
    def __init__(self,identity:NodeIdentity|str,secret:str|None=None):
        if isinstance(identity,NodeIdentity):self.identity=identity
        else:self.identity=NodeIdentity(identity,base64.b64encode(hashlib.sha256((secret or uuid.uuid4().hex).encode()).digest()).decode(),key_path=f'.aegis-test-{identity}.pem')
    def public_key(self):return self.identity.public_key
    def sign(self,r):r.signature=self.identity.sign(r.canonical());return r
    def verify(self,r,public_key=None):return NodeIdentity.verify(public_key or self.identity.public_key,r.canonical(),r.signature)
def make_report(node_id,threat_type,target,evidence_ref='',confidence=.5,severity='medium',expiration=None,indicators=None,context=None):
    return ThreatReport(report_id=str(uuid.uuid4()),reporter_node=node_id,issued_at=time.time(),expires_at=expiration,threat_type=threat_type,target=target,indicators=list(indicators or []),evidence_reference=evidence_ref,confidence=max(0,min(1,float(confidence))),severity=severity.lower(),context=context or {})
def make_envelope(sender_node,report,ttl=3):return PeerEnvelope(message_id=str(uuid.uuid4()),sender_node=sender_node,sent_at=time.time(),ttl=max(0,min(8,int(ttl))),report=report.model_dump(mode='json'))
