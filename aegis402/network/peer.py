from __future__ import annotations
import time,hashlib
from dataclasses import asdict
from ..crypto import canonical_json
from ..identity import NodeIdentity
from ..threats.reports import PeerEnvelope,make_envelope,validate_report
class PeerProtocol:
    def __init__(self,store,identity,max_skew=120,rate_limit=60):self.store=store;self.identity=identity;self.max_skew=max_skew;self.rate_limit=rate_limit
    def register(self,node_id,endpoint,public_key,trust=.2,bootstrap=False,capabilities=None):
        if node_id==self.identity.node_id and public_key!=self.identity.public_key:raise ValueError('node identity collision')
        if not public_key or not endpoint:raise ValueError('public_key and endpoint are required')
        existing=self.store.get_peer(node_id)
        if existing and existing.get('public_identity') and existing['public_identity']!=public_key:raise ValueError('identity key changed; explicit rotation required')
        self.store.peer(node_id,{'endpoint':endpoint,'public_identity':public_key,'trusted':bool(trust>0),'trust':max(0,min(1,float(trust))),'bootstrap':bool(bootstrap),'revoked':False,'capabilities':capabilities or []})
    def revoke(self,node_id):
        p=self.store.get_peer(node_id)
        if p:
            self.store.peer(node_id,{**{k:v for k,v in p.items() if k not in {'node_id','updated_at'}},'revoked':True,'trusted':False,'trust':0})
            if p.get('public_identity'):self.store.revoke_identity(node_id,p['public_identity'])
    def make_envelope(self,report,ttl=3):
        env=make_envelope(self.identity.node_id,report,ttl);env.signature=self.identity.sign(env.canonical());return env
    def verify_envelope(self,env:PeerEnvelope):
        p=self.store.get_peer(env.sender_node)
        if not p or p.get('revoked') or not p.get('trusted'):return False,'unknown or untrusted peer'
        if self.store.is_revoked_identity(p.get('public_identity','')):return False,'revoked peer identity'
        if abs(time.time()-env.sent_at)>self.max_skew:return False,'peer message outside freshness window'
        if env.ttl<0:return False,'propagation ttl exhausted'
        if env.version != 1:return False,'unsupported peer protocol version'
        if not self.store.rate_limit(env.sender_node,self.rate_limit):return False,'peer report rate limit exceeded'
        if not NodeIdentity.verify(p['public_identity'],env.canonical(),env.signature):return False,'invalid peer signature'
        if not self.store.seen_message(env.message_id,env.sender_node):return False,'duplicate peer message'
        return True,'authenticated'
    def make_report_request(self,report_id):
        env=PeerEnvelope(message_id=__import__('uuid').uuid4().__str__(),sender_node=self.identity.node_id,sent_at=time.time(),ttl=0,report={'request':'report','report_id':report_id});env.signature=self.identity.sign(env.canonical());return env
    def validate_report(self,report,last_sequence=None):
        return validate_report(report,max_clock_skew=self.max_skew,max_bytes=65536,last_sequence=last_sequence)
    def report_digest(self,report):return hashlib.sha256(canonical_json(report.model_dump(mode='json')).encode()).hexdigest()
